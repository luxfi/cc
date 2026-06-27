// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// nitroVec is a self-consistent AWS Nitro attestation vector: a real
// COSE_Sign1 (ECDSA-P384 / ES384) over a real CBOR attestation document, with
// a real X.509 chain rooted at a generated CA. It uses 100% real cryptography;
// only the trust anchor is a test CA (instead of AWS's HSM-held root, whose
// private key nobody outside AWS can sign with). The pinned, fingerprint-
// verified genuine AWS root is exercised separately in
// TestNitro_PinnedRootIsAuthenticAWS.
type nitroVec struct {
	evidence []byte
	rootPool *x509.CertPool
	leaf     *x509.Certificate
	leafPriv *ecdsa.PrivateKey
	cabundle [][]byte
	doc      *nitroDoc
	now      time.Time
	pcr0     []byte
	pcr1     []byte
	pcr2     []byte
	nonce    []byte
}

func rep48(b byte) []byte { return bytes.Repeat([]byte{b}, nitroPCRLenSHA384) }

// genNitroChain builds a P-384 root -> intermediate -> leaf chain valid in
// [notBefore, notAfter]. leafCurve selects the leaf key curve (P-384 for the
// real shape; P-256 to exercise the curve-rejection path). The leaf carries no
// EKU, exactly like a real Nitro signing certificate.
func genNitroChain(t *testing.T, leafCurve elliptic.Curve, notBefore, notAfter time.Time) (
	rootPool *x509.CertPool, leaf *x509.Certificate, leafPriv *ecdsa.PrivateKey, cabundle [][]byte,
) {
	t.Helper()

	rootPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.nitro-enclaves", Organization: []string{"LuxTest"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}

	interPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("inter key: %v", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test.nitro-enclaves intermediate"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("inter cert: %v", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatalf("parse inter: %v", err)
	}

	leafPriv, err = ecdsa.GenerateKey(leafCurve, rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "i-0abc.eu-west-1.aws.nitro-enclaves"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafPriv.PublicKey, interPriv)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	rootPool = x509.NewCertPool()
	rootPool.AddCert(rootCert)
	// AWS cabundle order is [ROOT, INTERM_1, ...]; the leaf is NOT included.
	cabundle = [][]byte{rootDER, interDER}
	return rootPool, leaf, leafPriv, cabundle
}

// encodeNitroPayload CBOR-encodes an AWS-faithful attestation document map:
// string keys, uint PCR indices, and optional fields omitted when nil (matching
// what the NSM emits, rather than encoding them as CBOR null).
func encodeNitroPayload(t *testing.T, d *nitroDoc) []byte {
	t.Helper()
	m := map[string]interface{}{
		"module_id":   d.ModuleID,
		"timestamp":   d.Timestamp,
		"digest":      d.Digest,
		"pcrs":        d.PCRs,
		"certificate": d.Certificate,
		"cabundle":    d.CABundle,
	}
	if d.PublicKey != nil {
		m["public_key"] = d.PublicKey
	}
	if d.UserData != nil {
		m["user_data"] = d.UserData
	}
	if d.Nonce != nil {
		m["nonce"] = d.Nonce
	}
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("cbor marshal payload: %v", err)
	}
	return b
}

// signNitro produces a tagged COSE_Sign1 (CBOR tag 18) over payload, signed by
// leafPriv with the given COSE algorithm.
func signNitro(t *testing.T, leafPriv *ecdsa.PrivateKey, alg cose.Algorithm, payload []byte) []byte {
	t.Helper()
	signer, err := cose.NewSigner(alg, leafPriv)
	if err != nil {
		t.Fatalf("cose signer: %v", err)
	}
	headers := cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: alg}}
	ev, err := cose.Sign1(rand.Reader, signer, headers, payload, nil)
	if err != nil {
		t.Fatalf("cose sign1: %v", err)
	}
	return ev
}

// signDoc encodes d and signs it with leafPriv (ES384), returning evidence.
func signDoc(t *testing.T, leafPriv *ecdsa.PrivateKey, d *nitroDoc) []byte {
	t.Helper()
	return signNitro(t, leafPriv, cose.AlgorithmES384, encodeNitroPayload(t, d))
}

func newNitroVec(t *testing.T) *nitroVec {
	t.Helper()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	rootPool, leaf, leafPriv, cabundle := genNitroChain(t, elliptic.P384(), now.Add(-time.Hour), now.Add(3*time.Hour))

	v := &nitroVec{
		rootPool: rootPool,
		leaf:     leaf,
		leafPriv: leafPriv,
		cabundle: cabundle,
		now:      now,
		pcr0:     rep48(0xa0),
		pcr1:     rep48(0xb1),
		pcr2:     rep48(0xc2),
		nonce:    bytes.Repeat([]byte{0x11}, 32),
	}
	v.doc = &nitroDoc{
		ModuleID:    "i-0abc1234def567890-enc0123456789abcdef",
		Timestamp:   uint64(now.UnixMilli()),
		Digest:      nitroDigestSHA384,
		PCRs:        map[uint64][]byte{0: v.pcr0, 1: v.pcr1, 2: v.pcr2},
		Certificate: leaf.Raw,
		CABundle:    cabundle,
		PublicKey:   bytes.Repeat([]byte{0x22}, 64),
		UserData:    []byte("lux-attestation"),
		Nonce:       v.nonce,
	}
	v.evidence = signDoc(t, leafPriv, v.doc)
	return v
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

func TestNitro_HappyPath(t *testing.T) {
	v := newNitroVec(t)

	rep, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Kind != KindNitro {
		t.Fatalf("kind = %q, want %q", rep.Kind, KindNitro)
	}
	if rep.Vendor != "aws.nitro.enclaves" {
		t.Fatalf("vendor = %q", rep.Vendor)
	}
	if !bytes.Equal(rep.Measurement, v.pcr0) {
		t.Fatalf("measurement = %x, want pcr0 %x", rep.Measurement, v.pcr0)
	}
	if !bytes.Equal(rep.ReportData, v.nonce) {
		t.Fatalf("report_data = %x, want nonce %x", rep.ReportData, v.nonce)
	}
	if !bytes.Equal(rep.HostData, []byte("lux-attestation")) {
		t.Fatalf("host_data = %x, want user_data", rep.HostData)
	}
	if rep.CompositeHash == [32]byte{} {
		t.Fatal("composite hash must not be zero")
	}
	if rep.Extra["nitro.module_id"] != v.doc.ModuleID {
		t.Fatalf("extra module_id = %q", rep.Extra["nitro.module_id"])
	}
	if rep.Extra["nitro.pcr0"] != hex.EncodeToString(v.pcr0) {
		t.Fatalf("extra pcr0 = %q", rep.Extra["nitro.pcr0"])
	}
	if rep.Extra["nitro.pcr2"] != hex.EncodeToString(v.pcr2) {
		t.Fatalf("extra pcr2 = %q", rep.Extra["nitro.pcr2"])
	}
	wantLeafFP := sha256.Sum256(v.leaf.Raw)
	if rep.Extra["nitro.leaf_fingerprint"] != hex.EncodeToString(wantLeafFP[:]) {
		t.Fatalf("extra leaf_fingerprint = %q", rep.Extra["nitro.leaf_fingerprint"])
	}
}

func TestNitro_HappyPath_Untagged(t *testing.T) {
	v := newNitroVec(t)
	// Re-sign as an untagged COSE_Sign1 (no CBOR tag 18) — AWS docs allow both.
	signer, err := cose.NewSigner(cose.AlgorithmES384, v.leafPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	headers := cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES384}}
	untagged, err := cose.Sign1Untagged(rand.Reader, signer, headers, encodeNitroPayload(t, v.doc), nil)
	if err != nil {
		t.Fatalf("sign1 untagged: %v", err)
	}
	if untagged[0] == 0xd2 {
		t.Fatal("expected untagged COSE_Sign1 (no 0xd2 prefix)")
	}
	if _, err := Dispatch(context.Background(), KindNitro, untagged,
		WithNitroRoots(v.rootPool), WithNow(v.now)); err != nil {
		t.Fatalf("verify untagged: %v", err)
	}
}

func TestNitro_PolicyAccepts(t *testing.T) {
	v := newNitroVec(t)
	// Pin PCR0/1/2, the measurement (PCR0), the nonce, and a generous max-age.
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now.Add(5*time.Minute)),
		WithNitroPCRs(map[uint][]byte{0: v.pcr0, 1: v.pcr1, 2: v.pcr2}),
		WithExpectedMeasurement(v.pcr0),
		WithExpectedReportData(v.nonce),
		WithNitroMaxAge(time.Hour))
	if err != nil {
		t.Fatalf("verify with full policy: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Trust-anchor authenticity: the pinned root really is the AWS Nitro root.
// ---------------------------------------------------------------------------

func TestNitro_PinnedRootIsAuthenticAWS(t *testing.T) {
	root := NitroRootCertificate()

	fp := sha256.Sum256(root.Raw)
	if got := hex.EncodeToString(fp[:]); got != NitroRootCAFingerprintSHA256 {
		t.Fatalf("pinned root fingerprint = %s, want AWS-documented %s", got, NitroRootCAFingerprintSHA256)
	}
	if root.Subject.CommonName != "aws.nitro-enclaves" {
		t.Fatalf("root CN = %q, want aws.nitro-enclaves", root.Subject.CommonName)
	}
	if len(root.Subject.Organization) == 0 || root.Subject.Organization[0] != "Amazon" {
		t.Fatalf("root O = %v, want [Amazon]", root.Subject.Organization)
	}
	if root.Subject.String() != root.Issuer.String() {
		t.Fatal("root is not self-issued")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root is not validly self-signed: %v", err)
	}
	pub, ok := root.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		t.Fatalf("root key is not ECDSA P-384")
	}
	if root.NotBefore.UTC().Year() != 2019 || root.NotAfter.UTC().Year() != 2049 {
		t.Fatalf("root validity = %s..%s, want 2019..2049", root.NotBefore.UTC(), root.NotAfter.UTC())
	}
	if !root.IsCA {
		t.Fatal("root is not a CA")
	}
}

// ---------------------------------------------------------------------------
// Tamper / refusal matrix
// ---------------------------------------------------------------------------

// TestNitro_RejectsTamperedSignature flips a signature byte: the COSE_Sign1
// signature no longer matches the leaf key.
func TestNitro_RejectsTamperedSignature(t *testing.T) {
	v := newNitroVec(t)
	msg, err := parseNitroCOSESign1(v.evidence)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	msg.Signature[0] ^= 0xff
	bad, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	_, err = Dispatch(context.Background(), KindNitro, bad, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

// TestNitro_RejectsTamperedPayload swaps in a modified payload while keeping the
// original signature — proving the document content is integrity-bound to the
// COSE signature (a forger cannot edit PCRs post-signing).
func TestNitro_RejectsTamperedPayload(t *testing.T) {
	v := newNitroVec(t)
	msg, err := parseNitroCOSESign1(v.evidence)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	forged := *v.doc
	forged.PCRs = map[uint64][]byte{0: rep48(0xff), 1: v.pcr1, 2: v.pcr2}
	msg.Payload = encodeNitroPayload(t, &forged) // signature NOT recomputed
	bad, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	_, err = Dispatch(context.Background(), KindNitro, bad, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

// TestNitro_RejectsWrongRoot verifies a test-CA-rooted document against the
// PINNED AWS root (no override) — the chain cannot anchor.
func TestNitro_RejectsWrongRoot(t *testing.T) {
	v := newNitroVec(t)
	_, err := Dispatch(context.Background(), KindNitro, v.evidence, WithNow(v.now))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

// TestNitro_RejectsUnrelatedRoot verifies against a *different* generated root.
func TestNitro_RejectsUnrelatedRoot(t *testing.T) {
	v := newNitroVec(t)
	otherPool, _, _, _ := genNitroChain(t, elliptic.P384(), v.now.Add(-time.Hour), v.now.Add(3*time.Hour))
	_, err := Dispatch(context.Background(), KindNitro, v.evidence, WithNitroRoots(otherPool), WithNow(v.now))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

// TestNitro_RejectsExpiredChain pins the clock outside the leaf's validity.
func TestNitro_RejectsExpiredChain(t *testing.T) {
	v := newNitroVec(t)
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now.Add(10*time.Hour)))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid (expired leaf)", err)
	}
}

// TestNitro_RejectsBrokenChain drops the intermediate from the cabundle.
func TestNitro_RejectsBrokenChain(t *testing.T) {
	v := newNitroVec(t)
	broken := *v.doc
	broken.CABundle = [][]byte{v.cabundle[0]} // root only, no intermediate
	ev := signDoc(t, v.leafPriv, &broken)
	_, err := Dispatch(context.Background(), KindNitro, ev, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid (missing intermediate)", err)
	}
}

// TestNitro_RejectsWrongPCR pins a PCR value that the document does not carry.
func TestNitro_RejectsWrongPCR(t *testing.T) {
	v := newNitroVec(t)
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now),
		WithNitroPCRs(map[uint][]byte{0: rep48(0xde)}))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (pcr mismatch)", err)
	}
}

// TestNitro_RejectsAbsentRequiredPCR pins an index the document omits.
func TestNitro_RejectsAbsentRequiredPCR(t *testing.T) {
	v := newNitroVec(t)
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now),
		WithNitroPCRs(map[uint][]byte{8: rep48(0x08)}))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (absent pcr)", err)
	}
}

// TestNitro_RejectsMeasurementMismatch pins a wrong PCR0 via the generic option.
func TestNitro_RejectsMeasurementMismatch(t *testing.T) {
	v := newNitroVec(t)
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now),
		WithExpectedMeasurement(rep48(0x00)))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (measurement)", err)
	}
}

// TestNitro_RejectsNonceMismatch pins a wrong nonce via the generic option.
func TestNitro_RejectsNonceMismatch(t *testing.T) {
	v := newNitroVec(t)
	wrong := make([]byte, 32)
	wrong[0] = 0xFF
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now),
		WithExpectedReportData(wrong))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (nonce binding)", err)
	}
}

// TestNitro_RejectsStale enforces a max-age the document violates.
func TestNitro_RejectsStale(t *testing.T) {
	v := newNitroVec(t)
	_, err := Dispatch(context.Background(), KindNitro, v.evidence,
		WithNitroRoots(v.rootPool), WithNow(v.now.Add(time.Hour)),
		WithNitroMaxAge(time.Minute))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (stale)", err)
	}
}

// TestNitro_RejectsFutureTimestamp refuses a document timestamped in the future.
func TestNitro_RejectsFutureTimestamp(t *testing.T) {
	v := newNitroVec(t)
	future := *v.doc
	future.Timestamp = uint64(v.now.Add(time.Hour).UnixMilli())
	ev := signDoc(t, v.leafPriv, &future)
	_, err := Dispatch(context.Background(), KindNitro, ev,
		WithNitroRoots(v.rootPool), WithNow(v.now), WithNitroMaxAge(time.Hour))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (future timestamp)", err)
	}
}

// TestNitro_RejectsWrongDigest refuses a non-SHA384 digest field.
func TestNitro_RejectsWrongDigest(t *testing.T) {
	v := newNitroVec(t)
	bad := *v.doc
	bad.Digest = "SHA256"
	ev := signDoc(t, v.leafPriv, &bad)
	_, err := Dispatch(context.Background(), KindNitro, ev, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence (digest)", err)
	}
}

// TestNitro_RejectsBadPCRLength refuses a PCR that is not 48 bytes under SHA384.
func TestNitro_RejectsBadPCRLength(t *testing.T) {
	v := newNitroVec(t)
	bad := *v.doc
	bad.PCRs = map[uint64][]byte{0: bytes.Repeat([]byte{0xa0}, 32), 1: v.pcr1}
	ev := signDoc(t, v.leafPriv, &bad)
	_, err := Dispatch(context.Background(), KindNitro, ev, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence (pcr length)", err)
	}
}

// TestNitro_RejectsNonP384Leaf refuses a leaf whose key is not P-384, even when
// the chain itself is well-formed.
func TestNitro_RejectsNonP384Leaf(t *testing.T) {
	v := newNitroVec(t)
	// Build a chain whose leaf is P-256; sign the COSE with ES256 so the
	// envelope is well-formed. Verify must reject at the curve check, before
	// any COSE signature check.
	rootPool, leaf, leafPriv, cabundle := genNitroChain(t, elliptic.P256(), v.now.Add(-time.Hour), v.now.Add(3*time.Hour))
	doc := *v.doc
	doc.Certificate = leaf.Raw
	doc.CABundle = cabundle
	ev := signNitro(t, leafPriv, cose.AlgorithmES256, encodeNitroPayload(t, &doc))
	_, err := Dispatch(context.Background(), KindNitro, ev, WithNitroRoots(rootPool), WithNow(v.now))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence (non-P384 leaf)", err)
	}
}

// TestNitro_RejectsAlgSubstitution refuses a document whose protected header
// claims an algorithm other than ES384 (algorithm-confusion defense). We sign
// with a real P-384 ES384 signature but rewrite the protected header to ES512.
func TestNitro_RejectsAlgSubstitution(t *testing.T) {
	v := newNitroVec(t)
	msg, err := parseNitroCOSESign1(v.evidence)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Force the protected header to a different alg; clear RawProtected so the
	// rewritten Protected map is what gets re-encoded.
	msg.Headers.RawProtected = nil
	msg.Headers.Protected = cose.ProtectedHeader{cose.HeaderLabelAlgorithm: cose.AlgorithmES512}
	bad, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	_, err = Dispatch(context.Background(), KindNitro, bad, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid (alg substitution)", err)
	}
}

// TestNitro_RejectsBadCBOR refuses non-COSE garbage.
func TestNitro_RejectsBadCBOR(t *testing.T) {
	for _, tc := range [][]byte{
		nil,
		{},
		[]byte("not cbor at all"),
		{0xd2, 0xff, 0xff}, // tag 18 then garbage
	} {
		_, err := Dispatch(context.Background(), KindNitro, tc)
		if !errors.Is(err, ErrInvalidEvidence) {
			t.Fatalf("evidence %x: err = %v, want ErrInvalidEvidence", tc, err)
		}
	}
}

// TestNitro_RejectsMissingPCR0 refuses a document with no PCR0.
func TestNitro_RejectsMissingPCR0(t *testing.T) {
	v := newNitroVec(t)
	bad := *v.doc
	bad.PCRs = map[uint64][]byte{1: v.pcr1, 2: v.pcr2}
	ev := signDoc(t, v.leafPriv, &bad)
	_, err := Dispatch(context.Background(), KindNitro, ev, WithNitroRoots(v.rootPool), WithNow(v.now))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence (missing pcr0)", err)
	}
}

// ---------------------------------------------------------------------------
// CompositeHash determinism
// ---------------------------------------------------------------------------

func TestNitro_CompositeHashStableAndContentBound(t *testing.T) {
	v := newNitroVec(t)
	r1, err := Dispatch(context.Background(), KindNitro, v.evidence, WithNitroRoots(v.rootPool), WithNow(v.now))
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}
	r2, err := Dispatch(context.Background(), KindNitro, v.evidence, WithNitroRoots(v.rootPool), WithNow(v.now))
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if r1.CompositeHash != r2.CompositeHash {
		t.Fatal("composite hash is not deterministic")
	}
	// A different PCR0 must change the composite hash.
	other := *v.doc
	other.PCRs = map[uint64][]byte{0: rep48(0x5a), 1: v.pcr1, 2: v.pcr2}
	ev := signDoc(t, v.leafPriv, &other)
	r3, err := Dispatch(context.Background(), KindNitro, ev, WithNitroRoots(v.rootPool), WithNow(v.now))
	if err != nil {
		t.Fatalf("verify 3: %v", err)
	}
	if r3.CompositeHash == r1.CompositeHash {
		t.Fatal("composite hash collided across different PCR0")
	}
}

// TestNitro_RejectsDuplicateCBORKey proves the hardened decoder is wired: a
// CBOR map carrying a duplicate key (here "digest" twice) is rejected, so a
// forger cannot smuggle a second value past the verifier. Bytes are hand-built
// because a conforming encoder will not emit duplicate keys.
func TestNitro_RejectsDuplicateCBORKey(t *testing.T) {
	dup := []byte{
		0xa2, // map, 2 pairs
		0x66, 'd', 'i', 'g', 'e', 's', 't', 0x66, 'S', 'H', 'A', '3', '8', '4',
		0x66, 'd', 'i', 'g', 'e', 's', 't', 0x66, 'S', 'H', 'A', '2', '5', '6',
	}
	if _, err := decodeNitroDoc(dup); err == nil {
		t.Fatal("decodeNitroDoc accepted a duplicate map key")
	}
}

// TestNitro_DispatchWired is a guard that KindNitro is wired into
// Dispatch (not a dangling verifier).
func TestNitro_DispatchWired(t *testing.T) {
	v := newNitroVec(t)
	// Direct verifier and Dispatch must agree.
	direct, errD := Nitro{}.Verify(context.Background(), v.evidence, WithNitroRoots(v.rootPool), WithNow(v.now))
	viaDispatch, errR := Dispatch(context.Background(), KindNitro, v.evidence, WithNitroRoots(v.rootPool), WithNow(v.now))
	if errD != nil || errR != nil {
		t.Fatalf("direct=%v dispatch=%v", errD, errR)
	}
	if direct.CompositeHash != viaDispatch.CompositeHash {
		t.Fatal("Dispatch and direct Verify disagree")
	}
}
