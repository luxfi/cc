// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// Nitro is the production AWS Nitro Enclaves verifier.
//
// An AWS Nitro Enclaves attestation document is a CBOR-encoded COSE_Sign1
// structure (RFC 9052) produced by the Nitro Hypervisor's Nitro Security
// Module (NSM). It is signed with ECDSA-P384 / SHA-384 (COSE alg ES384,
// label -35) by an ephemeral leaf certificate that the AWS Nitro Attestation
// PKI issues, chaining up to the well-known AWS Nitro Enclaves Root G1
// certificate. Nitro verifies, in order:
//
//  1. Parse the COSE_Sign1 envelope (tagged CBOR tag 18 or untagged).
//  2. Decode the CBOR attestation-document payload and validate its shape
//     (module_id, digest == "SHA384", timestamp, pcrs, certificate,
//     cabundle) per the AWS CDDL.
//  3. Parse the leaf certificate; require an ECDSA P-384 public key.
//  4. Build the X.509 chain leaf -> cabundle intermediates -> the pinned AWS
//     Nitro Enclaves Root G1, anchored ONLY at our embedded copy of that
//     root (never the cabundle's own root). CRL is disabled per AWS.
//  5. Verify the COSE_Sign1 signature against the leaf's P-384 key, binding
//     the protected-header algorithm to ES384 (no algorithm substitution).
//  6. Apply caller policy: expected PCR set, expected measurement (PCR0),
//     expected nonce (report data), and freshness (document timestamp).
//
// The trust anchor is pinned, not taken from the evidence: the embedded AWS
// root PEM (nitroRootCAPEM) is checked at parse time against the AWS-published
// SHA-256 fingerprint (NitroRootCAFingerprintSHA256). There is no insecure
// mode — a document that does not chain to the pinned AWS root is refused.
//
// Honest scope: this verifier proves "an AWS Nitro enclave whose image
// measures to these PCRs produced this document, bound to this nonce, and the
// signing leaf chains to the AWS Nitro Enclaves root." Whether a given PCR0
// is an *acceptable* enclave is the caller's policy (WithExpectedMeasurement /
// WithNitroPCRs). PCR0 is the SHA-384 measurement of the entire enclave image
// file; PCR1 covers the linux kernel/bootstrap and PCR2 the application.
type Nitro struct{}

const (
	// nitroVendor is the canonical issuer string for verified Nitro reports.
	nitroVendor = "aws.nitro.enclaves"

	// nitroDigestSHA384 is the only digest the NSM emits; PCRs are 48 bytes.
	nitroDigestSHA384 = "SHA384"

	// nitroPCRLenSHA384 is the byte length of a SHA-384 PCR.
	nitroPCRLenSHA384 = 48

	// nitroMaxPCRIndex is the highest valid PCR index (AWS CDDL: 0..31).
	nitroMaxPCRIndex = 31

	// nitroMaxOptionalField bounds public_key / user_data / nonce (AWS CDDL:
	// bytes .size (0..1024)).
	nitroMaxOptionalField = 1024

	// nitroMaxClockSkew is the tolerance for a document timestamp that sits
	// slightly ahead of the verifier's clock when freshness is enforced.
	nitroMaxClockSkew = 5 * time.Minute
)

// NitroRootCAFingerprintSHA256 is the AWS-published SHA-256 fingerprint of the
// DER encoding of the AWS Nitro Enclaves Root G1 certificate. The embedded
// root (nitroRootCAPEM) is checked against this value before it is ever used
// as a trust anchor; a mismatch panics (a corrupted pin is a build defect, not
// a runtime condition to recover from).
//
// Source: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
//
//	64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
const NitroRootCAFingerprintSHA256 = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

// nitroRootCAPEM is the AWS Nitro Enclaves Root G1 certificate, downloaded
// from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// and pinned here. Self-signed P-384 (ecdsa-with-SHA384),
// CN=aws.nitro-enclaves, O=Amazon, OU=AWS, valid 2019-10-28..2049-10-28.
const nitroRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
`

var (
	nitroRootOnce       sync.Once
	nitroRootPoolCached *x509.CertPool
	nitroRootCertCached *x509.Certificate
)

// nitroRootInit parses and fingerprint-checks the pinned AWS root exactly
// once. It panics on any failure: the only way it can fail is a corrupted
// embedded constant, which must never reach production.
func nitroRootInit() {
	block, _ := pem.Decode([]byte(nitroRootCAPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		panic("attest: pinned AWS Nitro root is not a CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("attest: pinned AWS Nitro root failed to parse: " + err.Error())
	}
	fp := sha256.Sum256(cert.Raw)
	if hex.EncodeToString(fp[:]) != NitroRootCAFingerprintSHA256 {
		panic("attest: pinned AWS Nitro root fingerprint mismatch (" +
			hex.EncodeToString(fp[:]) + ") — refusing to run")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	nitroRootCertCached = cert
	nitroRootPoolCached = pool
}

// nitroRootPool returns the pinned AWS Nitro Enclaves root as a verify pool.
func nitroRootPool() *x509.CertPool {
	nitroRootOnce.Do(nitroRootInit)
	return nitroRootPoolCached
}

// NitroRootCertificate returns the pinned, fingerprint-checked AWS Nitro
// Enclaves Root G1 certificate. Callers must treat it as read-only.
func NitroRootCertificate() *x509.Certificate {
	nitroRootOnce.Do(nitroRootInit)
	return nitroRootCertCached
}

// WithNitroRoots overrides the trust anchor used to verify the Nitro
// attestation document's certificate chain. Production callers MUST NOT set
// this — the pinned AWS Nitro Enclaves root is the only valid anchor. It
// exists so deterministic tests can verify a self-consistent chain rooted at a
// generated CA. A nil pool falls back to the pinned AWS root. (Mirrors the
// SEV path's WithKDSGetter test-only override.)
func WithNitroRoots(pool *x509.CertPool) Option {
	return func(c *config) { c.nitroRoots = pool }
}

// WithNitroPCRs pins required PCR values by index. Every index supplied must be
// present in the document and equal byte-for-byte, or Verify returns ErrPolicy.
// Use this to pin the enclave image identity (PCR0) and boot chain (PCR1/PCR2).
func WithNitroPCRs(pcrs map[uint][]byte) Option {
	return func(c *config) {
		m := make(map[uint][]byte, len(pcrs))
		for k, v := range pcrs {
			b := make([]byte, len(v))
			copy(b, v)
			m[k] = b
		}
		c.nitroExpectedPCRs = m
	}
}

// WithNitroMaxAge bounds document freshness. When d > 0, Verify refuses a
// document whose timestamp is older than d, or more than nitroMaxClockSkew in
// the future. When unset (the default) no age bound is enforced — callers that
// care about replay MUST set it (or bind a fresh nonce via
// WithExpectedReportData).
func WithNitroMaxAge(d time.Duration) Option {
	return func(c *config) { c.nitroMaxAge = d }
}

// nitroDoc is the decoded AWS Nitro attestation-document payload. Field names
// and types match the AWS CDDL exactly. Optional fields decode to nil when
// absent.
type nitroDoc struct {
	ModuleID    string            `cbor:"module_id"`
	Timestamp   uint64            `cbor:"timestamp"`
	Digest      string            `cbor:"digest"`
	PCRs        map[uint64][]byte `cbor:"pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

// nitroCBORDecMode is the hardened CBOR decoder for the attestation payload.
// Duplicate map keys are rejected so a forger cannot smuggle a second value
// for a field (e.g. two "pcrs" or two "nonce") past the verifier.
var nitroCBORDecMode = func() cbor.DecMode {
	dm, err := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic("attest: nitro CBOR dec mode: " + err.Error())
	}
	return dm
}()

// Verify implements Verifier for AWS Nitro Enclaves attestation documents.
func (Nitro) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	cfg := applyOptions(opts...)

	// 1. COSE_Sign1 envelope (tagged or untagged).
	msg, err := parseNitroCOSESign1(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// 2. Decode the attestation-document payload.
	doc, err := decodeNitroDoc(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// 3. Structural / semantic validation.
	if err := doc.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// 4. Parse the leaf certificate; require ECDSA P-384.
	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, fmt.Errorf("%w: leaf certificate: %v", ErrInvalidEvidence, err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P384() {
		return nil, fmt.Errorf("%w: leaf key is not ECDSA P-384", ErrInvalidEvidence)
	}

	// 5. Build and verify the X.509 chain to the pinned AWS root. We anchor
	//    ONLY at our pinned root; the cabundle's own root (cabundle[0]) is
	//    placed in intermediates, never trusted as an anchor. ExtKeyUsageAny
	//    is required because Nitro leaf certs carry no server-auth EKU.
	roots, err := nitroResolveRoots(cfg)
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for i, der := range doc.CABundle {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: cabundle[%d]: %v", ErrInvalidEvidence, i, err)
		}
		intermediates.AddCert(c)
	}
	now := cfg.nowOrWall()
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}

	// 6. COSE_Sign1 signature against the leaf's P-384 key. go-cose binds the
	//    protected-header alg to the verifier alg, so a document claiming any
	//    algorithm other than ES384 is rejected here (no alg substitution).
	verifier, err := cose.NewVerifier(cose.AlgorithmES384, pub)
	if err != nil {
		return nil, fmt.Errorf("%w: cose verifier: %v", ErrSignatureInvalid, err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	// 7. Caller policy on the now-verified fields.
	pcr0 := doc.PCRs[0]

	if cfg.nitroMaxAge > 0 {
		docTime := time.UnixMilli(int64(doc.Timestamp))
		age := now.Sub(docTime)
		if age < -nitroMaxClockSkew {
			return nil, fmt.Errorf("%w: document timestamp %s is %s in the future",
				ErrPolicy, docTime.UTC(), (-age).String())
		}
		if age > cfg.nitroMaxAge {
			return nil, fmt.Errorf("%w: document age %s exceeds max %s",
				ErrPolicy, age.String(), cfg.nitroMaxAge.String())
		}
	}

	for idx, want := range cfg.nitroExpectedPCRs {
		got, ok := doc.PCRs[uint64(idx)]
		if !ok {
			return nil, fmt.Errorf("%w: required pcr%d absent", ErrPolicy, idx)
		}
		if subtle.ConstantTimeCompare(want, got) != 1 {
			return nil, fmt.Errorf("%w: pcr%d mismatch (got %s)",
				ErrPolicy, idx, hex.EncodeToString(got))
		}
	}

	// Generic policy vocabulary, shared with the other Kinds:
	//   expected measurement -> PCR0 (the enclave image identity),
	//   expected report data -> the document nonce (freshness challenge).
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, pcr0) != 1 {
			return nil, fmt.Errorf("%w: measurement (pcr0) mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(pcr0))
		}
	}
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, doc.Nonce) != 1 {
			return nil, fmt.Errorf("%w: nonce mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(doc.Nonce))
		}
	}

	out := &VerifiedReport{
		Kind:        KindNitro,
		Vendor:      nitroVendor,
		Measurement: cloneBytes(pcr0),
		ReportData:  cloneBytes(doc.Nonce),
		HostData:    cloneBytes(doc.UserData),
		ChipID:      nil, // Nitro documents carry no silicon ID; see Extra["nitro.module_id"].
		IssuedAt:    now.UTC(),
		Extra:       buildNitroExtra(doc, leaf),
	}
	out.CompositeHash = computeCompositeHash(KindNitro, canonicalNitroBytes(doc, leaf))
	return out, nil
}

// nitroResolveRoots returns the trust-anchor pool: the test override when set,
// otherwise the pinned AWS Nitro Enclaves root.
func nitroResolveRoots(cfg config) (*x509.CertPool, error) {
	if cfg.nitroRoots != nil {
		pool, ok := cfg.nitroRoots.(*x509.CertPool)
		if !ok {
			return nil, fmt.Errorf("%w: nitro roots override is not *x509.CertPool", ErrInvalidEvidence)
		}
		if pool != nil {
			return pool, nil
		}
	}
	return nitroRootPool(), nil
}

// parseNitroCOSESign1 decodes a COSE_Sign1, accepting both the CBOR tag-18
// tagged form (0xd2 prefix, what the NSM emits) and the bare untagged 4-array.
func parseNitroCOSESign1(data []byte) (*cose.Sign1Message, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty evidence")
	}
	if data[0] == 0xd2 { // CBOR tag 18 == COSE_Sign1
		var msg cose.Sign1Message
		if err := msg.UnmarshalCBOR(data); err != nil {
			return nil, err
		}
		return &msg, nil
	}
	var um cose.UntaggedSign1Message
	if err := um.UnmarshalCBOR(data); err != nil {
		return nil, err
	}
	msg := cose.Sign1Message(um)
	return &msg, nil
}

// decodeNitroDoc CBOR-decodes the attestation-document payload with the
// hardened, duplicate-key-rejecting decoder.
func decodeNitroDoc(payload []byte) (*nitroDoc, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty attestation payload")
	}
	var doc nitroDoc
	if err := nitroCBORDecMode.Unmarshal(payload, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// validate enforces the structural invariants of the AWS CDDL before any trust
// decision is made on the document's contents.
func (d *nitroDoc) validate() error {
	if d.ModuleID == "" {
		return fmt.Errorf("missing module_id")
	}
	if d.Digest != nitroDigestSHA384 {
		return fmt.Errorf("unsupported digest %q (want %q)", d.Digest, nitroDigestSHA384)
	}
	if d.Timestamp == 0 {
		return fmt.Errorf("missing timestamp")
	}
	if len(d.Certificate) == 0 {
		return fmt.Errorf("missing certificate")
	}
	if len(d.CABundle) == 0 {
		return fmt.Errorf("empty cabundle")
	}
	if len(d.PCRs) == 0 {
		return fmt.Errorf("no pcrs")
	}
	for idx, v := range d.PCRs {
		if idx > nitroMaxPCRIndex {
			return fmt.Errorf("pcr index %d out of range (max %d)", idx, nitroMaxPCRIndex)
		}
		// digest is SHA384, so every locked PCR is exactly 48 bytes.
		if len(v) != nitroPCRLenSHA384 {
			return fmt.Errorf("pcr%d has length %d, want %d", idx, len(v), nitroPCRLenSHA384)
		}
	}
	if _, ok := d.PCRs[0]; !ok {
		return fmt.Errorf("missing pcr0")
	}
	if len(d.PublicKey) > nitroMaxOptionalField {
		return fmt.Errorf("public_key exceeds %d bytes", nitroMaxOptionalField)
	}
	if len(d.UserData) > nitroMaxOptionalField {
		return fmt.Errorf("user_data exceeds %d bytes", nitroMaxOptionalField)
	}
	if len(d.Nonce) > nitroMaxOptionalField {
		return fmt.Errorf("nonce exceeds %d bytes", nitroMaxOptionalField)
	}
	return nil
}

// buildNitroExtra collects Nitro-specific fields that don't fit the common
// shape. Keys are stable wire identifiers prefixed "nitro.".
func buildNitroExtra(d *nitroDoc, leaf *x509.Certificate) map[string]string {
	extra := make(map[string]string, len(d.PCRs)+6)
	extra["nitro.module_id"] = d.ModuleID
	extra["nitro.digest"] = d.Digest
	extra["nitro.timestamp_ms"] = fmt.Sprintf("%d", d.Timestamp)
	for _, idx := range sortedPCRIndices(d.PCRs) {
		extra[fmt.Sprintf("nitro.pcr%d", idx)] = hex.EncodeToString(d.PCRs[idx])
	}
	if len(d.PublicKey) > 0 {
		extra["nitro.public_key"] = hex.EncodeToString(d.PublicKey)
	}
	if len(d.UserData) > 0 {
		extra["nitro.user_data"] = hex.EncodeToString(d.UserData)
	}
	leafFP := sha256.Sum256(leaf.Raw)
	extra["nitro.leaf_fingerprint"] = hex.EncodeToString(leafFP[:])
	return extra
}

// canonicalNitroBytes returns the bytes that participate in CompositeHash. We
// hash the verifier-extracted fields (module_id, digest, timestamp, every PCR
// in ascending index order, nonce, user_data, public_key, and the leaf cert
// fingerprint) in a fixed order. Every variable-length field is 4-byte
// big-endian length-prefixed and the PCR count is prefixed, so the encoding is
// injective: distinct verifier outputs cannot produce the same bytes (and thus
// not the same CompositeHash), even though nonce/user_data/public_key may
// contain NUL. This makes the package guarantee "same CompositeHash ⇒ same
// verifier output" airtight rather than relying on a NUL-free assumption.
func canonicalNitroBytes(d *nitroDoc, leaf *x509.Certificate) []byte {
	buf := make([]byte, 0, 512)
	appendLP := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	appendU64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		buf = append(buf, b[:]...)
	}
	appendLP([]byte(d.ModuleID))
	appendLP([]byte(d.Digest))
	appendU64(d.Timestamp)
	idxs := sortedPCRIndices(d.PCRs)
	appendU64(uint64(len(idxs)))
	for _, idx := range idxs {
		appendU64(idx)
		appendLP(d.PCRs[idx])
	}
	appendLP(d.Nonce)
	appendLP(d.UserData)
	appendLP(d.PublicKey)
	leafFP := sha256.Sum256(leaf.Raw)
	buf = append(buf, leafFP[:]...) // fixed 32 bytes
	return buf
}

// sortedPCRIndices returns the PCR indices in ascending order for deterministic
// iteration (Go map order is randomized).
func sortedPCRIndices(pcrs map[uint64][]byte) []uint64 {
	idx := make([]uint64, 0, len(pcrs))
	for k := range pcrs {
		idx = append(idx, k)
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i] < idx[j] })
	return idx
}

// Compile-time guard: Nitro satisfies Verifier.
var _ Verifier = Nitro{}
