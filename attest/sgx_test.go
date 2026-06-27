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
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Self-consistent Intel SGX ECDSA quote vector.
//
// There is no maintained pure-Go Google DCAP SGX library and no committable
// real-vendor SGX quote in this repo (the SEV path embeds a real AMD report as
// a testdata file; we are constrained to a single _test.go file). So — exactly
// as nvtrust_test.go builds a matched (report, signed RIM, trust roots) triple
// with a fresh key — we synthesise a byte-exact Intel SGX ECDSA Quote v3 over a
// freshly generated PCK chain rooted in a test CA, with the attestation key
// bound into the QE report per the DCAP spec. The verification CODE under test
// is identical to what runs against a real Intel quote; only the trust anchor
// differs (test root here; the pinned Intel SGX Root CA in production, which
// the registered zero-value verifier uses — see TestSGX_PinnedRootRefusesTestChain).
//
// Wire layout produced (Intel SGX ECDSA QuoteLibReference, DCAP):
//
//	header[48] || isv_report[384] || u32(sig_len) ||
//	  isv_report_sig[64] || att_pubkey[64] || qe_report[384] || qe_report_sig[64] ||
//	  u16(auth_len) || auth[auth_len] || u16(cert_type=5) || u32(cert_len) || pck_chain_pem
// -----------------------------------------------------------------------------

type quoteSpec struct {
	mrEnclave [32]byte
	mrSigner  [32]byte
	nonce     [64]byte // ISV report_data (caller freshness challenge)
	isvProdID uint16
	isvSvn    uint16
	fmspc     []byte // 6 bytes; nil omits the Intel SGX extension
	pceid     []byte // 2 bytes
	notBefore time.Time
	notAfter  time.Time

	breakBinding bool // corrupt the att-key <-> QE binding (valid QE sig)
}

// offs records absolute byte offsets of mutable regions for tamper tests.
type offs struct {
	isvSig    int
	qeSig     int
	qeAuth    int
	mrEnclave int
}

type quoteFixture struct {
	quote []byte
	roots *x509.CertPool // trust anchor (the test root) for SGX{trustRoots:...}
	off   offs
}

func buildSGXQuote(t *testing.T, spec quoteSpec) quoteFixture {
	t.Helper()

	// --- PCK chain: test Root CA -> intermediate CA -> PCK leaf. ---
	rootKey := mustECDSA(t)
	intKey := mustECDSA(t)
	pckKey := mustECDSA(t)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test SGX Root CA"},
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootCert := mustCert(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intel SGX PCK Platform CA"},
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intCert := mustCert(t, intTmpl, rootCert, &intKey.PublicKey, rootKey)

	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Intel SGX PCK Certificate"},
		NotBefore:             spec.notBefore,
		NotAfter:              spec.notAfter,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01, 0x02, 0x03, 0x04, 0x05},
	}
	if spec.fmspc != nil {
		der, err := asn1.Marshal([]sgxExtItem{
			{OID: oidSGXFMSPC, Value: spec.fmspc},
			{OID: oidSGXPCEID, Value: spec.pceid},
		})
		if err != nil {
			t.Fatalf("marshal sgx ext: %v", err)
		}
		leafTmpl.ExtraExtensions = []pkix.Extension{{Id: oidSGXExtensions, Value: der}}
	}
	leafCert := mustCert(t, leafTmpl, intCert, &pckKey.PublicKey, intKey)

	chainPEM := bytes.Join([][]byte{
		pemCert(leafCert), pemCert(intCert), pemCert(rootCert),
	}, nil)

	// --- Attestation key (ephemeral, certified via the QE report binding). ---
	attKey := mustECDSA(t)
	attPubRaw := make([]byte, sgxECDSAPubLen)
	attKey.PublicKey.X.FillBytes(attPubRaw[:32])
	attKey.PublicKey.Y.FillBytes(attPubRaw[32:])

	authData := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33}

	// --- QE report: report_data[0:32] = SHA256(att_pubkey || auth), [32:64]=0. ---
	qeReport := make([]byte, sgxReportBodyLen)
	bind := sha256.New()
	bind.Write(attPubRaw)
	bind.Write(authData)
	copy(qeReport[sgxReportDataOff:], bind.Sum(nil))
	if spec.breakBinding {
		qeReport[sgxReportDataOff] ^= 0xFF // valid QE sig, wrong binding
	}
	qeSig := ecdsaRawSign(t, pckKey, qeReport)

	// --- ISV enclave report: MRENCLAVE, MRSIGNER, REPORT_DATA(nonce), SVNs. ---
	isvReport := make([]byte, sgxReportBodyLen)
	copy(isvReport[sgxMrEnclaveOff:], spec.mrEnclave[:])
	copy(isvReport[sgxMrSignerOff:], spec.mrSigner[:])
	copy(isvReport[sgxReportDataOff:], spec.nonce[:])
	binary.LittleEndian.PutUint16(isvReport[sgxIsvProdIDOff:], spec.isvProdID)
	binary.LittleEndian.PutUint16(isvReport[sgxIsvSvnOff:], spec.isvSvn)
	// attributes / cpu_svn: deterministic non-zero so Extra is meaningful.
	copy(isvReport[sgxAttributesOff:], []byte{0x07, 0, 0, 0, 0, 0, 0, 0, 0x03, 0, 0, 0, 0, 0, 0, 0})
	copy(isvReport[sgxCpuSvnOff:], bytes.Repeat([]byte{0x09}, 16))

	// --- Header: version=3, att_key_type=ECDSA-P256, Intel QE vendor ID. ---
	header := make([]byte, sgxHeaderLen)
	binary.LittleEndian.PutUint16(header[sgxHdrVersionOff:], sgxQuoteVersion)
	binary.LittleEndian.PutUint16(header[sgxHdrAttKeyOff:], sgxAttKeyTypeECDSA)
	copy(header[sgxHdrVendorIDOff:], intelQEVendorID[:])

	// --- ISV report signature over header||isv_report by the attestation key. ---
	signedISV := append(append([]byte{}, header...), isvReport...)
	isvSig := ecdsaRawSign(t, attKey, signedISV)

	// --- Assemble signature data, then the full quote. ---
	var sig bytes.Buffer
	sig.Write(isvSig)
	sig.Write(attPubRaw)
	sig.Write(qeReport)
	sig.Write(qeSig)
	writeU16(&sig, uint16(len(authData)))
	sig.Write(authData)
	writeU16(&sig, sgxCertTypePCKChain)
	writeU32(&sig, uint32(len(chainPEM)))
	sig.Write(chainPEM)

	var quote bytes.Buffer
	quote.Write(header)
	quote.Write(isvReport)
	writeU32(&quote, uint32(sig.Len()))
	quote.Write(sig.Bytes())

	base := sgxHeaderLen + sgxReportBodyLen + 4 // start of sig data
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	return quoteFixture{
		quote: quote.Bytes(),
		roots: roots,
		off: offs{
			isvSig:    base + 0,
			qeSig:     base + sgxECDSASigLen + sgxECDSAPubLen + sgxReportBodyLen,
			qeAuth:    base + sgxECDSASigLen + sgxECDSAPubLen + sgxReportBodyLen + sgxECDSASigLen + 2,
			mrEnclave: sgxHeaderLen + sgxMrEnclaveOff,
		},
	}
}

type sgxExtItem struct {
	OID   asn1.ObjectIdentifier
	Value []byte
}

func defaultSpec() quoteSpec {
	s := quoteSpec{
		isvProdID: 7,
		isvSvn:    3,
		fmspc:     []byte{0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00},
		pceid:     []byte{0x00, 0x00},
		notBefore: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		notAfter:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for i := range s.mrEnclave {
		s.mrEnclave[i] = byte(i)
	}
	for i := range s.mrSigner {
		s.mrSigner[i] = byte(0x80 + i)
	}
	for i := range s.nonce {
		s.nonce[i] = byte(0xC0 + i)
	}
	return s
}

func validNow() time.Time { return time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) }

func mustECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create cert %q: %v", tmpl.Subject.CommonName, err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert %q: %v", tmpl.Subject.CommonName, err)
	}
	return c
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func ecdsaRawSign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := make([]byte, sgxECDSASigLen)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func writeU16(b *bytes.Buffer, v uint16) {
	var p [2]byte
	binary.LittleEndian.PutUint16(p[:], v)
	b.Write(p[:])
}

func writeU32(b *bytes.Buffer, v uint32) {
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], v)
	b.Write(p[:])
}

// verifyTest runs the SGX verifier against a test-rooted chain at validNow.
func (f quoteFixture) verify(opts ...Option) (*VerifiedReport, error) {
	o := append([]Option{WithNow(validNow())}, opts...)
	return SGX{trustRoots: f.roots}.Verify(context.Background(), f.quote, o...)
}

// -----------------------------------------------------------------------------
// Happy path.
// -----------------------------------------------------------------------------

func TestSGX_Verify_HappyPath(t *testing.T) {
	spec := defaultSpec()
	f := buildSGXQuote(t, spec)

	rep, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Kind != KindSGX {
		t.Errorf("kind = %q, want %q", rep.Kind, KindSGX)
	}
	if rep.Vendor != "intel.sgx.dcap" {
		t.Errorf("vendor = %q", rep.Vendor)
	}
	wantMeas := append(append([]byte{}, spec.mrEnclave[:]...), spec.mrSigner[:]...)
	if !bytes.Equal(rep.Measurement, wantMeas) {
		t.Errorf("measurement = %x, want %x", rep.Measurement, wantMeas)
	}
	if !bytes.Equal(rep.ReportData, spec.nonce[:]) {
		t.Errorf("report_data = %x, want %x", rep.ReportData, spec.nonce[:])
	}
	if !bytes.Equal(rep.ChipID, spec.fmspc) {
		t.Errorf("chip_id = %x, want fmspc %x", rep.ChipID, spec.fmspc)
	}
	if rep.IssuedAt.IsZero() {
		t.Error("issued_at not set")
	}
	if rep.CompositeHash == ([32]byte{}) {
		t.Error("composite hash is zero")
	}
	for _, k := range []string{"sgx.mrenclave", "sgx.mrsigner", "sgx.isv_prod_id", "sgx.isv_svn", "sgx.fmspc", "sgx.cpu_svn"} {
		if _, ok := rep.Extra[k]; !ok {
			t.Errorf("missing extra key %q", k)
		}
	}
	if rep.Extra["sgx.isv_prod_id"] != "7" || rep.Extra["sgx.isv_svn"] != "3" {
		t.Errorf("svn extras = %q/%q, want 7/3", rep.Extra["sgx.isv_prod_id"], rep.Extra["sgx.isv_svn"])
	}
}

func TestSGX_Verify_PolicyBindings(t *testing.T) {
	spec := defaultSpec()
	f := buildSGXQuote(t, spec)
	wantMeas := append(append([]byte{}, spec.mrEnclave[:]...), spec.mrSigner[:]...)

	if _, err := f.verify(
		WithExpectedReportData(spec.nonce[:]),
		WithExpectedMeasurement(wantMeas),
	); err != nil {
		t.Fatalf("verify with correct policy: %v", err)
	}
}

func TestSGX_Verify_DeterministicCompositeHash(t *testing.T) {
	// Two quotes with identical measured fields but independent keys/sigs must
	// yield the same CompositeHash: it is over extracted fields, not the wire.
	spec := defaultSpec()
	f1 := buildSGXQuote(t, spec)
	f2 := buildSGXQuote(t, spec)

	r1, err := f1.verify()
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}
	r2, err := f2.verify()
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if r1.CompositeHash != r2.CompositeHash {
		t.Errorf("composite hash not deterministic across keys: %x vs %x", r1.CompositeHash, r2.CompositeHash)
	}
}

func TestSGX_Verify_FMSPCFallbackToSubjectKeyID(t *testing.T) {
	spec := defaultSpec()
	spec.fmspc = nil // omit Intel SGX extension -> ChipID falls back
	f := buildSGXQuote(t, spec)

	rep, err := f.verify()
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(rep.ChipID) == 0 {
		t.Error("chip_id empty; want PCK SubjectKeyId fallback")
	}
	if _, ok := rep.Extra["sgx.fmspc"]; ok {
		t.Error("sgx.fmspc present despite omitted extension")
	}
}

// -----------------------------------------------------------------------------
// Self-registration + pinned-root behaviour.
// -----------------------------------------------------------------------------

func TestSGX_SelfRegisteredViaInit(t *testing.T) {
	v, ok := RegisteredVerifier(KindSGX)
	if !ok {
		t.Fatal("KindSGX did not self-register via init()")
	}
	if _, isSGX := v.(SGX); !isSGX {
		t.Fatalf("registered verifier is %T, want SGX", v)
	}
}

func TestSGX_PinnedRootRefusesTestChain(t *testing.T) {
	// The registered zero-value verifier trusts ONLY the pinned Intel SGX Root
	// CA. A self-rooted test quote must be refused — proof the root is pinned,
	// not taken from the quote.
	f := buildSGXQuote(t, defaultSpec())
	v, _ := RegisteredVerifier(KindSGX)

	_, err := v.Verify(context.Background(), f.quote, WithNow(validNow()))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid (test chain must not chain to Intel root)", err)
	}
}

// -----------------------------------------------------------------------------
// Tamper / refusal.
// -----------------------------------------------------------------------------

func TestSGX_Verify_RejectsTamperedISVSignature(t *testing.T) {
	f := buildSGXQuote(t, defaultSpec())
	f.quote[f.off.isvSig+5] ^= 0x01

	_, err := f.verify()
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestSGX_Verify_RejectsTamperedQESignature(t *testing.T) {
	f := buildSGXQuote(t, defaultSpec())
	f.quote[f.off.qeSig+5] ^= 0x01

	_, err := f.verify()
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestSGX_Verify_RejectsTamperedMeasurementBody(t *testing.T) {
	// Flipping a MRENCLAVE byte after signing breaks the ISV report signature
	// (the body is covered): integrity is enforced cryptographically.
	f := buildSGXQuote(t, defaultSpec())
	f.quote[f.off.mrEnclave] ^= 0x01

	_, err := f.verify()
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestSGX_Verify_RejectsBrokenAttKeyBinding(t *testing.T) {
	// QE report signature is valid, but SHA256(att_pubkey||auth) no longer
	// matches the QE report_data: the attestation key is not QE-certified.
	spec := defaultSpec()
	spec.breakBinding = true
	f := buildSGXQuote(t, spec)

	_, err := f.verify()
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

func TestSGX_Verify_RejectsWrongMeasurementPolicy(t *testing.T) {
	f := buildSGXQuote(t, defaultSpec())
	wrong := bytes.Repeat([]byte{0xAB}, 64)

	_, err := f.verify(WithExpectedMeasurement(wrong))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestSGX_Verify_RejectsWrongReportDataPolicy(t *testing.T) {
	f := buildSGXQuote(t, defaultSpec())
	wrong := bytes.Repeat([]byte{0xFF}, 64)

	_, err := f.verify(WithExpectedReportData(wrong))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestSGX_Verify_RejectsStaleChain(t *testing.T) {
	// Verification clock past the PCK chain's NotAfter -> expired -> refused.
	f := buildSGXQuote(t, defaultSpec())

	_, err := SGX{trustRoots: f.roots}.Verify(
		context.Background(), f.quote,
		WithNow(time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)),
	)
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid (expired chain)", err)
	}
}

func TestSGX_Verify_RejectsUntrustedRoot(t *testing.T) {
	// A different, unrelated root must not validate the chain.
	f := buildSGXQuote(t, defaultSpec())
	otherRoot := x509.NewCertPool()
	otherKey := mustECDSA(t)
	otherTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Unrelated Root"},
		NotBefore:             defaultSpec().notBefore,
		NotAfter:              defaultSpec().notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	otherRoot.AddCert(mustCert(t, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey))

	_, err := SGX{trustRoots: otherRoot}.Verify(context.Background(), f.quote, WithNow(validNow()))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

func TestSGX_Verify_RejectsMalformed(t *testing.T) {
	cases := []struct {
		name  string
		quote []byte
	}{
		{"empty", nil},
		{"truncated", make([]byte, 100)},
		{"bad-version", func() []byte {
			f := buildSGXQuote(t, defaultSpec())
			binary.LittleEndian.PutUint16(f.quote[sgxHdrVersionOff:], 99)
			return f.quote
		}()},
		{"bad-att-key-type", func() []byte {
			f := buildSGXQuote(t, defaultSpec())
			binary.LittleEndian.PutUint16(f.quote[sgxHdrAttKeyOff:], 7)
			return f.quote
		}()},
		{"non-intel-vendor", func() []byte {
			f := buildSGXQuote(t, defaultSpec())
			f.quote[sgxHdrVendorIDOff] ^= 0xFF
			return f.quote
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := SGX{}.Verify(context.Background(), c.quote, WithNow(validNow()))
			if !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("err = %v, want ErrInvalidEvidence", err)
			}
		})
	}
}

// TestSGX_Verify_NeverReturnsPartialOnError asserts the package invariant: a
// non-nil error always pairs with a nil report.
func TestSGX_Verify_NeverReturnsPartialOnError(t *testing.T) {
	f := buildSGXQuote(t, defaultSpec())
	f.quote[f.off.isvSig+1] ^= 0x01

	rep, err := f.verify()
	if err == nil {
		t.Fatal("expected error")
	}
	if rep != nil {
		t.Fatalf("got non-nil report on error: %+v", rep)
	}
}
