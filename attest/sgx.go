// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// KindSGX is the Intel SGX DCAP ECDSA attestation evidence framing. The
// evidence is a raw Intel SGX ECDSA Quote (version 3, attestation key type
// ECDSA-256-with-P-256) as produced by the Intel-provided Quoting Enclave —
// header || ISV enclave report || quote-signature-data, with the PCK
// certificate chain embedded as certification-data type 5.
const KindSGX Kind = "sgx"

// -----------------------------------------------------------------------------
// SGX verifier — Intel DCAP ECDSA quote verification (pure Go).
//
// There is no maintained pure-Go Google DCAP SGX library (go-sev-guest covers
// AMD SEV-SNP; go-tdx-guest covers Intel TDX; neither parses the SGX v3 quote /
// enclave report). Per the package contract we implement the quote-structure
// parse + ECDSA-P256 signature checks + X.509 chain to the pinned Intel SGX
// Root CA directly, from crypto/{ecdsa,ecdh,x509,sha256} and encoding/{asn1,
// binary,pem}. No cgo, no Intel QVL, no network on the verify path.
//
// What Verify proves, end to end, from the quote bytes alone + the pinned
// Intel SGX Root CA (the full offline DCAP chain of trust):
//
//  1. Structure: version==3, att-key-type==ECDSA-P256, Intel QE Vendor ID,
//     and every length field bounded — a malformed quote never reaches a
//     trust decision (ErrInvalidEvidence).
//  2. PCK chain: the embedded PCK leaf -> Intel SGX Platform/Processor CA ->
//     Intel SGX Root CA chains to the PINNED root (never the root carried in
//     the quote), within certificate validity at the verification clock
//     (ErrChainInvalid; expired/not-yet-valid certs are refused here too).
//  3. QE report signature: the Quoting Enclave report is ECDSA-P256 signed by
//     the PCK leaf key (ErrSignatureInvalid).
//  4. Attestation-key binding: SHA-256(att_pubkey || qe_auth_data) equals the
//     low 32 bytes of the QE report's REPORT_DATA (upper 32 bytes zero). This
//     is the DCAP hinge: it binds the ephemeral attestation key to the
//     PCK-certified, genuine Intel QE (ErrChainInvalid on mismatch).
//  5. ISV report signature: the ISV enclave report (with the quote header) is
//     ECDSA-P256 signed by that bound attestation key (ErrSignatureInvalid).
//     The attestation key point is validated on P-256 before use
//     (invalid-curve defense).
//  6. Measurement: MRENCLAVE (enclave code/data identity) and MRSIGNER
//     (signing identity) are extracted from the ISV report and surfaced as
//     the 64-byte Measurement (MRENCLAVE || MRSIGNER), plus individually in
//     Extra. Caller policy may pin both via WithExpectedMeasurement.
//  7. Freshness: the 64-byte ISV REPORT_DATA carries the caller challenge;
//     WithExpectedReportData binds the gate's nonce (ErrPolicy on mismatch).
//
// HONEST SCOPE — what offline verification does NOT cover without Intel
// collateral (documented, never faked): TCB-level status (UpToDate /
// SWHardeningNeeded / OutOfDate / Revoked) is a function of the platform's
// FMSPC + CPUSVN/PCESVN evaluated against Intel's signed TCB Info, and PCK /
// Root CRLs supply revocation. Those are PCS artifacts fetched by FMSPC from
// api.trustedservices.intel.com (TCB Info + QE Identity + CRLs, each signed by
// Intel's TCB Signing cert which itself chains to this Root CA). This verifier
// extracts and surfaces the platform TCB descriptor (FMSPC, CPUSVN, PCESVN,
// ISV SVN) in Extra so a higher layer holding that collateral evaluates the
// TCB level; certificate-validity staleness IS enforced here. Wiring a signed
// TCB Info / CRL input is the production follow-up — see Extra["sgx.fmspc"].
// -----------------------------------------------------------------------------

// SGX is the Intel SGX DCAP ECDSA quote verifier.
//
// The zero value verifies against the embedded, pinned Intel SGX Root CA and
// is what self-registers under KindSGX. trustRoots is unexported and only set
// by in-package tests (which build a self-consistent chain rooted in a test
// CA); external callers always get the pinned Intel root — there is no
// API to inject an alternate trust anchor, by design (misuse resistance:
// the root is the one thing an attacker must not be able to swap).
type SGX struct {
	// trustRoots, when non-nil, replaces the pinned Intel SGX Root CA as the
	// set of trusted roots. Production leaves it nil. Tests set it directly.
	trustRoots *x509.CertPool
}

// Verify implements Verifier for Intel SGX DCAP ECDSA quotes.
func (s SGX) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	cfg := applyOptions(opts...)

	q, err := parseSGXQuote(evidence)
	if err != nil {
		return nil, err // already wrapped as ErrInvalidEvidence
	}

	roots, err := s.rootPool()
	if err != nil {
		return nil, fmt.Errorf("%w: sgx root pool: %v", ErrChainInvalid, err)
	}

	now := cfg.nowOrWall()

	// (2) PCK chain to the pinned Intel SGX Root CA, within validity at `now`.
	pckLeaf, err := verifyPCKChain(q.pckChain, roots, now)
	if err != nil {
		return nil, fmt.Errorf("%w: pck chain: %v", ErrChainInvalid, err)
	}
	pckKey, ok := pckLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: pck leaf key is %T, want ecdsa", ErrChainInvalid, pckLeaf.PublicKey)
	}

	// (3) QE report is signed by the PCK leaf.
	if !ecdsaVerifyRaw(pckKey, q.qeReport, q.qeReportSig) {
		return nil, fmt.Errorf("%w: qe report signature", ErrSignatureInvalid)
	}

	// (4) Attestation-key binding: SHA-256(att_pubkey || qe_auth_data) equals
	// the low 32 bytes of the QE report's REPORT_DATA, upper 32 bytes zero.
	if err := checkAttestationKeyBinding(q.attPubKeyRaw, q.qeAuthData, q.qeReport); err != nil {
		return nil, fmt.Errorf("%w: attestation key binding: %v", ErrChainInvalid, err)
	}

	// Reconstruct the attestation public key, validating the point is on
	// P-256 (invalid-curve attack defense) before any signature check.
	attKey, err := ecdsaPubFromRaw(q.attPubKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: attestation key: %v", ErrInvalidEvidence, err)
	}

	// (5) ISV enclave report (prefixed by the quote header) is signed by the
	// bound attestation key. signedISV = evidence[0 : headerLen+reportBodyLen].
	if !ecdsaVerifyRaw(attKey, q.signedISV, q.isvReportSig) {
		return nil, fmt.Errorf("%w: isv enclave report signature", ErrSignatureInvalid)
	}

	// (6) Measurement extraction.
	body := q.isvReport
	mrEnclave := body[sgxMrEnclaveOff : sgxMrEnclaveOff+32]
	mrSigner := body[sgxMrSignerOff : sgxMrSignerOff+32]
	reportData := body[sgxReportDataOff : sgxReportDataOff+64]

	measurement := make([]byte, 0, 64)
	measurement = append(measurement, mrEnclave...)
	measurement = append(measurement, mrSigner...)

	// (7) Caller policy: freshness nonce binding against ISV REPORT_DATA.
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, reportData) != 1 {
			return nil, fmt.Errorf("%w: report_data mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(reportData))
		}
	}
	// Caller policy: pin the launch measurement (MRENCLAVE || MRSIGNER).
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, measurement) != 1 {
			return nil, fmt.Errorf("%w: measurement mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(measurement))
		}
	}

	fmspc, pceid := parseSGXPlatformExtension(pckLeaf)

	out := &VerifiedReport{
		Kind:        KindSGX,
		Vendor:      "intel.sgx.dcap",
		Measurement: measurement,
		ReportData:  cloneBytes(reportData),
		ChipID:      sgxChipID(fmspc, pckLeaf),
		IssuedAt:    now.UTC(),
		Extra:       buildSGXExtra(q, mrEnclave, mrSigner, fmspc, pceid, pckLeaf),
	}
	out.CompositeHash = computeCompositeHash(KindSGX, canonicalSGXBytes(q, mrEnclave, mrSigner, reportData, fmspc))
	return out, nil
}

// rootPool returns the trusted root set: the test-injected pool when set,
// otherwise the pinned Intel SGX Root CA.
func (s SGX) rootPool() (*x509.CertPool, error) {
	if s.trustRoots != nil {
		return s.trustRoots, nil
	}
	return intelSGXRootPool()
}

// -----------------------------------------------------------------------------
// Quote wire format (Intel SGX ECDSA Quote v3).
// -----------------------------------------------------------------------------

const (
	sgxQuoteVersion     = 3
	sgxAttKeyTypeECDSA  = 2 // ECDSA-256-with-P-256
	sgxHeaderLen        = 48
	sgxReportBodyLen    = 384
	sgxECDSASigLen      = 64 // r(32) || s(32), big-endian
	sgxECDSAPubLen      = 64 // x(32) || y(32), big-endian
	sgxCertTypePCKChain = 5  // QE certification data type: PCK cert chain (PEM)

	// Header field offsets.
	sgxHdrVersionOff  = 0  // uint16
	sgxHdrAttKeyOff   = 2  // uint16
	sgxHdrVendorIDOff = 12 // [16]byte QE Vendor ID
	sgxHdrVendorIDLen = 16

	// ISV / QE report body field offsets (within a 384-byte report body).
	sgxMrEnclaveOff  = 64
	sgxMrSignerOff   = 128
	sgxIsvProdIDOff  = 256 // uint16
	sgxIsvSvnOff     = 258 // uint16
	sgxAttributesOff = 48  // [16]byte
	sgxCpuSvnOff     = 0   // [16]byte
	sgxReportDataOff = 320 // [64]byte
)

// intelQEVendorID is Intel's Quoting-Enclave vendor identifier carried in the
// header of every Intel-issued ECDSA quote. Non-Intel framings are refused.
var intelQEVendorID = [16]byte{
	0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9,
	0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
}

// sgxQuote is the parsed, bounds-checked view of an SGX ECDSA quote. All
// slices alias the input evidence; nothing is mutated.
type sgxQuote struct {
	isvReport    []byte // 384-byte ISV enclave report body
	signedISV    []byte // header || isvReport (432 bytes) — ISV-sig message
	isvReportSig []byte // 64-byte ECDSA sig over signedISV by the att key
	attPubKeyRaw []byte // 64-byte raw att public key (x || y)
	qeReport     []byte // 384-byte QE report body — QE-sig message
	qeReportSig  []byte // 64-byte ECDSA sig over qeReport by the PCK leaf
	qeAuthData   []byte // QE authentication data (variable)
	pckChain     []byte // PEM-concatenated PCK cert chain (cert-data type 5)
}

// parseSGXQuote parses and bounds-checks an SGX ECDSA v3 quote. Every length
// is validated against the remaining buffer before use, so a truncated or
// over-claiming quote fails as ErrInvalidEvidence rather than panicking.
func parseSGXQuote(b []byte) (*sgxQuote, error) {
	if len(b) < sgxHeaderLen+sgxReportBodyLen+4 {
		return nil, fmt.Errorf("%w: sgx quote too short (%d bytes)", ErrInvalidEvidence, len(b))
	}
	if v := binary.LittleEndian.Uint16(b[sgxHdrVersionOff:]); v != sgxQuoteVersion {
		return nil, fmt.Errorf("%w: sgx quote version %d, want %d", ErrInvalidEvidence, v, sgxQuoteVersion)
	}
	if t := binary.LittleEndian.Uint16(b[sgxHdrAttKeyOff:]); t != sgxAttKeyTypeECDSA {
		return nil, fmt.Errorf("%w: att key type %d, want ECDSA-P256 (%d)", ErrInvalidEvidence, t, sgxAttKeyTypeECDSA)
	}
	if subtle.ConstantTimeCompare(b[sgxHdrVendorIDOff:sgxHdrVendorIDOff+sgxHdrVendorIDLen], intelQEVendorID[:]) != 1 {
		return nil, fmt.Errorf("%w: QE vendor ID is not Intel", ErrInvalidEvidence)
	}

	q := &sgxQuote{}
	q.isvReport = b[sgxHeaderLen : sgxHeaderLen+sgxReportBodyLen]
	q.signedISV = b[:sgxHeaderLen+sgxReportBodyLen]

	r := &cursor{buf: b, off: sgxHeaderLen + sgxReportBodyLen}

	sigLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	// The signature-data length must exactly cover the remaining bytes.
	if int(sigLen) != r.remaining() {
		return nil, fmt.Errorf("%w: sig data length %d != remaining %d", ErrInvalidEvidence, sigLen, r.remaining())
	}

	if q.isvReportSig, err = r.take(sgxECDSASigLen); err != nil {
		return nil, err
	}
	if q.attPubKeyRaw, err = r.take(sgxECDSAPubLen); err != nil {
		return nil, err
	}
	if q.qeReport, err = r.take(sgxReportBodyLen); err != nil {
		return nil, err
	}
	if q.qeReportSig, err = r.take(sgxECDSASigLen); err != nil {
		return nil, err
	}
	authLen, err := r.u16()
	if err != nil {
		return nil, err
	}
	if q.qeAuthData, err = r.take(int(authLen)); err != nil {
		return nil, err
	}
	certType, err := r.u16()
	if err != nil {
		return nil, err
	}
	if certType != sgxCertTypePCKChain {
		return nil, fmt.Errorf("%w: cert-data type %d, want PCK chain (%d)", ErrInvalidEvidence, certType, sgxCertTypePCKChain)
	}
	certLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	if q.pckChain, err = r.take(int(certLen)); err != nil {
		return nil, err
	}
	return q, nil
}

// cursor is a bounds-checked little-endian reader over a byte slice. Returned
// slices alias buf. Any over-read yields ErrInvalidEvidence, never a panic.
type cursor struct {
	buf []byte
	off int
}

func (c *cursor) remaining() int { return len(c.buf) - c.off }

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > c.remaining() {
		return nil, fmt.Errorf("%w: read of %d exceeds %d remaining", ErrInvalidEvidence, n, c.remaining())
	}
	s := c.buf[c.off : c.off+n]
	c.off += n
	return s, nil
}

func (c *cursor) u16() (uint16, error) {
	s, err := c.take(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(s), nil
}

func (c *cursor) u32() (uint32, error) {
	s, err := c.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(s), nil
}

// -----------------------------------------------------------------------------
// Crypto: ECDSA-P256 raw signatures, key binding, chain verification.
// -----------------------------------------------------------------------------

// ecdsaVerifyRaw verifies a 64-byte raw (r||s, big-endian) ECDSA-P256
// signature over SHA-256(msg) by pub. A wrong-length signature is a verify
// failure, not a panic.
func ecdsaVerifyRaw(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if len(sig) != sgxECDSASigLen {
		return false
	}
	digest := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
}

// ecdsaPubFromRaw reconstructs a P-256 public key from the 64-byte raw x||y
// encoding, validating the point lies on the curve via crypto/ecdh (rejecting
// the identity and off-curve points — an invalid-curve attack defense).
func ecdsaPubFromRaw(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != sgxECDSAPubLen {
		return nil, fmt.Errorf("att key is %d bytes, want %d", len(raw), sgxECDSAPubLen)
	}
	uncompressed := make([]byte, 1+sgxECDSAPubLen)
	uncompressed[0] = 0x04
	copy(uncompressed[1:], raw)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		return nil, fmt.Errorf("att key not on P-256: %v", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[:32]),
		Y:     new(big.Int).SetBytes(raw[32:]),
	}, nil
}

// checkAttestationKeyBinding enforces the DCAP binding: the low 32 bytes of the
// QE report's REPORT_DATA equal SHA-256(att_pubkey || qe_auth_data), and the
// upper 32 bytes are zero. This is what ties the ephemeral attestation key to a
// PCK-certified, genuine Intel Quoting Enclave.
func checkAttestationKeyBinding(attPubKeyRaw, qeAuthData, qeReport []byte) error {
	h := sha256.New()
	h.Write(attPubKeyRaw)
	h.Write(qeAuthData)
	want := h.Sum(nil)

	got := qeReport[sgxReportDataOff : sgxReportDataOff+64]
	if subtle.ConstantTimeCompare(want, got[:32]) != 1 {
		return fmt.Errorf("hash(att_pubkey||auth) != qe report_data[0:32]")
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(zero[:], got[32:64]) != 1 {
		return fmt.Errorf("qe report_data[32:64] not zero-padded")
	}
	return nil
}

// verifyPCKChain parses the PEM-concatenated PCK chain (leaf first) and
// verifies the leaf chains to one of the pinned roots at time `now`. The root
// carried inside the quote is NEVER trusted: only `roots` is. Returns the
// verified PCK leaf certificate.
func verifyPCKChain(chainPEM []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := chainPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse cert: %v", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates in PCK chain")
	}

	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// PCK certs do not carry standard TLS EKUs; accept any so the chain
		// check is purely identity + validity + signature, not key-purpose.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, err
	}
	return leaf, nil
}

// -----------------------------------------------------------------------------
// Intel SGX platform extension (FMSPC / PCEID) — best-effort, informational.
// -----------------------------------------------------------------------------

var (
	oidSGXExtensions = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	oidSGXPCEID      = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 3}
	oidSGXFMSPC      = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
)

// parseSGXPlatformExtension extracts FMSPC (6 bytes) and PCEID (2 bytes) from
// the Intel SGX X.509 extension on the PCK leaf. Best-effort: returns nil on
// any absence or parse error. FMSPC keys Intel's TCB Info collateral; it is
// surfaced for a TCB-evaluating layer, not used as a trust-path decision.
func parseSGXPlatformExtension(cert *x509.Certificate) (fmspc, pceid []byte) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidSGXExtensions) {
			continue
		}
		var outer asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &outer); err != nil {
			return nil, nil
		}
		body := outer.Bytes
		for len(body) > 0 {
			var item asn1.RawValue
			var err error
			body, err = asn1.Unmarshal(body, &item)
			if err != nil {
				return fmspc, pceid
			}
			oid, val := splitOIDValue(item.Bytes)
			switch {
			case oid.Equal(oidSGXFMSPC):
				fmspc = octetString(val)
			case oid.Equal(oidSGXPCEID):
				pceid = octetString(val)
			}
		}
		return fmspc, pceid
	}
	return nil, nil
}

// splitOIDValue decodes a SEQUENCE { OID, value } body into the OID and the
// raw remaining value bytes.
func splitOIDValue(seqBody []byte) (asn1.ObjectIdentifier, []byte) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(seqBody, &oid)
	if err != nil {
		return nil, nil
	}
	return oid, rest
}

// octetString returns the contents of a DER OCTET STRING, or nil.
func octetString(der []byte) []byte {
	var v asn1.RawValue
	if _, err := asn1.Unmarshal(der, &v); err != nil {
		return nil
	}
	if v.Tag != asn1.TagOctetString {
		return nil
	}
	return v.Bytes
}

// sgxChipID returns the silicon identifier for the report: the FMSPC when
// available (the platform-TCB family key), else the PCK leaf's raw subject
// key identifier as a stable per-platform fallback.
func sgxChipID(fmspc []byte, leaf *x509.Certificate) []byte {
	if len(fmspc) > 0 {
		return cloneBytes(fmspc)
	}
	return cloneBytes(leaf.SubjectKeyId)
}

// -----------------------------------------------------------------------------
// VerifiedReport projection.
// -----------------------------------------------------------------------------

func buildSGXExtra(q *sgxQuote, mrEnclave, mrSigner, fmspc, pceid []byte, leaf *x509.Certificate) map[string]string {
	body := q.isvReport
	extra := map[string]string{
		"sgx.mrenclave":   hex.EncodeToString(mrEnclave),
		"sgx.mrsigner":    hex.EncodeToString(mrSigner),
		"sgx.isv_prod_id": fmt.Sprintf("%d", binary.LittleEndian.Uint16(body[sgxIsvProdIDOff:])),
		"sgx.isv_svn":     fmt.Sprintf("%d", binary.LittleEndian.Uint16(body[sgxIsvSvnOff:])),
		"sgx.attributes":  hex.EncodeToString(body[sgxAttributesOff : sgxAttributesOff+16]),
		"sgx.cpu_svn":     hex.EncodeToString(body[sgxCpuSvnOff : sgxCpuSvnOff+16]),
		"sgx.pck_subject": leaf.Subject.CommonName,
	}
	if len(fmspc) > 0 {
		extra["sgx.fmspc"] = hex.EncodeToString(fmspc)
	}
	if len(pceid) > 0 {
		extra["sgx.pceid"] = hex.EncodeToString(pceid)
	}
	return extra
}

// canonicalSGXBytes returns the deterministic, fixed-shape bytes that feed
// CompositeHash: the verifier-extracted fields, never the raw quote. Re-
// deriving on the consumer side reproduces the same hash iff the same quote
// was verified. Layout (fixed widths): mrenclave(32) || mrsigner(32) ||
// report_data(64) || isv_prod_id(2 LE) || isv_svn(2 LE) || attributes(16) ||
// fmspc(6, zero-padded).
func canonicalSGXBytes(q *sgxQuote, mrEnclave, mrSigner, reportData, fmspc []byte) []byte {
	body := q.isvReport
	buf := make([]byte, 0, 32+32+64+2+2+16+6)
	buf = append(buf, fixedSize(mrEnclave, 32)...)
	buf = append(buf, fixedSize(mrSigner, 32)...)
	buf = append(buf, fixedSize(reportData, 64)...)
	buf = append(buf, body[sgxIsvProdIDOff:sgxIsvProdIDOff+2]...)
	buf = append(buf, body[sgxIsvSvnOff:sgxIsvSvnOff+2]...)
	buf = append(buf, body[sgxAttributesOff:sgxAttributesOff+16]...)
	buf = append(buf, fixedSize(fmspc, 6)...)
	return buf
}

// -----------------------------------------------------------------------------
// Pinned Intel SGX Root CA.
// -----------------------------------------------------------------------------

// intelSGXRootCAPEM is the Intel SGX Provisioning Certification Root CA,
// fetched from
// https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem
// Subject/Issuer: CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara,
// ST=CA, C=US. ECDSA-P256, valid 2018-05-21 .. 2049-12-31. SHA-256
// fingerprint 44A0196B2B99F889B8E149E95B807A350E74249643 99E885A7CBB8CCFAB674D3.
// This is the single offline trust anchor for the SGX DCAP chain; it is
// pinned in source, never read from the quote.
const intelSGXRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----`

var (
	intelRootOnce sync.Once
	intelRootPool *x509.CertPool
	intelRootErr  error
)

// intelSGXRootPool parses the pinned Intel SGX Root CA once into a cert pool.
func intelSGXRootPool() (*x509.CertPool, error) {
	intelRootOnce.Do(func() {
		block, _ := pem.Decode([]byte(intelSGXRootCAPEM))
		if block == nil {
			intelRootErr = fmt.Errorf("pinned Intel SGX Root CA PEM did not decode")
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			intelRootErr = fmt.Errorf("pinned Intel SGX Root CA parse: %v", err)
			return
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		intelRootPool = pool
	})
	return intelRootPool, intelRootErr
}

// -----------------------------------------------------------------------------
// Self-registration (driver pattern).
//
// The package's legacy Dispatch routes a fixed switch of Kinds in verifier.go.
// New Kinds self-register here from their own file's init(), the open
// extension point that needs no central edit. RegisteredVerifier is the
// lookup; the intended end-state folds Dispatch's default case into it so
// there is one routing path. Until then, KindSGX is reached via
// RegisteredVerifier(KindSGX) or the SGX value directly.
// -----------------------------------------------------------------------------

var (
	registryMu sync.RWMutex
	registry   = map[Kind]Verifier{}
)

func registerVerifier(kind Kind, v Verifier) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[kind] = v
}

// RegisteredVerifier returns the verifier a Kind self-registered via init(),
// if any. It is the driver-pattern lookup for Kinds added without editing the
// central Dispatch switch.
func RegisteredVerifier(kind Kind) (Verifier, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	v, ok := registry[kind]
	return v, ok
}

func init() { registerVerifier(KindSGX, SGX{}) }

// Compile-time guard: SGX satisfies Verifier.
var _ Verifier = SGX{}
