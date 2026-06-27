// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/cc/attest/nvidia"
)

// =============================================================================
// Self-consistent ModeLocal vector: a real SPDM-signed measurement report,
// a device cert chain (root -> intermediate -> leaf, ECDSA P-384) that the
// leaf key signs the report under, and an NVIDIA-signed RIM whose index-
// keyed golden values equal the signed measurements.
//
// The verification logic exercised is production-real (real ECDSA P-384
// over the real DSP0274 transcript, real X.509 path validation, real RIM
// signature + index match). Only the trust anchor is a test root, exactly
// as go-sev-guest's tests use a test signer and production pins AMD's root.
// =============================================================================

const (
	testFixedNow   = "2026-06-27T12:00:00Z"
	testArch       = "Hopper"
	testDriver     = "535.104.05"
	testVBIOS      = "96.00.74.00.01"
	testLeafSerial = 0x4e56494449413031 // "NVIDIA01" as an int serial
)

// localVector is everything a ModeLocal Verify needs, plus the knobs to
// tamper for negative cases.
type localVector struct {
	evidence  []byte // the GPU evidence envelope JSON
	rim       []byte // signed RIM
	rimRoots  []nvidia.TrustRoot
	devRoots  *x509.CertPool
	nonce     [32]byte
	leafCert  *x509.Certificate
	leafPriv  *ecdsa.PrivateKey
	intermPEM string
	now       time.Time
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	return tm
}

func u8ptr(v uint8) *uint8 { return &v }

func mkCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func le16(v int) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(v))
	return b
}

func le24(v int) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16)}
}

// joseConcat encodes (r,s) as fixed-width big-endian r||s (the SPDM/JOSE form).
func joseConcatLocal(r, s *big.Int, size int) []byte {
	out := make([]byte, size*2)
	rB := r.Bytes()
	sB := s.Bytes()
	copy(out[size-len(rB):size], rB)
	copy(out[size*2-len(sB):], sB)
	return out
}

// buildSPDMRequest builds a GET_MEASUREMENTS (0xE0) request asking for all
// blocks with a signature, carrying the requester nonce.
func buildSPDMRequest(version byte, nonce [32]byte) []byte {
	req := []byte{version, 0xE0, 0x01 /*sig requested*/, 0xFF /*all blocks*/}
	req = append(req, nonce[:]...)
	req = append(req, 0x00) // SlotIDParam
	return req
}

type measBlock struct {
	index uint8
	value []byte // 48-byte digest
}

// buildSignedSPDMResponse builds a MEASUREMENTS (0x60) response over the
// given blocks and signs the DSP0274 transcript (request || responseBody)
// with leafPriv. Returns the full response message (body || signature).
func buildSignedSPDMResponse(t *testing.T, version byte, blocks []measBlock, respNonce [32]byte, leafPriv *ecdsa.PrivateKey, requestMsg []byte) []byte {
	t.Helper()
	var record []byte
	for _, b := range blocks {
		dmtf := []byte{0x00} // value type: digest (bit7=0), type 0
		dmtf = append(dmtf, le16(len(b.value))...)
		dmtf = append(dmtf, b.value...)
		blk := []byte{b.index, 0x01 /*DMTF spec*/}
		blk = append(blk, le16(len(dmtf))...)
		blk = append(blk, dmtf...)
		record = append(record, blk...)
	}
	body := []byte{version, 0x60, 0x00, 0x00, byte(len(blocks))}
	body = append(body, le24(len(record))...)
	body = append(body, record...)
	body = append(body, respNonce[:]...)
	body = append(body, le16(0)...) // opaque length 0

	digest := spdmDigestForTest(version, requestMsg, body)
	r, s, err := ecdsa.Sign(rand.Reader, leafPriv, digest)
	if err != nil {
		t.Fatalf("spdm sign: %v", err)
	}
	sig := joseConcatLocal(r, s, 48) // P-384 -> 96-byte r||s
	return append(body, sig...)
}

// spdmDigestForTest independently reproduces the DSP0274 transcript digest
// the verifier checks (SHA-384). 1.1: SHA384(req||body). 1.2: SHA384(ctx ||
// SHA384(req||body)).
func spdmDigestForTest(version byte, requestMsg, body []byte) []byte {
	h := sha512.New384()
	h.Write(requestMsg)
	h.Write(body)
	th := h.Sum(nil)
	if version < 0x12 {
		return th
	}
	const prefixUnit = "dmtf-spdm-v1.2.*"
	const context = "responder-measurements signing"
	ctx := make([]byte, 100)
	for i := 0; i < 4; i++ {
		copy(ctx[i*16:(i+1)*16], prefixUnit)
	}
	copy(ctx[100-len(context):], context)
	h2 := sha512.New384()
	h2.Write(ctx)
	h2.Write(th)
	return h2.Sum(nil)
}

// buildLocalVector assembles a complete, valid ModeLocal vector for the
// given SPDM version.
func buildLocalVector(t *testing.T, version byte) localVector {
	t.Helper()
	now := mustTime(t, testFixedNow)

	// --- device chain: root -> intermediate -> leaf (all P-384) ---
	rootPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	intermPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	leafPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "NVIDIA Test Device Identity Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	rootCert := mkCert(t, rootTmpl, rootTmpl, rootPriv.Public(), rootPriv)

	intermTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "NVIDIA Test GPU Attestation CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	intermCert := mkCert(t, intermTmpl, rootCert, intermPriv.Public(), rootPriv)

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(testLeafSerial),
		Subject:      pkix.Name{CommonName: "GPU-TEST-0001"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCert := mkCert(t, leafTmpl, intermCert, leafPriv.Public(), intermPriv)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	// --- SPDM request + signed response ---
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	var respNonce [32]byte
	for i := range respNonce {
		respNonce[i] = byte(0xA0 + i)
	}
	val0 := bytes.Repeat([]byte{0x11}, 48)
	val1 := bytes.Repeat([]byte{0x22}, 48)
	req := buildSPDMRequest(version, nonce)
	resp := buildSignedSPDMResponse(t, version, []measBlock{
		{index: 0, value: val0},
		{index: 1, value: val1},
	}, respNonce, leafPriv, req)

	// --- RIM: index-keyed golden values == the signed measurements ---
	rimPub, rimPriv, _ := ed25519.GenerateKey(rand.Reader)
	rimRoots := []nvidia.TrustRoot{{KeyID: "nvidia-rim-1", Public: rimPub}}
	entries := []nvidia.RIMEntry{
		{Name: "FW_RT", ValueHex: hex.EncodeToString(val0), Index: u8ptr(0)},
		{Name: "VBIOS_RT", ValueHex: hex.EncodeToString(val1), Index: u8ptr(1)},
	}
	rim := signRIMEd25519(t, rimPriv, "nvidia-rim-1", testArch, testDriver, testVBIOS, entries)

	// --- evidence envelope ---
	env := map[string]any{
		"evidence_version": "2.1",
		"gpu_uuid":         "GPU-TEST-0001",
		"architecture":     testArch,
		"driver_version":   testDriver,
		"vbios_version":    testVBIOS,
		"nonce":            hex.EncodeToString(nonce[:]),
		"cert_chain":       []string{certPEM(leafCert), certPEM(intermCert)},
		"spdm_request":     base64.StdEncoding.EncodeToString(req),
		"spdm_response":    base64.StdEncoding.EncodeToString(resp),
		"spdm_asym_algo":   "ecdsa-p384-sha384",
		"measurements": []map[string]any{
			{"pcr_index": 0, "name": "FW_RT", "value": hex.EncodeToString(val0)},
			{"pcr_index": 1, "name": "VBIOS_RT", "value": hex.EncodeToString(val1)},
		},
	}
	evidence, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	return localVector{
		evidence:  evidence,
		rim:       rim,
		rimRoots:  rimRoots,
		devRoots:  rootPool,
		nonce:     nonce,
		leafCert:  leafCert,
		leafPriv:  leafPriv,
		intermPEM: certPEM(intermCert),
		now:       now,
	}
}

func (v localVector) verifier() NVTrust {
	return NewNVTrust(
		WithNVTrustDeviceRoots(v.devRoots),
		WithNVTrustClock(func() time.Time { return v.now }),
	)
}

// =============================================================================
// signRIMEd25519 — reproduces the nvidia RIM wire format (canonical body =
// json.Marshal of architecture/driver/vbios/entries; signed blob appends
// signer_key_id + signature). Entries may carry an index (omitempty).
// =============================================================================

func signRIMEd25519(t *testing.T, priv ed25519.PrivateKey, kid, arch, driver, vbios string, entries []nvidia.RIMEntry) []byte {
	t.Helper()
	body := struct {
		Architecture  string            `json:"architecture"`
		DriverVersion string            `json:"driver_version"`
		VBIOSVersion  string            `json:"vbios_version"`
		Entries       []nvidia.RIMEntry `json:"entries"`
	}{arch, driver, vbios, entries}
	canon, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	signed := struct {
		Architecture  string            `json:"architecture"`
		DriverVersion string            `json:"driver_version"`
		VBIOSVersion  string            `json:"vbios_version"`
		Entries       []nvidia.RIMEntry `json:"entries"`
		SignerKeyID   string            `json:"signer_key_id"`
		SignatureB64  string            `json:"signature"`
	}{arch, driver, vbios, entries, kid, base64.StdEncoding.EncodeToString(sig)}
	out, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

// =============================================================================
// ModeLocal happy paths
// =============================================================================

func TestNVTrustLocal_HappyPath_SPDM11(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	rep, err := v.verifier().Verify(context.Background(), v.evidence,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots),
		WithExpectedReportData(v.nonce[:]))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Kind != KindNVTrust || rep.Vendor != "nvidia.nvtrust.local" {
		t.Fatalf("kind/vendor = %q/%q", rep.Kind, rep.Vendor)
	}
	// ReportData is the SIGNED requester nonce.
	if !bytes.Equal(rep.ReportData, v.nonce[:]) {
		t.Fatalf("report_data = %x want %x", rep.ReportData, v.nonce[:])
	}
	// ChipID is the trusted leaf serial, NOT the envelope UUID.
	if !bytes.Equal(rep.ChipID, big.NewInt(testLeafSerial).Bytes()) {
		t.Fatalf("chip_id = %x want %x", rep.ChipID, big.NewInt(testLeafSerial).Bytes())
	}
	// Measurement equals the signed-RIM measurement root.
	parsed, err := nvidia.ParseAndVerifyRIM(v.rim, v.rimRoots)
	if err != nil {
		t.Fatalf("reparse rim: %v", err)
	}
	wantRoot := parsed.MeasurementRoot()
	if !bytes.Equal(rep.Measurement, wantRoot[:]) {
		t.Fatalf("measurement = %x want %x", rep.Measurement, wantRoot[:])
	}
	if rep.CompositeHash == [32]byte{} {
		t.Fatal("composite hash must not be zero")
	}
	if rep.Extra["nvtrust.mode"] != "local" {
		t.Fatalf("extra mode = %q", rep.Extra["nvtrust.mode"])
	}
	if rep.Extra["nvtrust.spdm_asym_algo"] != "ecdsa-p384-sha384" {
		t.Fatalf("extra algo = %q", rep.Extra["nvtrust.spdm_asym_algo"])
	}
}

func TestNVTrustLocal_HappyPath_SPDM12(t *testing.T) {
	v := buildLocalVector(t, 0x12)
	_, err := v.verifier().Verify(context.Background(), v.evidence,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if err != nil {
		t.Fatalf("verify 1.2: %v", err)
	}
}

// =============================================================================
// ModeLocal fail-closed / tamper rejection
// =============================================================================

// Dispatch uses the zero value (no pinned device root) -> must refuse.
func TestNVTrustLocal_Dispatch_FailClosed(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	_, err := Dispatch(context.Background(), KindNVTrust, v.evidence,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (no device root)", err)
	}
}

func TestNVTrustLocal_RejectsTamperedSPDMSignature(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	// Flip a byte inside the base64 spdm_response so the signature breaks.
	var env map[string]any
	if err := json.Unmarshal(v.evidence, &env); err != nil {
		t.Fatal(err)
	}
	resp, _ := base64.StdEncoding.DecodeString(env["spdm_response"].(string))
	resp[len(resp)-1] ^= 0xFF // last byte of the signature
	env["spdm_response"] = base64.StdEncoding.EncodeToString(resp)
	tampered, _ := json.Marshal(env)

	_, err := v.verifier().Verify(context.Background(), tampered,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestNVTrustLocal_RejectsTamperedMeasurementInSignedRecord(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	// Flip a measurement byte in the signed record (not the signature). The
	// SPDM signature no longer covers the record -> signature failure.
	var env map[string]any
	json.Unmarshal(v.evidence, &env)
	resp, _ := base64.StdEncoding.DecodeString(env["spdm_response"].(string))
	// The first measurement digest sits well inside the record; flipping any
	// record byte invalidates the signature.
	resp[12] ^= 0x01
	env["spdm_response"] = base64.StdEncoding.EncodeToString(resp)
	tampered, _ := json.Marshal(env)

	_, err := v.verifier().Verify(context.Background(), tampered,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestNVTrustLocal_RejectsWrongDeviceRoot(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	// A device-root pool that does NOT contain the chain's root.
	otherPriv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	otherTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Unrelated Root"},
		NotBefore:             v.now.Add(-time.Hour),
		NotAfter:              v.now.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	otherRoot := mkCert(t, otherTmpl, otherTmpl, otherPriv.Public(), otherPriv)
	pool := x509.NewCertPool()
	pool.AddCert(otherRoot)

	verifier := NewNVTrust(
		WithNVTrustDeviceRoots(pool),
		WithNVTrustClock(func() time.Time { return v.now }),
	)
	_, err := verifier.Verify(context.Background(), v.evidence,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

func TestNVTrustLocal_RejectsRIMMismatch(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	// A cryptographically valid RIM whose index-0 golden differs from the
	// signed measurement -> POLICY refusal (signed, but does not match).
	rimPub2, rimPriv2, _ := ed25519.GenerateKey(rand.Reader)
	roots2 := []nvidia.TrustRoot{{KeyID: "nvidia-rim-2", Public: rimPub2}}
	bad := []nvidia.RIMEntry{
		{Name: "FW_RT", ValueHex: hex.EncodeToString(bytes.Repeat([]byte{0xEE}, 48)), Index: u8ptr(0)},
		{Name: "VBIOS_RT", ValueHex: hex.EncodeToString(bytes.Repeat([]byte{0x22}, 48)), Index: u8ptr(1)},
	}
	badRIM := signRIMEd25519(t, rimPriv2, "nvidia-rim-2", testArch, testDriver, testVBIOS, bad)
	_, err := v.verifier().Verify(context.Background(), v.evidence,
		WithNVTrustRIM(badRIM), WithNVTrustTrustRoots(roots2))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestNVTrustLocal_RejectsTamperedRIMSignature(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	tampered := bytes.Replace(v.rim,
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0x11}, 48))),
		[]byte(hex.EncodeToString(bytes.Repeat([]byte{0x33}, 48))), 1)
	if bytes.Equal(tampered, v.rim) {
		t.Fatal("rim did not mutate")
	}
	_, err := v.verifier().Verify(context.Background(), v.evidence,
		WithNVTrustRIM(tampered), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

func TestNVTrustLocal_RejectsWrongExpectedNonce(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	wrong := make([]byte, 32)
	wrong[0] = 0xFF
	_, err := v.verifier().Verify(context.Background(), v.evidence,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots),
		WithExpectedReportData(wrong))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (nonce binding)", err)
	}
}

func TestNVTrustLocal_RejectsEnvelopeNonceMismatch(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	// Change the envelope nonce so it no longer equals the SIGNED request
	// nonce -> ErrPolicy (consistency).
	var env map[string]any
	json.Unmarshal(v.evidence, &env)
	other := make([]byte, 32)
	other[31] = 0x09
	env["nonce"] = hex.EncodeToString(other)
	tampered, _ := json.Marshal(env)
	_, err := v.verifier().Verify(context.Background(), tampered,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestNVTrustLocal_RejectsMissingSPDM(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	var env map[string]any
	json.Unmarshal(v.evidence, &env)
	delete(env, "spdm_response")
	delete(env, "attestation_quote")
	noSPDM, _ := json.Marshal(env)
	_, err := v.verifier().Verify(context.Background(), noSPDM,
		WithNVTrustRIM(v.rim), WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence", err)
	}
}

func TestNVTrustLocal_RefusesWithoutRIM(t *testing.T) {
	v := buildLocalVector(t, 0x11)
	_, err := v.verifier().Verify(context.Background(), v.evidence,
		WithNVTrustTrustRoots(v.rimRoots))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

// =============================================================================
// ModeNRAS: EAT/JWT verification
// =============================================================================

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// buildEATES256 builds an ES256-signed EAT compact JWS over the claims.
func buildEATES256(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr := map[string]string{"alg": "ES256", "kid": kid}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signedInput := b64url(hb) + "." + b64url(cb)
	sum := sha256Sum([]byte(signedInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
	if err != nil {
		t.Fatalf("eat sign: %v", err)
	}
	sig := joseConcatLocal(r, s, 32)
	return signedInput + "." + b64url(sig)
}

func nrasVerifier(t *testing.T, pub *ecdsa.PublicKey, kid string, now time.Time) NVTrust {
	return NewNVTrust(
		WithNVTrustMode(ModeNRAS),
		WithNVTrustNRASRoots([]nvidia.TrustRoot{{KeyID: kid, Public: pub}}),
		WithNVTrustClock(func() time.Time { return now }),
	)
}

func TestNVTrustNRAS_HappyPath(t *testing.T) {
	now := mustTime(t, testFixedNow)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	measRoot := bytes.Repeat([]byte{0x5A}, 32)
	token := buildEATES256(t, priv, "nras-1", map[string]any{
		"eat_nonce":                      hex.EncodeToString(nonce[:]),
		"exp":                            now.Add(time.Hour).Unix(),
		"iat":                            now.Add(-time.Minute).Unix(),
		"x-nvidia-overall-att-result":    true,
		"x-nvidia-gpu-measurements-root": hex.EncodeToString(measRoot),
	})
	rep, err := nrasVerifier(t, &priv.PublicKey, "nras-1", now).Verify(
		context.Background(), []byte(token), WithExpectedReportData(nonce[:]))
	if err != nil {
		t.Fatalf("nras verify: %v", err)
	}
	if rep.Vendor != "nvidia.nvtrust.nras" {
		t.Fatalf("vendor = %q", rep.Vendor)
	}
	if !bytes.Equal(rep.ReportData, nonce[:]) {
		t.Fatalf("report_data = %x want %x", rep.ReportData, nonce[:])
	}
	if !bytes.Equal(rep.Measurement, measRoot) {
		t.Fatalf("measurement = %x want %x", rep.Measurement, measRoot)
	}
	if rep.Extra["nvtrust.nras_result"] != "true" {
		t.Fatalf("nras_result = %q", rep.Extra["nvtrust.nras_result"])
	}
}

func TestNVTrustNRAS_RejectsBadSignature(t *testing.T) {
	now := mustTime(t, testFixedNow)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := buildEATES256(t, priv, "nras-1", map[string]any{
		"exp": now.Add(time.Hour).Unix(),
	})
	// Corrupt the final signature segment.
	bad := token[:len(token)-4] + "AAAA"
	_, err := nrasVerifier(t, &priv.PublicKey, "nras-1", now).Verify(
		context.Background(), []byte(bad))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

func TestNVTrustNRAS_RejectsExpired(t *testing.T) {
	now := mustTime(t, testFixedNow)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := buildEATES256(t, priv, "nras-1", map[string]any{
		"exp": now.Add(-time.Hour).Unix(),
	})
	_, err := nrasVerifier(t, &priv.PublicKey, "nras-1", now).Verify(
		context.Background(), []byte(token))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (expired)", err)
	}
}

func TestNVTrustNRAS_RejectsNonceMismatch(t *testing.T) {
	now := mustTime(t, testFixedNow)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var nonce [32]byte
	nonce[0] = 0x01
	token := buildEATES256(t, priv, "nras-1", map[string]any{
		"eat_nonce": hex.EncodeToString(nonce[:]),
		"exp":       now.Add(time.Hour).Unix(),
	})
	wrong := make([]byte, 32)
	wrong[0] = 0x02
	_, err := nrasVerifier(t, &priv.PublicKey, "nras-1", now).Verify(
		context.Background(), []byte(token), WithExpectedReportData(wrong))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (nonce)", err)
	}
}

func TestNVTrustNRAS_RejectsNegativeResult(t *testing.T) {
	now := mustTime(t, testFixedNow)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token := buildEATES256(t, priv, "nras-1", map[string]any{
		"exp":                         now.Add(time.Hour).Unix(),
		"x-nvidia-overall-att-result": false,
	})
	_, err := nrasVerifier(t, &priv.PublicKey, "nras-1", now).Verify(
		context.Background(), []byte(token))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (negative result)", err)
	}
}

func TestNVTrustNRAS_RefusesWithoutTrust(t *testing.T) {
	now := mustTime(t, testFixedNow)
	v := NewNVTrust(WithNVTrustMode(ModeNRAS), WithNVTrustClock(func() time.Time { return now }))
	_, err := v.Verify(context.Background(), []byte("x.y.z"))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (no NRAS trust)", err)
	}
}
