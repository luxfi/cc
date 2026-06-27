// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/luxfi/cc/attest/nvidia"
)

// nvTrustFixture builds a matched (GPU report, signed RIM, trust roots)
// triple. The RIM is signed with a fresh ed25519 key; the report's
// measurements equal the RIM golden values so RIM.Match passes. Callers
// mutate the returned bytes to drive negative cases.
func nvTrustFixture(t *testing.T) (report, rim []byte, roots []nvidia.TrustRoot, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	roots = []nvidia.TrustRoot{{KeyID: "nvidia-rim-1", Public: pub}}
	entries := []nvidia.RIMEntry{
		{Name: "FW_RUNTIME", ValueHex: "deadbeef00112233"},
		{Name: "VBIOS_RT", ValueHex: "cafebabe44556677"},
	}
	rim = signRIMEd25519(t, priv, "nvidia-rim-1", "Hopper", "535.104.05", "96.00.74.00.01", entries)
	report = []byte(`{
  "evidence_version": "2.1",
  "gpu_uuid": "GPU-1234-5678",
  "architecture": "Hopper",
  "driver_version": "535.104.05",
  "vbios_version": "96.00.74.00.01",
  "nonce": "` + hex.EncodeToString(make([]byte, 32)) + `",
  "measurements": [
    {"pcr_index": 0, "name": "FW_RUNTIME", "value": "deadbeef00112233"},
    {"pcr_index": 1, "name": "VBIOS_RT",   "value": "cafebabe44556677"}
  ],
  "attestation_quote": "AAAA",
  "nvswitch_present": false
}`)
	return report, rim, roots, pub, priv
}

// signRIMEd25519 reproduces the nvidia RIM wire format: the signature is
// over json.Marshal of the body (architecture, driver_version,
// vbios_version, entries — in that field order, matching the package's
// canonicalization), and the signed blob appends signer_key_id + signature.
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

func TestNVTrust_LocalRIM_HappyPath(t *testing.T) {
	report, rim, roots, _, _ := nvTrustFixture(t)

	rep, err := Dispatch(context.Background(), KindNVTrust, report,
		WithNVTrustRIM(rim), WithNVTrustTrustRoots(roots))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Kind != KindNVTrust {
		t.Fatalf("kind = %q, want %q", rep.Kind, KindNVTrust)
	}
	if rep.Vendor != "nvidia.nvtrust" {
		t.Fatalf("vendor = %q", rep.Vendor)
	}
	if string(rep.ChipID) != "GPU-1234-5678" {
		t.Fatalf("chip_id = %q", string(rep.ChipID))
	}
	// ReportData is the 32-byte nonce (all zero in the fixture).
	if len(rep.ReportData) != 32 || !bytes.Equal(rep.ReportData, make([]byte, 32)) {
		t.Fatalf("report_data = %x", rep.ReportData)
	}
	// Measurement is the signed RIM measurement root.
	parsedRIM, err := nvidia.ParseAndVerifyRIM(rim, roots)
	if err != nil {
		t.Fatalf("re-parse rim: %v", err)
	}
	wantRoot := parsedRIM.MeasurementRoot()
	if !bytes.Equal(rep.Measurement, wantRoot[:]) {
		t.Fatalf("measurement = %x, want %x", rep.Measurement, wantRoot[:])
	}
	if rep.CompositeHash == [32]byte{} {
		t.Fatal("composite hash must not be zero")
	}
	if rep.Extra["nvtrust.driver_version"] != "535.104.05" {
		t.Fatalf("extra driver = %q", rep.Extra["nvtrust.driver_version"])
	}
	if rep.Extra["nvtrust.rim_signer"] != "nvidia-rim-1" {
		t.Fatalf("extra rim_signer = %q", rep.Extra["nvtrust.rim_signer"])
	}
}

func TestNVTrust_RefusesWithoutRIM(t *testing.T) {
	report, _, roots, _, _ := nvTrustFixture(t)
	_, err := Dispatch(context.Background(), KindNVTrust, report,
		WithNVTrustTrustRoots(roots))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (no insecure mode)", err)
	}
}

func TestNVTrust_RefusesWithoutTrustRoots(t *testing.T) {
	report, rim, _, _, _ := nvTrustFixture(t)
	_, err := Dispatch(context.Background(), KindNVTrust, report,
		WithNVTrustRIM(rim))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (no insecure mode)", err)
	}
}

func TestNVTrust_RejectsTamperedRIMSignature(t *testing.T) {
	report, rim, roots, _, _ := nvTrustFixture(t)
	// Flip a measurement value byte in the RIM body — the ed25519
	// signature no longer covers the manifest. Must be a CHAIN failure
	// (the golden values are not vendor-authentic), not silently accepted.
	tampered := bytes.Replace(rim, []byte("deadbeef00112233"), []byte("deadbeef00112234"), 1)
	if bytes.Equal(tampered, rim) {
		t.Fatal("fixture did not mutate")
	}
	_, err := Dispatch(context.Background(), KindNVTrust, report,
		WithNVTrustRIM(tampered), WithNVTrustTrustRoots(roots))
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid", err)
	}
}

func TestNVTrust_RejectsMeasurementMismatch(t *testing.T) {
	report, _, roots, _, priv := nvTrustFixture(t)
	// A cryptographically VALID RIM whose golden value differs from what
	// the GPU reports — must be a POLICY refusal (signed, but the GPU's
	// actual measurement is not covered).
	badEntries := []nvidia.RIMEntry{
		{Name: "FW_RUNTIME", ValueHex: "0000000000000000"},
		{Name: "VBIOS_RT", ValueHex: "cafebabe44556677"},
	}
	badRIM := signRIMEd25519(t, priv, "nvidia-rim-1", "Hopper", "535.104.05", "96.00.74.00.01", badEntries)
	_, err := Dispatch(context.Background(), KindNVTrust, report,
		WithNVTrustRIM(badRIM), WithNVTrustTrustRoots(roots))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestNVTrust_RejectsBadEvidence(t *testing.T) {
	_, rim, roots, _, _ := nvTrustFixture(t)
	_, err := Dispatch(context.Background(), KindNVTrust, []byte("{not json"),
		WithNVTrustRIM(rim), WithNVTrustTrustRoots(roots))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence", err)
	}
}

func TestNVTrust_EnforcesExpectedNonce(t *testing.T) {
	report, rim, roots, _, _ := nvTrustFixture(t)
	wrongNonce := make([]byte, 32)
	wrongNonce[0] = 0xFF
	_, err := Dispatch(context.Background(), KindNVTrust, report,
		WithNVTrustRIM(rim), WithNVTrustTrustRoots(roots),
		WithExpectedReportData(wrongNonce))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy (nonce binding)", err)
	}
}
