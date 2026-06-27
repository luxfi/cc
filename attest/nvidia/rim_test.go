package nvidia

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

// makeManifest produces a signed RIM manifest for the supplied entries
// using the provided ed25519 key.
func makeManifestEd25519(t *testing.T, priv ed25519.PrivateKey, kid string, entries []RIMEntry) []byte {
	t.Helper()
	body := rawRIM{
		Architecture:  "Hopper",
		DriverVersion: "535.104.05",
		VBIOSVersion:  "96.00.74.00.01",
		Entries:       entries,
	}
	canon, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := ed25519.Sign(priv, canon)
	body.SignerKeyID = kid
	body.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

func TestParseAndVerifyRIM_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	roots := []TrustRoot{{KeyID: "nvidia-rim-1", Public: pub}}
	entries := []RIMEntry{
		{Name: "FW_RUNTIME", ValueHex: "deadbeef"},
		{Name: "VBIOS_RT", ValueHex: "cafebabe"},
	}
	blob := makeManifestEd25519(t, priv, "nvidia-rim-1", entries)
	r, err := ParseAndVerifyRIM(blob, roots)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.SignerKeyID != "nvidia-rim-1" {
		t.Fatalf("signer: %s", r.SignerKeyID)
	}
}

func TestParseAndVerifyRIM_RejectsTamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	roots := []TrustRoot{{KeyID: "k", Public: pub}}
	entries := []RIMEntry{{Name: "X", ValueHex: "00"}}
	blob := makeManifestEd25519(t, priv, "k", entries)

	// Flip a byte in the manifest entries — signature must reject.
	tampered := append([]byte{}, blob...)
	for i := range tampered {
		if tampered[i] == 'X' {
			tampered[i] = 'Y'
			break
		}
	}
	if _, err := ParseAndVerifyRIM(tampered, roots); !errors.Is(err, ErrRIMBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestParseAndVerifyRIM_RejectsUnknownSigner(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	roots := []TrustRoot{{KeyID: "OTHER", Public: pub}}
	blob := makeManifestEd25519(t, priv, "k", []RIMEntry{{Name: "X", ValueHex: "00"}})
	if _, err := ParseAndVerifyRIM(blob, roots); !errors.Is(err, ErrRIMBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestParseAndVerifyRIM_RejectsEmpty(t *testing.T) {
	if _, err := ParseAndVerifyRIM(nil, []TrustRoot{{KeyID: "k"}}); !errors.Is(err, ErrRIMEmpty) {
		t.Fatalf("got %v", err)
	}
}

func TestParseAndVerifyRIM_RejectsNoTrustRoots(t *testing.T) {
	if _, err := ParseAndVerifyRIM([]byte("{}"), nil); !errors.Is(err, ErrRIMNoTrustRoots) {
		t.Fatalf("got %v", err)
	}
}

func TestParseAndVerifyRIM_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	roots := []TrustRoot{{KeyID: "ecdsa-1", Public: &priv.PublicKey}}

	body := rawRIM{
		Architecture:  "Hopper",
		DriverVersion: "535.104.05",
		VBIOSVersion:  "96.00.74.00.01",
		Entries:       []RIMEntry{{Name: "FW", ValueHex: "01"}},
	}
	canon, _ := json.Marshal(body)
	digest := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body.SignerKeyID = "ecdsa-1"
	body.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	blob, _ := json.Marshal(body)

	if _, err := ParseAndVerifyRIM(blob, roots); err != nil {
		t.Fatalf("ecdsa verify: %v", err)
	}
}

func TestParseAndVerifyRIM_RSAPSS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	roots := []TrustRoot{{KeyID: "rsa-1", Public: &priv.PublicKey}}

	body := rawRIM{
		Architecture: "Hopper", DriverVersion: "535.104.05",
		VBIOSVersion: "96", Entries: []RIMEntry{{Name: "FW", ValueHex: "01"}},
	}
	canon, _ := json.Marshal(body)
	digest := sha256.Sum256(canon)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body.SignerKeyID = "rsa-1"
	body.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	blob, _ := json.Marshal(body)

	if _, err := ParseAndVerifyRIM(blob, roots); err != nil {
		t.Fatalf("rsa verify: %v", err)
	}
}

func TestRIM_Match_HappyPath(t *testing.T) {
	rim := &RIM{
		Architecture:  "Hopper",
		DriverVersion: "535.104.05",
		VBIOSVersion:  "96.00.74.00.01",
		Entries: []RIMEntry{
			{Name: "FW_RUNTIME", ValueHex: "deadbeef00112233"},
			{Name: "VBIOS_RT", ValueHex: "cafebabe44556677"},
		},
	}
	report, err := ParseGPUReport(goodReportJSON())
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if err := rim.Match(report); err != nil {
		t.Fatalf("match: %v", err)
	}
}

func TestRIM_Match_RejectsArchMismatch(t *testing.T) {
	rim := &RIM{Architecture: "Blackwell", DriverVersion: "535.104.05", VBIOSVersion: "96.00.74.00.01"}
	report, _ := ParseGPUReport(goodReportJSON())
	if err := rim.Match(report); !errors.Is(err, ErrRIMArchMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestRIM_Match_RejectsVersionMismatch(t *testing.T) {
	rim := &RIM{Architecture: "Hopper", DriverVersion: "OTHER", VBIOSVersion: "OTHER"}
	report, _ := ParseGPUReport(goodReportJSON())
	if err := rim.Match(report); !errors.Is(err, ErrRIMVersionMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestRIM_Match_RejectsMissingMeasurement(t *testing.T) {
	rim := &RIM{
		Architecture:  "Hopper",
		DriverVersion: "535.104.05",
		VBIOSVersion:  "96.00.74.00.01",
		Entries: []RIMEntry{
			{Name: "OTHER", ValueHex: "00"},
		},
	}
	report, _ := ParseGPUReport(goodReportJSON())
	if err := rim.Match(report); !errors.Is(err, ErrRIMMissingEntry) {
		t.Fatalf("got %v", err)
	}
}

func TestRIM_Match_RejectsValueMismatch(t *testing.T) {
	rim := &RIM{
		Architecture:  "Hopper",
		DriverVersion: "535.104.05",
		VBIOSVersion:  "96.00.74.00.01",
		Entries: []RIMEntry{
			{Name: "FW_RUNTIME", ValueHex: "00"},
			{Name: "VBIOS_RT", ValueHex: "cafebabe44556677"},
		},
	}
	report, _ := ParseGPUReport(goodReportJSON())
	if err := rim.Match(report); !errors.Is(err, ErrRIMValueMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestRIM_MeasurementRoot_Deterministic(t *testing.T) {
	a := &RIM{Entries: []RIMEntry{{Name: "B", ValueHex: "02"}, {Name: "A", ValueHex: "01"}}}
	b := &RIM{Entries: []RIMEntry{{Name: "A", ValueHex: "01"}, {Name: "B", ValueHex: "02"}}}
	if a.MeasurementRoot() != b.MeasurementRoot() {
		t.Fatal("root differs across orderings")
	}
}
