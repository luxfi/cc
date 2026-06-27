//go:build hwattest

// Real-hardware attestation tests. Build with `-tags hwattest` on a
// host with a Hopper (H100) or Blackwell (B100/B200) GPU plus the
// NVIDIA confidential-compute stack. The default build excludes this
// file so CI does not fault on hardware that is not present.
//
// Set environment:
//
//	NRAS_ENDPOINT       — full URL to NRAS (default: production NRAS)
//	NRAS_TRUST_ROOT_PEM — path to a PEM file containing the NRAS
//	                      signing public key
//	GPU_REPORT_PATH     — path to a JSON evidence report produced by
//	                      the local nvidia-cc-host binary
//	RIM_PATH            — path to a signed RIM JSON for this driver
//	                      and VBIOS combination
//	RIM_TRUST_ROOT_PEM  — path to a PEM file containing the RIM
//	                      signing public key (may equal NRAS root)
//
// All tests skip when their inputs are missing — running with the
// build tag on a host that lacks a configured GPU is harmless.

package nvidia

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func loadPubKeyPEM(t *testing.T, path string) interface{} {
	t.Helper()
	if path == "" {
		t.Skipf("PEM path not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PEM %s: %v", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse PKIX %s: %v", path, err)
	}
	return pub
}

func TestHardware_ParseLocalGPUReport(t *testing.T) {
	path := os.Getenv("GPU_REPORT_PATH")
	if path == "" {
		t.Skip("GPU_REPORT_PATH not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	rep, err := ParseGPUReport(raw)
	if err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	if rep.Architecture != "Hopper" && rep.Architecture != "Blackwell" {
		t.Fatalf("unexpected arch: %q", rep.Architecture)
	}
	t.Logf("parsed report: arch=%s driver=%s vbios=%s",
		rep.Architecture, rep.DriverVersion, rep.VBIOSVersion)
}

func TestHardware_VerifyAgainstRealNRAS(t *testing.T) {
	endpoint := os.Getenv("NRAS_ENDPOINT")
	if endpoint == "" {
		t.Skip("NRAS_ENDPOINT not set")
	}
	reportPath := os.Getenv("GPU_REPORT_PATH")
	if reportPath == "" {
		t.Skip("GPU_REPORT_PATH not set")
	}
	rootPath := os.Getenv("NRAS_TRUST_ROOT_PEM")
	if rootPath == "" {
		t.Skip("NRAS_TRUST_ROOT_PEM not set")
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read evidence: %v", err)
	}
	rep, err := ParseGPUReport(raw)
	if err != nil {
		t.Fatalf("parse evidence: %v", err)
	}
	pub := loadPubKeyPEM(t, rootPath)

	c := NewNRASClient(endpoint, []TrustRoot{{KeyID: "nras", Public: pub}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Verify(ctx, raw, rep.Nonce, VerifyOptions{})
	if err != nil {
		t.Fatalf("nras verify: %v", err)
	}
	if res.Token == "" {
		t.Fatal("empty token")
	}
}

func TestHardware_RIMMatchAgainstReport(t *testing.T) {
	reportPath := os.Getenv("GPU_REPORT_PATH")
	rimPath := os.Getenv("RIM_PATH")
	rimRoot := os.Getenv("RIM_TRUST_ROOT_PEM")
	if reportPath == "" || rimPath == "" || rimRoot == "" {
		t.Skip("GPU_REPORT_PATH / RIM_PATH / RIM_TRUST_ROOT_PEM not all set")
	}
	rep, err := readReport(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	rimRaw, err := os.ReadFile(rimPath)
	if err != nil {
		t.Fatalf("read rim: %v", err)
	}
	pub := loadPubKeyPEM(t, rimRoot)
	rim, err := ParseAndVerifyRIM(rimRaw, []TrustRoot{{KeyID: "rim", Public: pub}})
	if err != nil {
		t.Fatalf("rim parse+verify: %v", err)
	}
	if err := rim.Match(rep); err != nil {
		t.Fatalf("rim match: %v", err)
	}
}

func readReport(path string) (*GPUReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGPUReport(raw)
}
