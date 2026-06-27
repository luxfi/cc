package nvidia

import (
	"encoding/hex"
	"errors"
	"testing"
)

func goodReportJSON() []byte {
	return []byte(`{
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
  "cert_chain": ["-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"],
  "attestation_quote": "AAAA",
  "nvswitch_present": false
}`)
}

func TestParseGPUReport_HappyPath(t *testing.T) {
	r, err := ParseGPUReport(goodReportJSON())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.UUID != "GPU-1234-5678" {
		t.Fatalf("uuid: %s", r.UUID)
	}
	if r.Architecture != "Hopper" {
		t.Fatalf("arch: %s", r.Architecture)
	}
	if len(r.Measurements) != 2 {
		t.Fatalf("measurements: %d", len(r.Measurements))
	}
	if r.Measurements[0].Name != "FW_RUNTIME" {
		t.Fatalf("name: %s", r.Measurements[0].Name)
	}
	if hex.EncodeToString(r.Measurements[0].Value) != "deadbeef00112233" {
		t.Fatalf("value decode: %x", r.Measurements[0].Value)
	}
}

func TestParseGPUReport_RejectsEmpty(t *testing.T) {
	if _, err := ParseGPUReport(nil); !errors.Is(err, ErrReportEmpty) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsBadJSON(t *testing.T) {
	if _, err := ParseGPUReport([]byte("{not json")); !errors.Is(err, ErrReportBadJSON) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsBadVersion(t *testing.T) {
	in := []byte(`{"evidence_version":"0.9","gpu_uuid":"x","architecture":"Hopper","nonce":"` + hex.EncodeToString(make([]byte, 32)) + `","measurements":[{"name":"a","value":"00"}]}`)
	if _, err := ParseGPUReport(in); !errors.Is(err, ErrReportBadVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsUnknownArch(t *testing.T) {
	in := []byte(`{"evidence_version":"2.1","gpu_uuid":"x","architecture":"Pascal","nonce":"` + hex.EncodeToString(make([]byte, 32)) + `","measurements":[{"name":"a","value":"00"}]}`)
	if _, err := ParseGPUReport(in); !errors.Is(err, ErrReportUnknownArch) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsMissingNonce(t *testing.T) {
	in := []byte(`{"evidence_version":"2.1","gpu_uuid":"x","architecture":"Hopper","measurements":[{"name":"a","value":"00"}]}`)
	if _, err := ParseGPUReport(in); !errors.Is(err, ErrReportMissingNonce) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsBadNonce(t *testing.T) {
	in := []byte(`{"evidence_version":"2.1","gpu_uuid":"x","architecture":"Hopper","nonce":"deadbeef","measurements":[{"name":"a","value":"00"}]}`)
	if _, err := ParseGPUReport(in); !errors.Is(err, ErrReportBadNonce) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsNoMeasurements(t *testing.T) {
	in := []byte(`{"evidence_version":"2.1","gpu_uuid":"x","architecture":"Hopper","nonce":"` + hex.EncodeToString(make([]byte, 32)) + `","measurements":[]}`)
	if _, err := ParseGPUReport(in); !errors.Is(err, ErrReportNoMeasurements) {
		t.Fatalf("got %v", err)
	}
}

func TestParseGPUReport_RejectsBadMeasurementHex(t *testing.T) {
	in := []byte(`{"evidence_version":"2.1","gpu_uuid":"x","architecture":"Hopper","nonce":"` + hex.EncodeToString(make([]byte, 32)) + `","measurements":[{"name":"a","value":"GG"}]}`)
	if _, err := ParseGPUReport(in); err == nil {
		t.Fatal("expected error on bad hex")
	}
}

func TestMeasurementMap(t *testing.T) {
	r, err := ParseGPUReport(goodReportJSON())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := r.MeasurementMap()
	if len(m) != 2 {
		t.Fatalf("map size %d", len(m))
	}
	if _, ok := m["FW_RUNTIME"]; !ok {
		t.Fatal("missing FW_RUNTIME")
	}
}
