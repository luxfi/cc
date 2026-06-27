// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"testing"
	"time"

	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
)

// sevSnpAttestationMilan is a real AMD Milan SEV-SNP attestation report
// (0x4A0 bytes) captured via the SNP_GUEST_REQUEST ioctl. Sourced from
// the upstream go-sev-guest test corpus and committed verbatim so this
// package's tests do not require live hardware or network access.
//
//go:embed testdata/sev_snp_attestation_milan.bin
var sevSnpAttestationMilan []byte

// sevSnpVcekMilan is the VCEK leaf certificate that signed the report
// above, as issued by the AMD KDS for the matching CHIP_ID + TCB.
//
//go:embed testdata/sev_snp_vcek_milan.cer
var sevSnpVcekMilan []byte

// kdsResponses is the pre-fetched KDS replay map. The keys are the exact
// URLs go-sev-guest hits when verifying this report; the values are the
// committed bytes. Tests inject this via WithKDSGetter so verification
// runs offline.
//
// The product CA bundle URL is the one the lib resolves for Milan
// (encoded into the Milan product chain), and the VCEK URL is computed
// from the report's CHIP_ID + reported TCB.
func newKDSReplay() trust.HTTPSGetter {
	return test.SimpleGetter(map[string][]byte{
		"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": trust.AskArkMilanVcekBytes,
		"https://kdsintf.amd.com/vcek/v1/Milan/3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68": sevSnpVcekMilan,
	})
}

// fixedNow pins the verification clock inside the validity window of
// the committed VCEK so tests are reproducible regardless of when CI
// runs. The committed VCEK is valid roughly 2023–2030; we pick a date
// safely inside that window.
func fixedNow() time.Time {
	return time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
}

// -----------------------------------------------------------------------------
// SEV-SNP — production path against committed real-vendor fixtures
// -----------------------------------------------------------------------------

func TestSEVSNP_Verify_HappyPath(t *testing.T) {
	// Reset the package-level cert cache so prior tests don't leak.
	trust.ClearProductCertCache()

	rep, err := SEVSNP{}.Verify(
		context.Background(),
		sevSnpAttestationMilan,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep == nil {
		t.Fatal("verify returned nil report")
	}
	if rep.Kind != KindSEVSNP {
		t.Errorf("kind = %q, want %q", rep.Kind, KindSEVSNP)
	}
	if rep.Vendor != "amd.sev.snp" {
		t.Errorf("vendor = %q, want amd.sev.snp", rep.Vendor)
	}
	if len(rep.Measurement) != 48 {
		t.Errorf("measurement length = %d, want 48", len(rep.Measurement))
	}
	if len(rep.ReportData) != 64 {
		t.Errorf("report_data length = %d, want 64", len(rep.ReportData))
	}
	if len(rep.ChipID) != 64 {
		t.Errorf("chip_id length = %d, want 64", len(rep.ChipID))
	}
	if rep.IssuedAt.IsZero() {
		t.Error("issued_at not set")
	}
	if rep.CompositeHash == ([32]byte{}) {
		t.Error("composite hash is zero")
	}
	// Extra fields must include the canonical SEV identifiers.
	for _, key := range []string{"sev_snp.policy", "sev_snp.vmpl", "sev_snp.current_tcb"} {
		if _, ok := rep.Extra[key]; !ok {
			t.Errorf("missing extra key %q", key)
		}
	}
}

func TestSEVSNP_Verify_DispatchRoutesToSEV(t *testing.T) {
	trust.ClearProductCertCache()

	rep, err := Dispatch(
		context.Background(),
		KindSEVSNP,
		sevSnpAttestationMilan,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
	)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if rep.Kind != KindSEVSNP {
		t.Errorf("kind = %q, want %q", rep.Kind, KindSEVSNP)
	}
}

func TestSEVSNP_Verify_RejectsWrongLength(t *testing.T) {
	_, err := SEVSNP{}.Verify(
		context.Background(),
		[]byte("too short"),
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
	)
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence", err)
	}
}

func TestSEVSNP_Verify_RejectsTamperedSignature(t *testing.T) {
	trust.ClearProductCertCache()

	tampered := append([]byte(nil), sevSnpAttestationMilan...)
	// Flip a bit inside the ECDSA signature R-component (0x2A0 is the
	// start of the signature region; offset +0x10 lands inside R, not
	// in the MBZ tail at 0x330+). Any flip here makes the signature
	// check fail without tripping the parser's MBZ guard.
	tampered[0x2A0+0x10] ^= 0x01

	_, err := SEVSNP{}.Verify(
		context.Background(),
		tampered,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
	)
	if err == nil {
		t.Fatal("expected error on tampered signature, got nil")
	}
	// Tampering inside the signature region must be classified as a
	// signature failure or a chain failure (either is a refusal). We
	// also accept ErrInvalidEvidence in case go-sev-guest's parser
	// catches the corruption first — what matters is the verifier
	// refuses and never returns a *VerifiedReport.
	if !errors.Is(err, ErrSignatureInvalid) &&
		!errors.Is(err, ErrChainInvalid) &&
		!errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("err = %v, want one of ErrSignatureInvalid|ErrChainInvalid|ErrInvalidEvidence", err)
	}
}

func TestSEVSNP_Verify_RejectsWrongReportData(t *testing.T) {
	trust.ClearProductCertCache()

	wrong := bytes.Repeat([]byte{0xFF}, 64)
	_, err := SEVSNP{}.Verify(
		context.Background(),
		sevSnpAttestationMilan,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
		WithExpectedReportData(wrong),
	)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestSEVSNP_Verify_RejectsWrongMeasurement(t *testing.T) {
	trust.ClearProductCertCache()

	wrong := bytes.Repeat([]byte{0xAB}, 48)
	_, err := SEVSNP{}.Verify(
		context.Background(),
		sevSnpAttestationMilan,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
		WithExpectedMeasurement(wrong),
	)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestSEVSNP_Verify_DeterministicCompositeHash(t *testing.T) {
	trust.ClearProductCertCache()

	rep1, err := SEVSNP{}.Verify(
		context.Background(),
		sevSnpAttestationMilan,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
	)
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}
	trust.ClearProductCertCache()
	rep2, err := SEVSNP{}.Verify(
		context.Background(),
		sevSnpAttestationMilan,
		WithKDSGetter(newKDSReplay()),
		WithNow(fixedNow()),
	)
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if rep1.CompositeHash != rep2.CompositeHash {
		t.Errorf("composite hash not deterministic: %x vs %x",
			rep1.CompositeHash, rep2.CompositeHash)
	}
}

// -----------------------------------------------------------------------------
// Dispatch errors
// -----------------------------------------------------------------------------

func TestDispatch_RejectsUnknownKind(t *testing.T) {
	_, err := Dispatch(context.Background(), Kind("madeup"), []byte{0x00})
	if !errors.Is(err, ErrUnsupportedKind) {
		t.Fatalf("err = %v, want ErrUnsupportedKind", err)
	}
}

// TestStubsReturnNotImplemented confirms the TDX stub FAILS LOUD —
// returning ErrNotImplemented (a hard refusal callers must not paper
// over) rather than silently returning a nil error. This guards against
// an accidental future change that silently accepts evidence the
// verifier hasn't actually checked, while keeping the failure
// recoverable so request-handling goroutines do not crash the whole
// process. The NVIDIA path is no longer a stub — see nvtrust_test.go.
// When stage 2 of #222 lands, replace this test with a real TDX case.
func TestStubsReturnNotImplemented(t *testing.T) {
	cases := []struct {
		name string
		v    Verifier
	}{
		{"tdx", TDX{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s.Verify panicked (must error-return instead): %v", c.name, r)
				}
			}()
			rep, err := c.v.Verify(context.Background(), []byte{0x00})
			if rep != nil {
				t.Fatalf("%s.Verify returned non-nil report: %+v", c.name, rep)
			}
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("%s.Verify returned %v, want ErrNotImplemented", c.name, err)
			}
		})
	}
}

// TestDispatch_StubKindsReturnNotImplemented covers the Dispatch path
// for the stub kinds: the entry point must surface ErrNotImplemented
// instead of crashing.
func TestDispatch_StubKindsReturnNotImplemented(t *testing.T) {
	for _, kind := range []Kind{KindTDX} {
		t.Run(string(kind), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Dispatch(%s) panicked: %v", kind, r)
				}
			}()
			rep, err := Dispatch(context.Background(), kind, []byte{0x00})
			if rep != nil {
				t.Fatalf("Dispatch(%s) returned non-nil report: %+v", kind, rep)
			}
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("Dispatch(%s) returned %v, want ErrNotImplemented", kind, err)
			}
		})
	}
}
