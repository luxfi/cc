// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
)

// KindSEVSNP is the AMD SEV-SNP raw attestation report framing: a 0x4A0-byte
// ABI report carrying no certificate chain (the VCEK leaf is fetched from the
// AMD KDS at verify time).
const KindSEVSNP Kind = "sev_snp"

// SEVSNP is the production SEV-SNP verifier. It accepts a raw 0x4A0-byte
// AMD SEV-SNP attestation report (no embedded cert chain) and:
//
//  1. Parses the report via go-sev-guest/abi.ReportToProto.
//  2. Fetches the VCEK leaf from the AMD KDS at
//     kdsintf.amd.com/vcek/v1/<product>/<hwid>?... using the report's
//     CHIP_ID + reported TCB. The product CA bundle (ARK→ASK) is
//     embedded in go-sev-guest/verify/trust.
//  3. Validates the chain to AMD's pinned root and checks the report
//     signature against the VCEK public key.
//  4. Extracts MEASUREMENT, REPORT_DATA, HOST_DATA, CHIP_ID, TCB.
//  5. Enforces caller-supplied policy options (expected report data,
//     expected measurement).
//
// Production path requires network reachability to kdsintf.amd.com. In
// tests the WithKDSGetter option installs a SimpleGetter that replays
// pre-fetched bytes from testdata/.
type SEVSNP struct{}

// Verify implements Verifier for SEV-SNP raw reports.
func (SEVSNP) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	if len(evidence) != abi.ReportSize {
		return nil, fmt.Errorf("%w: sev-snp expects %d bytes, got %d",
			ErrInvalidEvidence, abi.ReportSize, len(evidence))
	}

	cfg := applyOptions(opts...)

	// Parse first so we fail fast on malformed framing.
	report, err := abi.ReportToProto(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// Build verify.Options. We rely on the embedded ARK/ASK trusted
	// roots inside go-sev-guest; the only thing we override is the
	// HTTPS getter (so tests can replay KDS responses) and Now.
	vopts := &verify.Options{}
	if cfg.kdsGetter != nil {
		g, ok := cfg.kdsGetter.(trust.HTTPSGetter)
		if !ok {
			return nil, fmt.Errorf("%w: kds getter does not implement trust.HTTPSGetter",
				ErrInvalidEvidence)
		}
		vopts.Getter = g
	} else {
		vopts.Getter = trust.DefaultHTTPSGetter()
	}
	if !cfg.now.IsZero() {
		vopts.Now = cfg.now
	} else {
		vopts.Now = time.Now()
	}

	// Chain + signature verify. This:
	//   - fetches VCEK from KDS by CHIP_ID + TCB
	//   - validates ARK→ASK→VCEK
	//   - validates VCEK extensions match the report's TCB
	//   - validates the report signature against VCEK
	if err := verify.RawSnpReportContext(ctx, evidence, vopts); err != nil {
		// go-sev-guest reports a single error string. Classify by
		// substring so callers can distinguish chain vs signature
		// failures via errors.Is. This is conservative — when in
		// doubt, treat as ChainInvalid (refuse).
		msg := err.Error()
		switch {
		case strings.Contains(msg, "could not interpret report bytes"):
			return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
		case strings.Contains(msg, "signature"):
			return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
		default:
			return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
		}
	}

	// Apply caller policy on the verified report fields.
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, report.GetReportData()) != 1 {
			return nil, fmt.Errorf("%w: report_data mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(report.GetReportData()))
		}
	}
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, report.GetMeasurement()) != 1 {
			return nil, fmt.Errorf("%w: measurement mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(report.GetMeasurement()))
		}
	}

	out := &VerifiedReport{
		Kind:        KindSEVSNP,
		Vendor:      "amd.sev.snp",
		Measurement: cloneBytes(report.GetMeasurement()),
		ReportData:  cloneBytes(report.GetReportData()),
		HostData:    cloneBytes(report.GetHostData()),
		ChipID:      cloneBytes(report.GetChipId()),
		IssuedAt:    vopts.Now.UTC(),
		Extra:       buildSEVExtra(report),
	}
	// CompositeHash binds verifier kind + the canonical fields the
	// chain validated. Re-deriving on the consumer side reproduces the
	// same hash iff the same evidence was verified by an honest
	// verifier with the same policy.
	out.CompositeHash = computeCompositeHash(KindSEVSNP, canonicalSEVBytes(report))
	return out, nil
}

// buildSEVExtra collects sev-snp-specific fields that don't fit the
// common shape. Keys are stable wire identifiers; values are hex.
func buildSEVExtra(report *spb.Report) map[string]string {
	extra := make(map[string]string, 6)
	extra["sev_snp.policy"] = fmt.Sprintf("%#x", report.GetPolicy())
	extra["sev_snp.vmpl"] = fmt.Sprintf("%d", report.GetVmpl())
	extra["sev_snp.current_tcb"] = fmt.Sprintf("%#x", report.GetCurrentTcb())
	extra["sev_snp.committed_tcb"] = fmt.Sprintf("%#x", report.GetCommittedTcb())
	extra["sev_snp.platform_info"] = fmt.Sprintf("%#x", report.GetPlatformInfo())
	if id := report.GetFamilyId(); len(id) > 0 {
		extra["sev_snp.family_id"] = hex.EncodeToString(id)
	}
	if id := report.GetImageId(); len(id) > 0 {
		extra["sev_snp.image_id"] = hex.EncodeToString(id)
	}
	return extra
}

// canonicalSEVBytes returns the bytes that participate in CompositeHash.
// We hash the verifier-extracted fields (not the raw report) so that any
// pre-verify field shuffling at lower layers cannot change the root
// without changing what the verifier saw. Field order is fixed and
// matches the public ABI ordering of the report.
func canonicalSEVBytes(report *spb.Report) []byte {
	// Length: 8(policy) + 8(current_tcb) + 8(committed_tcb)
	//       + 16(family) + 16(image) + 32(host) + 48(meas)
	//       + 64(report_data) + 64(chip_id) = 264 bytes max.
	buf := make([]byte, 0, 264)
	appendU64 := func(v uint64) {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (8 * i))
		}
		buf = append(buf, b[:]...)
	}
	appendU64(report.GetPolicy())
	appendU64(report.GetCurrentTcb())
	appendU64(report.GetCommittedTcb())
	buf = append(buf, fixedSize(report.GetFamilyId(), 16)...)
	buf = append(buf, fixedSize(report.GetImageId(), 16)...)
	buf = append(buf, fixedSize(report.GetHostData(), 32)...)
	buf = append(buf, fixedSize(report.GetMeasurement(), 48)...)
	buf = append(buf, fixedSize(report.GetReportData(), 64)...)
	buf = append(buf, fixedSize(report.GetChipId(), 64)...)
	return buf
}

// fixedSize returns b padded or truncated to size n. Zero-pads when
// short. This guarantees canonicalSEVBytes is a fixed-shape blob.
func fixedSize(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func init() { registerVerifier(KindSEVSNP, SEVSNP{}) }

// Compile-time guard: SEVSNP satisfies Verifier.
var _ Verifier = SEVSNP{}

// Sentinel for unused import resilience: keep the errors import live in
// case future SEV-specific sentinels are added here. (No-op at runtime.)
var _ = errors.New
