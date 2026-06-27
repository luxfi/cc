// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/luxfi/cc/attest/nvidia"
)

// NVTrust is the NVIDIA GPU confidential-compute attestation verifier.
//
// NVTrust is NVIDIA's open attestation toolkit. It has two trust models:
//
//   - LOCAL (this verifier, the canonical Kind): the GPU evidence report
//     is matched against a Reference Integrity Manifest (RIM) that NVIDIA
//     signs per driver+VBIOS. The operator pins the RIM signing key; the
//     verifier checks the RIM signature and that every measurement the GPU
//     reports equals the signed golden value. No network, no NVIDIA cloud
//     dependency — the only trust anchor is the operator-pinned signing key.
//     This is the mode a decentralized / blockchain control plane requires.
//
//   - REMOTE (NVIDIA Remote Attestation Service): the evidence is POSTed to
//     NRAS, which returns a signed JWS token. That path is the lower-level
//     nvidia.NRASClient primitive; it is a distinct deployment choice (trust
//     NVIDIA's cloud) and is NOT what this Kind dispatches to. Callers that
//     accept a cloud dependency use nvidia.NRASClient directly.
//
// Evidence is the JSON GPU evidence envelope (see nvidia.ParseGPUReport).
// The signed RIM and the trust roots that may sign it are supplied via
// options — WithNVTrustRIM and WithNVTrustTrustRoots. There is no insecure
// mode: a verify with no RIM or no trust roots is refused with ErrPolicy,
// exactly as nvidia.ParseAndVerifyRIM refuses an empty trust-root set.
//
// On success the VerifiedReport carries:
//
//   - Measurement: the RIM measurement root (sha256 over the signed,
//     name-sorted golden measurement list the GPU was proven to match).
//   - ReportData:  the 32-byte freshness nonce echoed in the GPU report.
//   - ChipID:      the per-GPU UUID bytes.
//   - Extra:       driver/VBIOS/architecture/evidence-version + RIM signer.
//
// Honest scope: local mode proves "this GPU reports measurements that match
// an NVIDIA-signed RIM for its driver+VBIOS, bound to a fresh nonce." It
// does not, on its own, verify the GPU device certificate's SPDM signature
// against NVIDIA's device root CA — that anchor is what the REMOTE NRAS path
// (or a future embedded device-root) provides. Local mode is a strict
// upgrade over any unsigned/structural-only check and is the cloud-free
// integrity gate; deployments needing device-cert chaining add the NRAS
// primitive on top.
type NVTrust struct{}

// Verify implements Verifier for the NVIDIA local-RIM attestation path.
func (NVTrust) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	cfg := applyOptions(opts...)

	// Parse the GPU evidence envelope. ParseGPUReport validates the
	// envelope version, architecture, nonce shape, and decodes every
	// measurement — structural problems fail here before any trust
	// decision is made.
	report, err := nvidia.ParseGPUReport(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// No insecure mode: a signed RIM and the keys that may sign it are
	// mandatory. Refuse rather than fall back to "trust the report".
	if len(cfg.nvtrustRIM) == 0 {
		return nil, fmt.Errorf("%w: nvtrust requires a signed RIM (WithNVTrustRIM)", ErrPolicy)
	}
	if len(cfg.nvtrustTrustRoots) == 0 {
		return nil, fmt.Errorf("%w: nvtrust requires RIM trust roots (WithNVTrustTrustRoots)", ErrPolicy)
	}

	// Verify the RIM's detached signature against the operator-pinned
	// trust roots. A bad signature means the golden values are not vendor-
	// authentic — treat as a vendor-chain failure (refuse).
	rim, err := nvidia.ParseAndVerifyRIM(cfg.nvtrustRIM, cfg.nvtrustTrustRoots)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}

	// Match every reported measurement against the signed RIM, and assert
	// the RIM's driver/VBIOS/architecture preconditions equal the report.
	// A cryptographically valid RIM that does not cover this GPU's actual
	// measurements is a policy refusal, not a chain failure.
	if err := rim.Match(report); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicy, err)
	}

	measRoot := rim.MeasurementRoot()

	// Caller-supplied policy: freshness nonce binding.
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, report.Nonce[:]) != 1 {
			return nil, fmt.Errorf("%w: nonce mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(report.Nonce[:]))
		}
	}
	// Caller-supplied policy: pin the expected measurement root.
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, measRoot[:]) != 1 {
			return nil, fmt.Errorf("%w: measurement root mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(measRoot[:]))
		}
	}

	out := &VerifiedReport{
		Kind:        KindNVTrust,
		Vendor:      "nvidia.nvtrust",
		Measurement: append([]byte(nil), measRoot[:]...),
		ReportData:  append([]byte(nil), report.Nonce[:]...),
		ChipID:      []byte(report.UUID),
		IssuedAt:    cfg.nowOrWall().UTC(),
		Extra:       buildNVTrustExtra(report, rim),
	}
	out.CompositeHash = computeCompositeHash(KindNVTrust, canonicalNVTrustBytes(report, rim))
	return out, nil
}

// buildNVTrustExtra collects NVIDIA-specific fields that don't fit the
// common shape. Keys are stable wire identifiers prefixed "nvtrust.".
func buildNVTrustExtra(report *nvidia.GPUReport, rim *nvidia.RIM) map[string]string {
	extra := make(map[string]string, 6)
	extra["nvtrust.gpu_uuid"] = report.UUID
	extra["nvtrust.architecture"] = report.Architecture
	extra["nvtrust.driver_version"] = report.DriverVersion
	extra["nvtrust.vbios_version"] = report.VBIOSVersion
	extra["nvtrust.evidence_version"] = report.EvidenceVersion
	extra["nvtrust.rim_signer"] = rim.SignerKeyID
	if report.NVSwitchPresent {
		extra["nvtrust.nvswitch_present"] = "true"
	}
	return extra
}

// canonicalNVTrustBytes returns the bytes that participate in
// CompositeHash. We hash the verifier-extracted fields (UUID, arch,
// driver, VBIOS, nonce, signed measurement root, RIM signer) in a fixed,
// null-separated order so that re-deriving the hash on the consumer side
// reproduces the same value iff the same evidence was matched against the
// same signed RIM. UUID/version strings cannot contain NUL, so the
// separator is unambiguous.
func canonicalNVTrustBytes(report *nvidia.GPUReport, rim *nvidia.RIM) []byte {
	measRoot := rim.MeasurementRoot()
	buf := make([]byte, 0, 256)
	appendField := func(b []byte) {
		buf = append(buf, b...)
		buf = append(buf, 0x00)
	}
	appendField([]byte(report.UUID))
	appendField([]byte(report.Architecture))
	appendField([]byte(report.DriverVersion))
	appendField([]byte(report.VBIOSVersion))
	appendField(report.Nonce[:])
	appendField(measRoot[:])
	appendField([]byte(rim.SignerKeyID))
	return buf
}

// Compile-time guard: NVTrust satisfies Verifier.
var _ Verifier = NVTrust{}
