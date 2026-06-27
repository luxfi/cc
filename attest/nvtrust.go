// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/cc/attest/nvidia"
)

// NVTrust is the NVIDIA GPU confidential-compute attestation verifier. It
// implements both NVIDIA trust models behind one Kind, selected by Mode:
//
//   - ModeLocal (default, cloud-free): full hardware verification. The GPU
//     evidence carries a signed SPDM MEASUREMENTS report plus the GPU's
//     device certificate chain. NVTrust (1) chains the leaf to an operator-
//     pinned NVIDIA device-identity root, (2) verifies the SPDM report
//     signature with that leaf key, (3) extracts measurements from the
//     SIGNED record and matches them by index to an NVIDIA-signed Reference
//     Integrity Manifest, and (4) binds the signed requester nonce to the
//     caller's freshness challenge. This is the mode a decentralized
//     control plane requires — the only trust anchors are the operator-
//     pinned device root and RIM signing key; no NVIDIA cloud is contacted.
//
//   - ModeNRAS (remote): the evidence is an NVIDIA Remote Attestation
//     Service EAT/JWT. NVTrust verifies the token signature against pinned
//     NRAS signer keys (or an x5c chain to a pinned NRAS root), checks
//     freshness, and binds the eat_nonce. The relying party trusts NVIDIA's
//     cloud verdict. The live POST to NRAS is nvidia.NRASClient's job; this
//     Kind only verifies the resulting token (no network in Verify).
//
// Trust anchors are NEVER taken from the evidence. They are operator-pinned
// at construction (NewNVTrust + options), exactly as AMD's ARK is pinned
// for SEV-SNP. There is no insecure mode: ModeLocal with no device root, or
// ModeNRAS with no NRAS trust, is refused.
//
// The zero value (NVTrust{}, used by Dispatch) is ModeLocal with no pinned
// device root and therefore fail-closed: it refuses every input. Production
// callers construct a configured verifier with NewNVTrust and use it as a
// Verifier; see nvtrust_options.go.
//
// On success the VerifiedReport carries:
//
//   - Measurement: the matched RIM measurement root (ModeLocal) or the EAT
//     measurement root (ModeNRAS). Trust-score / tier is policy ON TOP of
//     this — the caller scores an already-verified measurement.
//   - ReportData:  the 32-byte freshness nonce (the SIGNED SPDM requester
//     nonce in ModeLocal; the eat_nonce in ModeNRAS).
//   - ChipID:      the device leaf-certificate serial (ModeLocal) — a
//     trusted GPU identity, not the untrusted envelope UUID.
type NVTrust struct {
	mode         NVTrustMode
	deviceRoots  *x509.CertPool     // ModeLocal: NVIDIA device-identity root CA
	nrasRoots    []nvidia.TrustRoot // ModeNRAS: NRAS signer keys (by kid)
	nrasRootPool *x509.CertPool     // ModeNRAS: NRAS root CA for x5c chaining (optional)
	now          func() time.Time   // injectable clock; nil = per-call WithNow / wall
}

// NVTrustMode selects the GPU attestation trust model.
type NVTrustMode uint8

const (
	// ModeLocal performs full local hardware SPDM verification. This is
	// the zero value, so an unconfigured NVTrust defaults to the strict
	// (and, without a pinned device root, fail-closed) local path.
	ModeLocal NVTrustMode = iota
	// ModeNRAS verifies an NVIDIA Remote Attestation Service EAT token.
	ModeNRAS
)

func (m NVTrustMode) String() string {
	switch m {
	case ModeLocal:
		return "local"
	case ModeNRAS:
		return "nras"
	default:
		return "invalid"
	}
}

// Verify implements Verifier, dispatching on the configured mode.
func (n NVTrust) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	cfg := applyOptions(opts...)
	switch n.mode {
	case ModeLocal:
		return n.verifyLocal(evidence, cfg)
	case ModeNRAS:
		return n.verifyNRAS(evidence, cfg)
	default:
		return nil, fmt.Errorf("%w: nvtrust mode %d", ErrUnsupportedKind, n.mode)
	}
}

// verifyLocal runs the full SPDM + device-chain + RIM verification.
func (n NVTrust) verifyLocal(evidence []byte, cfg config) (*VerifiedReport, error) {
	now := n.clock(cfg)

	report, err := nvidia.ParseGPUReport(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// No insecure mode: the device-identity root must be pinned.
	if n.deviceRoots == nil {
		return nil, fmt.Errorf("%w: nvtrust local mode requires a pinned NVIDIA device root (NewNVTrust + WithNVTrustDeviceRoots)", ErrPolicy)
	}
	// The signed SPDM evidence (request + response) is mandatory in local
	// mode — without it there is nothing cryptographic to verify.
	if len(report.SPDMResponse) == 0 || len(report.SPDMRequest) == 0 {
		return nil, fmt.Errorf("%w: nvtrust local mode requires spdm_request and spdm_response", ErrInvalidEvidence)
	}

	// 1) Chain the GPU device cert to the pinned NVIDIA root, get the leaf.
	chain, err := nvidia.ParseCertChainPEM(report.CertChain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	leaf, err := nvidia.VerifyDeviceChain(chain, n.deviceRoots, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}
	leafKey, err := nvidia.LeafSPDMKey(leaf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}

	// 2) Verify the SPDM measurement-report signature with the leaf key.
	algo, err := nvidia.ParseSPDMAsymAlgo(report.SPDMAsymAlgo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	spdm, err := nvidia.VerifySPDMMeasurementSignature(leafKey, algo, report.SPDMRequest, report.SPDMResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	// 3) The SIGNED requester nonce is the freshness anchor. It must match
	// the envelope's claimed nonce (consistency) and is what policy binds.
	_, reqNonce, err := nvidia.SPDMRequestNonce(report.SPDMRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	if reqNonce != report.Nonce {
		return nil, fmt.Errorf("%w: envelope nonce %x != signed request nonce %x",
			ErrPolicy, report.Nonce[:], reqNonce[:])
	}

	// 4) Match the SIGNED measurements against the NVIDIA-signed RIM.
	if len(cfg.nvtrustRIM) == 0 {
		return nil, fmt.Errorf("%w: nvtrust requires a signed RIM (WithNVTrustRIM)", ErrPolicy)
	}
	if len(cfg.nvtrustTrustRoots) == 0 {
		return nil, fmt.Errorf("%w: nvtrust requires RIM trust roots (WithNVTrustTrustRoots)", ErrPolicy)
	}
	rim, err := nvidia.ParseAndVerifyRIM(cfg.nvtrustRIM, cfg.nvtrustTrustRoots)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}
	if err := rim.MatchSPDM(report.Architecture, report.DriverVersion, report.VBIOSVersion, spdm.Measurements); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	measRoot := rim.MeasurementRoot()

	// 5) Caller policy: freshness nonce and measurement-root pin.
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, reqNonce[:]) != 1 {
			return nil, fmt.Errorf("%w: nonce mismatch (got %s)", ErrPolicy, hex.EncodeToString(reqNonce[:]))
		}
	}
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, measRoot[:]) != 1 {
			return nil, fmt.Errorf("%w: measurement root mismatch (got %s)", ErrPolicy, hex.EncodeToString(measRoot[:]))
		}
	}

	out := &VerifiedReport{
		Kind:        KindNVTrust,
		Vendor:      "nvidia.nvtrust.local",
		Measurement: append([]byte(nil), measRoot[:]...),
		ReportData:  append([]byte(nil), reqNonce[:]...),
		ChipID:      leaf.SerialNumber.Bytes(),
		IssuedAt:    now.UTC(),
		Extra:       buildNVTrustLocalExtra(report, rim, leaf, algo),
	}
	out.CompositeHash = computeCompositeHash(KindNVTrust, canonicalNVTrustLocalBytes(leaf, reqNonce, measRoot, rim.SignerKeyID, spdm.Signature))
	return out, nil
}

// verifyNRAS verifies an NVIDIA Remote Attestation Service EAT token.
func (n NVTrust) verifyNRAS(evidence []byte, cfg config) (*VerifiedReport, error) {
	now := n.clock(cfg)
	if len(n.nrasRoots) == 0 && n.nrasRootPool == nil {
		return nil, fmt.Errorf("%w: nvtrust NRAS mode requires pinned NRAS trust (WithNVTrustNRASRoots / WithNVTrustNRASRootCAs)", ErrPolicy)
	}
	if len(evidence) == 0 {
		return nil, fmt.Errorf("%w: empty NRAS token", ErrInvalidEvidence)
	}

	// Freshness challenge from policy: must be 32 bytes if supplied.
	var challenge *[32]byte
	if cfg.expectedReportData != nil {
		if len(cfg.expectedReportData) != 32 {
			return nil, fmt.Errorf("%w: NRAS challenge must be 32 bytes, got %d", ErrPolicy, len(cfg.expectedReportData))
		}
		var c [32]byte
		copy(c[:], cfg.expectedReportData)
		challenge = &c
	}

	eat, err := nvidia.VerifyEAT(string(evidence), n.nrasRoots, n.nrasRootPool, challenge, now)
	if err != nil {
		return nil, classifyEATError(err)
	}

	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, eat.Measurement) != 1 {
			return nil, fmt.Errorf("%w: measurement mismatch (got %s)", ErrPolicy, hex.EncodeToString(eat.Measurement))
		}
	}

	out := &VerifiedReport{
		Kind:        KindNVTrust,
		Vendor:      "nvidia.nvtrust.nras",
		Measurement: append([]byte(nil), eat.Measurement...),
		IssuedAt:    now.UTC(),
		Extra:       buildNVTrustNRASExtra(eat),
	}
	if eat.HasNonce {
		out.ReportData = append([]byte(nil), eat.Nonce[:]...)
	}
	tokenHash := sha256.Sum256(evidence)
	out.CompositeHash = computeCompositeHash(KindNVTrust, canonicalNVTrustNRASBytes(eat, tokenHash))
	return out, nil
}

// clock resolves the verification time: per-call WithNow wins (tests),
// then the instance clock, then wall.
func (n NVTrust) clock(cfg config) time.Time {
	if !cfg.now.IsZero() {
		return cfg.now
	}
	if n.now != nil {
		return n.now()
	}
	return time.Now()
}

// classifyEATError maps EAT verification failures onto the refusal
// taxonomy: bad token/structure -> ErrInvalidEvidence, untrusted chain or
// signature -> ErrChainInvalid/ErrSignatureInvalid, everything else
// (freshness, nonce, negative verdict) -> ErrPolicy. Every path refuses.
func classifyEATError(err error) error {
	switch {
	case errors.Is(err, nvidia.ErrEATBadJWT):
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	case errors.Is(err, nvidia.ErrEATChainUntrusted):
		return fmt.Errorf("%w: %v", ErrChainInvalid, err)
	case errors.Is(err, nvidia.ErrEATBadSignature), errors.Is(err, nvidia.ErrEATNoSigner):
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	default:
		return fmt.Errorf("%w: %v", ErrPolicy, err)
	}
}

// buildNVTrustLocalExtra collects local-mode audit fields. The envelope
// UUID/driver/VBIOS are CLAIMED (untrusted labels) and tagged as such; the
// device identity is the verified leaf subject.
func buildNVTrustLocalExtra(report *nvidia.GPUReport, rim *nvidia.RIM, leaf *x509.Certificate, algo nvidia.SPDMAsymAlgo) map[string]string {
	extra := map[string]string{
		"nvtrust.mode":            "local",
		"nvtrust.claimed_uuid":    report.UUID,
		"nvtrust.architecture":    report.Architecture,
		"nvtrust.driver_version":  report.DriverVersion,
		"nvtrust.vbios_version":   report.VBIOSVersion,
		"nvtrust.evidence_ver":    report.EvidenceVersion,
		"nvtrust.rim_signer":      rim.SignerKeyID,
		"nvtrust.spdm_asym_algo":  algo.String(),
		"nvtrust.device_subject":  leaf.Subject.String(),
		"nvtrust.device_serial":   leaf.SerialNumber.Text(16),
		"nvtrust.device_issuer":   leaf.Issuer.String(),
		"nvtrust.device_notafter": leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	if report.NVSwitchPresent {
		extra["nvtrust.nvswitch_present"] = "true"
	}
	return extra
}

func buildNVTrustNRASExtra(eat *nvidia.EATResult) map[string]string {
	extra := map[string]string{
		"nvtrust.mode":        "nras",
		"nvtrust.nras_signer": eat.SignerKeyID,
	}
	if eat.OverallResult != "" {
		extra["nvtrust.nras_result"] = eat.OverallResult
	}
	if !eat.ExpiresAt.IsZero() {
		extra["nvtrust.nras_exp"] = eat.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return extra
}

// canonicalNVTrustLocalBytes is the deterministic, verified-fields blob
// that CompositeHash commits to. It binds the device identity (leaf SPKI),
// the freshness nonce, the matched RIM measurement root + signer, and the
// SPDM signature (which uniquely commits to the exact signed measurement
// record under the device key). NUL-separated; SPKI/sig are fixed-shape
// DER/bytes so the separator is unambiguous across the string fields.
func canonicalNVTrustLocalBytes(leaf *x509.Certificate, nonce [32]byte, measRoot [32]byte, rimSigner string, spdmSig []byte) []byte {
	buf := make([]byte, 0, 512)
	appendField := func(b []byte) {
		buf = append(buf, b...)
		buf = append(buf, 0x00)
	}
	appendField(leaf.RawSubjectPublicKeyInfo)
	appendField(nonce[:])
	appendField(measRoot[:])
	appendField([]byte(rimSigner))
	appendField(spdmSig)
	return buf
}

func canonicalNVTrustNRASBytes(eat *nvidia.EATResult, tokenHash [32]byte) []byte {
	buf := make([]byte, 0, 160)
	appendField := func(b []byte) {
		buf = append(buf, b...)
		buf = append(buf, 0x00)
	}
	appendField(tokenHash[:])
	appendField(eat.Measurement)
	appendField([]byte(eat.SignerKeyID))
	if eat.HasNonce {
		appendField(eat.Nonce[:])
	} else {
		appendField(nil)
	}
	return buf
}

// Compile-time guard: NVTrust satisfies Verifier.
var _ Verifier = NVTrust{}
