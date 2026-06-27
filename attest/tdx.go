// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

// KindTDX is the Intel TDX framing: a raw Intel DCAP v4 TDX quote with the PCK
// certificate chain embedded in its signed certification data.
const KindTDX Kind = "tdx"

// TDX is the production Intel TDX verifier. It accepts a raw Intel
// DCAP v4 TDX quote (the bytes the guest reads from the TDX quote-
// generation service) and performs the full DCAP attestation flow via
// github.com/google/go-tdx-guest — the canonical Google verifier, sibling
// of go-sev-guest used by the SEV-SNP path:
//
//  1. Parse the quote via go-tdx-guest/abi.QuoteToProto (QuoteV4 only).
//  2. Verify the PCK certificate chain that is EMBEDDED in the quote's
//     signed certification data (PCK Leaf -> Intel SGX Platform CA ->
//     Intel SGX Root CA) up to Intel's Root CA, which ships pinned inside
//     go-tdx-guest (verify/trusted_root.pem). Unlike SEV — where the VCEK
//     leaf is fetched from the AMD KDS — the TDX leaf travels inside the
//     quote, so the chain itself needs no network.
//  3. Verify the Quoting Enclave (QE) report signature with the verified
//     PCK leaf key, and verify the attestation-key binding: the QE report
//     data must equal SHA-256(ECDSA attestation key || QE auth data), so
//     the key that signed the TD report is the one Intel's QE vouched for.
//  4. Verify the TD report (TDQuoteBody) ECDSA-P256 signature made by that
//     attestation key over the quote header + body.
//  5. Fetch Intel PCS collateral (TCB Info + QE Identity, plus PCK and Root
//     CA CRLs) and enforce TCB status: the platform's TEE_TCB_SVN must map
//     to an "UpToDate" TCB level, the QE identity must match, and no cert
//     in the chain may be revoked. This is the freshness/patch-level gate;
//     a downlevel or revoked platform is REFUSED.
//  6. Extract MRTD + the four RTMRs and fold them into a single 48-byte
//     measurement root, extract REPORTDATA, and enforce caller policy
//     (expected measurement / expected report data == nonce binding).
//
// Trust anchor: the Intel SGX Root CA pinned inside go-tdx-guest. It is
// never taken from the quote. Production requires network reachability to
// the Intel PCS (api.trustedservices.intel.com) for collateral, exactly as
// the SEV-SNP path requires the AMD KDS; operators that cannot reach Intel
// directly front it with a PCCS mirror and point the getter at it. In tests
// the getter is overridden (see WithKDSGetter) to replay committed Intel
// collateral from testdata/ so verification runs offline.
//
// As with every Kind: (nil, err) means refuse. There is no partial report
// and no best-effort fallback.
type TDX struct{}

const (
	tdxVendor = "intel.tdx"

	// Field sizes from the Intel TDX DCAP quote spec (see go-tdx-guest/abi):
	// MRTD and each RTMR are SHA-384 (48 bytes); REPORTDATA is 64 bytes.
	tdxMrTdSize      = 48
	tdxRtmrSize      = 48
	tdxRtmrCount     = 4
	tdxReportDataLen = 64
)

// tdxMeasureFoldDomain domain-separates the TD measurement-root fold so it
// can never collide with a raw register value or another kind's hash input.
var tdxMeasureFoldDomain = []byte("LUX-TDX-MEAS-FOLD-v1")

// Verify implements Verifier for Intel TDX DCAP v4 quotes.
func (TDX) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(evidence) < abi.QuoteMinSize {
		return nil, fmt.Errorf("%w: tdx quote expects at least %d bytes, got %d",
			ErrInvalidEvidence, abi.QuoteMinSize, len(evidence))
	}

	cfg := applyOptions(opts...)

	// Parse first so we fail fast on malformed framing, and so the extracted
	// fields below come from a structurally validated quote (CheckQuoteV4 runs
	// inside QuoteToProto).
	anyQuote, err := abi.QuoteToProto(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	quote, ok := anyQuote.(*tdxpb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported tdx quote type %T (only DCAP QuoteV4)",
			ErrInvalidEvidence, anyQuote)
	}

	// Build the full-rigor verification options. GetCollateral and
	// CheckRevocations are ON: without collateral the TEE_TCB_SVN is never
	// compared to Intel's signed TCB levels, so a downlevel/vulnerable but
	// otherwise well-formed platform would pass. DefaultOptions() leaves both
	// off, so we set them explicitly.
	vopts := &verify.Options{
		GetCollateral:    true,
		CheckRevocations: true,
		Now:              cfg.nowOrWall(),
	}
	// Getter resolution mirrors the SEV path. The cc/attest option carries an
	// HTTPS getter as `any` (WithKDSGetter); for KindTDX it supplies the Intel
	// PCS / PCCS getter and tests inject a replay map so the suite runs
	// offline. Production leaves it nil and the live Intel PCS getter is used.
	if cfg.kdsGetter != nil {
		g, ok := cfg.kdsGetter.(trust.HTTPSGetter)
		if !ok {
			return nil, fmt.Errorf("%w: injected getter does not implement go-tdx-guest trust.HTTPSGetter",
				ErrInvalidEvidence)
		}
		vopts.Getter = g
	} else {
		vopts.Getter = trust.DefaultHTTPSGetter()
	}

	// Full DCAP verification: PCK chain -> Intel SGX Root CA, QE report sig,
	// attestation-key binding, TD report ECDSA-P256 sig, TCB status, and
	// revocation. Reuses the parse above (no re-decode).
	if err := verify.TdxQuote(quote, vopts); err != nil {
		return nil, classifyTDXVerifyError(err)
	}

	// Chain + signatures + TCB are valid; extract measurements and apply
	// caller policy.
	return buildTDXReport(quote, cfg)
}

// classifyTDXVerifyError maps go-tdx-guest's flat error strings onto the
// package refusal taxonomy so callers can switch on errors.Is. go-tdx-guest
// returns a single error value; we classify by content. Every branch is a
// refusal — when in doubt we treat the failure as a vendor-chain failure
// (ErrChainInvalid), never as success. Ordering is significant: the most
// specific causes are matched first.
func classifyTDXVerifyError(err error) error {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	// Structural / framing problems the parser surfaces late.
	case strings.Contains(low, "could not convert raw bytes"),
		strings.Contains(low, "quote format not supported"),
		strings.Contains(low, "unsupported quote type"),
		strings.Contains(low, "is nil"):
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)

	// TCB status: the chain is cryptographically valid but the platform's
	// patch level does not meet Intel's "UpToDate" bar (or no level matches).
	// This is a policy refusal on otherwise-valid evidence.
	case strings.Contains(low, "tcb status"),
		strings.Contains(low, "matching tcb level"),
		strings.Contains(low, "tcb level"):
		return fmt.Errorf("%w: %v", ErrPolicy, err)

	// Revocation: a certificate in the chain was pulled by Intel.
	case strings.Contains(low, "revoked"),
		strings.Contains(low, "revocation"):
		return fmt.Errorf("%w: %v", ErrChainInvalid, err)

	// Signature / attestation-key binding failures. ErrHashVerificationFail
	// ("unable to verify message digest using quote's signature and ecdsa
	// attestation key") is the TD report signature; ErrSHA56VerificationFail
	// ("QE Report Data does not match ... ECDSA Attestation Key ...") is the
	// attestation-key binding. Both mean the signing key is not authentic.
	case strings.Contains(low, "signature"),
		strings.Contains(low, "ecdsa attestation key"),
		strings.Contains(low, "message digest"),
		strings.Contains(low, "report data does not match"):
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)

	// Everything else — cert/chain/CRL/issuer/public-key/collateral/expiry —
	// is a vendor-chain validation failure. Conservative default: refuse.
	default:
		return fmt.Errorf("%w: %v", ErrChainInvalid, err)
	}
}

// buildTDXReport extracts the verified measurements from a TD quote whose
// chain, signatures, and TCB status have already passed, applies caller
// policy, and returns the canonical VerifiedReport.
func buildTDXReport(quote *tdxpb.QuoteV4, cfg config) (*VerifiedReport, error) {
	body := quote.GetTdQuoteBody()
	if body == nil {
		return nil, fmt.Errorf("%w: tdx quote has no TD report body", ErrInvalidEvidence)
	}

	mrtd := body.GetMrTd()
	rtmrs := body.GetRtmrs()
	reportData := body.GetReportData()

	// Defense in depth: the parser already enforced these, but we are about to
	// make trust decisions on the output of C-ABI / proto code, so we recheck
	// the lengths that feed the measurement fold and the policy comparisons.
	if len(mrtd) != tdxMrTdSize {
		return nil, fmt.Errorf("%w: MRTD is %d bytes, expected %d", ErrInvalidEvidence, len(mrtd), tdxMrTdSize)
	}
	if len(rtmrs) != tdxRtmrCount {
		return nil, fmt.Errorf("%w: got %d RTMRs, expected %d", ErrInvalidEvidence, len(rtmrs), tdxRtmrCount)
	}
	for i, r := range rtmrs {
		if len(r) != tdxRtmrSize {
			return nil, fmt.Errorf("%w: RTMR%d is %d bytes, expected %d", ErrInvalidEvidence, i, len(r), tdxRtmrSize)
		}
	}
	if len(reportData) != tdxReportDataLen {
		return nil, fmt.Errorf("%w: REPORTDATA is %d bytes, expected %d", ErrInvalidEvidence, len(reportData), tdxReportDataLen)
	}

	// Fold MRTD + the four RTMRs into a single 48-byte TD measurement root.
	// MRTD is the build-time launch measurement; the RTMRs are the runtime-
	// extended registers (firmware config, kernel, OS, runtime). Pinning the
	// fold pins the entire launch+runtime state in one comparison value.
	measurement := foldTDXMeasurement(mrtd, rtmrs)

	// Caller policy on the verified fields. Constant-time compares.
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, reportData) != 1 {
			return nil, fmt.Errorf("%w: report_data mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(reportData))
		}
	}
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, measurement) != 1 {
			return nil, fmt.Errorf("%w: measurement mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(measurement))
		}
	}

	out := &VerifiedReport{
		Kind:        KindTDX,
		Vendor:      tdxVendor,
		Measurement: measurement,
		ReportData:  cloneBytes(reportData),
		// HostData/ChipID: TDX exposes no host-data or per-chip identifier in
		// the TD report (PCK identity is per-platform FMSPC, surfaced in Extra
		// where available). Left nil rather than populated with a stand-in.
		IssuedAt: cfg.nowOrWall().UTC(),
		Extra:    buildTDXExtra(body),
	}
	out.CompositeHash = computeCompositeHash(KindTDX, canonicalTDXBytes(body))
	return out, nil
}

// foldTDXMeasurement returns SHA-384(domain || 0x00 || MRTD || RTMR0..3).
// SHA-384 keeps the root at the 48-byte width of the TDX measurement
// registers themselves, symmetric with the SEV-SNP 48-byte launch digest.
func foldTDXMeasurement(mrtd []byte, rtmrs [][]byte) []byte {
	h := sha512.New384()
	h.Write(tdxMeasureFoldDomain)
	h.Write([]byte{0x00}) // domain separator
	h.Write(mrtd)
	for _, r := range rtmrs {
		h.Write(r)
	}
	return h.Sum(nil)
}

// buildTDXExtra collects TDX-specific fields that don't fit the common shape.
// Keys are stable wire identifiers prefixed "tdx."; values are hex. The raw
// MRTD and each RTMR are exposed individually so callers can pin finer-grained
// policy than the folded measurement root.
func buildTDXExtra(body *tdxpb.TDQuoteBody) map[string]string {
	extra := make(map[string]string, 12)
	extra["tdx.mrtd"] = hex.EncodeToString(body.GetMrTd())
	for i, r := range body.GetRtmrs() {
		extra[fmt.Sprintf("tdx.rtmr%d", i)] = hex.EncodeToString(r)
	}
	extra["tdx.mrseam"] = hex.EncodeToString(body.GetMrSeam())
	extra["tdx.mrsignerseam"] = hex.EncodeToString(body.GetMrSignerSeam())
	extra["tdx.seam_attributes"] = hex.EncodeToString(body.GetSeamAttributes())
	extra["tdx.td_attributes"] = hex.EncodeToString(body.GetTdAttributes())
	extra["tdx.xfam"] = hex.EncodeToString(body.GetXfam())
	extra["tdx.mrconfigid"] = hex.EncodeToString(body.GetMrConfigId())
	extra["tdx.mrowner"] = hex.EncodeToString(body.GetMrOwner())
	extra["tdx.mrownerconfig"] = hex.EncodeToString(body.GetMrOwnerConfig())
	extra["tdx.tee_tcb_svn"] = hex.EncodeToString(body.GetTeeTcbSvn())
	return extra
}

// canonicalTDXBytes returns the fixed-shape bytes that participate in
// CompositeHash. We hash the verifier-extracted TD report fields (never the
// raw wire) in a fixed order and width so a consumer re-deriving the hash
// reproduces it iff the same quote was verified. Field widths follow the
// Intel TDX quote spec; fixedSize zero-pads/truncates to keep the blob shape
// constant.
func canonicalTDXBytes(body *tdxpb.TDQuoteBody) []byte {
	// 16(teeTcbSvn) + 48(mrSeam) + 48(mrSignerSeam) + 8(seamAttrs)
	//   + 8(tdAttrs) + 8(xfam) + 48(mrTd) + 48(mrConfigId) + 48(mrOwner)
	//   + 48(mrOwnerConfig) + 4*48(rtmrs) + 64(reportData) = 632 bytes.
	buf := make([]byte, 0, 632)
	buf = append(buf, fixedSize(body.GetTeeTcbSvn(), 16)...)
	buf = append(buf, fixedSize(body.GetMrSeam(), 48)...)
	buf = append(buf, fixedSize(body.GetMrSignerSeam(), 48)...)
	buf = append(buf, fixedSize(body.GetSeamAttributes(), 8)...)
	buf = append(buf, fixedSize(body.GetTdAttributes(), 8)...)
	buf = append(buf, fixedSize(body.GetXfam(), 8)...)
	buf = append(buf, fixedSize(body.GetMrTd(), 48)...)
	buf = append(buf, fixedSize(body.GetMrConfigId(), 48)...)
	buf = append(buf, fixedSize(body.GetMrOwner(), 48)...)
	buf = append(buf, fixedSize(body.GetMrOwnerConfig(), 48)...)
	for _, r := range body.GetRtmrs() {
		buf = append(buf, fixedSize(r, 48)...)
	}
	buf = append(buf, fixedSize(body.GetReportData(), 64)...)
	return buf
}

func init() { registerVerifier(KindTDX, TDX{}) }

// Compile-time guard: TDX satisfies Verifier.
var _ Verifier = TDX{}
