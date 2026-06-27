// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// tdxProdQuote is a real Intel TDX DCAP v4 quote captured from a Sapphire
// Rapids (SPR, E4 stepping) TD. Sourced verbatim from the upstream
// go-tdx-guest test corpus (testing/testdata/tdx_prod_quote_SPR_E4.dat) and
// committed so this package's tests need no live TDX hardware or network.
//
//go:embed testdata/tdx_prod_quote_spr_e4.bin
var tdxProdQuote []byte

// The Intel PCS collateral that pairs with the quote above, committed
// verbatim from the same upstream corpus. NOTE: upstream deliberately bumped
// the TCB SVNs in tdx_tcb_info.json above the quote's TEE_TCB_SVN, so the
// full collateral path is EXPECTED to refuse on TCB status — that is what
// TestTDX_Verify_FullProductionPath_RefusesStaleTCB asserts. The quote itself
// is cryptographically genuine (TestTDX_QuoteIsCryptographicallyAuthentic).
//
//go:embed testdata/tdx_tcb_info.json
var tdxTcbInfoBody []byte

//go:embed testdata/tdx_qe_identity.json
var tdxQeIdentityBody []byte

//go:embed testdata/tdx_pck_crl.body
var tdxPckCrlBody []byte

//go:embed testdata/tdx_root_ca_crl.der
var tdxRootCaCrlBody []byte

// Issuer chains returned as Intel PCS response headers. The TCB Info and QE
// Identity share the Intel SGX TCB-Signing issuer chain; the PCK CRL uses the
// PCK Platform CA chain.
//
//go:embed testdata/tdx_collateral_issuer_chain.txt
var tdxCollateralIssuerChain string

//go:embed testdata/tdx_pck_crl_issuer_chain.txt
var tdxPckCrlIssuerChain string

// tdxFixedNow pins the verification clock inside the validity window of the
// committed quote's PCK chain and collateral (the quote is from ~2023). Tests
// are reproducible regardless of when CI runs, exactly like the SEV path's
// fixedNow.
func tdxFixedNow() time.Time {
	return time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
}

// Absolute byte offsets into the raw quote, per the Intel DCAP v4 layout
// (header 0x30, then the TD quote body; see go-tdx-guest/abi):
//   - MRTD begins at header(0x30) + body-relative MRTD offset(0x88).
//   - The ECDSA-P256 signature begins at header(0x30) + body(0x248) +
//     signed-data-size(4).
const (
	tdxAbsMRTDOffset = 0x30 + 0x88
	tdxAbsSigOffset  = 0x30 + 0x248 + 4
)

// tdxReplayGetter replays the committed Intel PCS collateral so the full
// production verification path runs offline. The URL keys are exactly the
// ones go-tdx-guest requests (mirrored from the upstream TestGetter); a
// substring fallback keeps the test robust to incidental URL formatting.
type tdxReplayGetter struct{}

func (tdxReplayGetter) Get(url string) (map[string][]string, []byte, error) {
	const (
		hdrTCB = "Tcb-Info-Issuer-Chain"
		hdrQE  = "Sgx-Enclave-Identity-Issuer-Chain"
		hdrPCK = "Sgx-Pck-Crl-Issuer-Chain"
	)
	switch {
	case strings.Contains(url, "qe/identity"):
		return map[string][]string{hdrQE: {tdxCollateralIssuerChain}}, tdxQeIdentityBody, nil
	case strings.Contains(url, "/tcb"):
		return map[string][]string{hdrTCB: {tdxCollateralIssuerChain}}, tdxTcbInfoBody, nil
	case strings.Contains(url, "pckcrl"):
		return map[string][]string{hdrPCK: {tdxPckCrlIssuerChain}}, tdxPckCrlBody, nil
	case strings.Contains(url, "RootCA"):
		return nil, tdxRootCaCrlBody, nil
	default:
		return nil, nil, errors.New("tdx replay getter: unexpected url " + url)
	}
}

// tdxErrGetter simulates an unreachable Intel PCS.
type tdxErrGetter struct{}

func (tdxErrGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("intel pcs unreachable")
}

func mustParseQuote(t *testing.T, raw []byte) *tdxpb.QuoteV4 {
	t.Helper()
	any, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatalf("QuoteToProto: %v", err)
	}
	q, ok := any.(*tdxpb.QuoteV4)
	if !ok {
		t.Fatalf("quote is %T, want *tdxpb.QuoteV4", any)
	}
	return q
}

// -----------------------------------------------------------------------------
// Cryptographic authenticity of the real quote
// -----------------------------------------------------------------------------

// TestTDX_QuoteIsCryptographicallyAuthentic proves the committed SPR quote
// passes the full DCAP cryptographic chain — PCK chain to the Intel SGX Root
// CA pinned in go-tdx-guest, QE report signature, attestation-key binding, and
// the TD report ECDSA-P256 signature — independent of the (deliberately stale)
// TCB collateral. This documents that the only reason the full production path
// refuses this fixture is the TCB SVN bump, not a broken quote.
func TestTDX_QuoteIsCryptographicallyAuthentic(t *testing.T) {
	quote := mustParseQuote(t, tdxProdQuote)
	// GetCollateral:false isolates the chain+signature checks from the TCB
	// collateral comparison.
	err := verify.TdxQuote(quote, &verify.Options{
		GetCollateral:    false,
		CheckRevocations: false,
		Now:              tdxFixedNow(),
	})
	if err != nil {
		t.Fatalf("real Intel SPR quote failed cryptographic verification: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Full production path: TCB-status enforcement against real Intel collateral
// -----------------------------------------------------------------------------

// TestTDX_Verify_FullProductionPath_RefusesStaleTCB drives the public
// TDX.Verify with the live-equivalent replay getter, exercising the entire
// production pipeline: parse -> PCK chain -> Intel SGX Root CA -> QE sig ->
// attestation-key binding -> TD report sig -> Intel PCS collateral fetch ->
// TCB-status comparison -> revocation. The committed collateral's TCB SVN is
// above the quote's, so the TCB gate fires and the platform is REFUSED.
func TestTDX_Verify_FullProductionPath_RefusesStaleTCB(t *testing.T) {
	rep, err := TDX{}.Verify(context.Background(), tdxProdQuote,
		WithKDSGetter(tdxReplayGetter{}), WithNow(tdxFixedNow()))
	if err == nil {
		t.Fatalf("expected refusal on stale TCB, got report %+v", rep)
	}
	if rep != nil {
		t.Errorf("refusal must return a nil report, got %+v", rep)
	}
	if !errors.Is(err, ErrPolicy) {
		t.Errorf("stale TCB: want ErrPolicy, got %v", err)
	}
	if !strings.Contains(err.Error(), "TCB") {
		t.Errorf("stale TCB: want a TCB-status message, got %v", err)
	}
}

// TestTDX_Reject_NoFallbackOnCollateralFailure proves there is no best-effort
// fallback: if Intel PCS is unreachable, verification refuses.
func TestTDX_Reject_NoFallbackOnCollateralFailure(t *testing.T) {
	rep, err := TDX{}.Verify(context.Background(), tdxProdQuote,
		WithKDSGetter(tdxErrGetter{}), WithNow(tdxFixedNow()))
	if err == nil || rep != nil {
		t.Fatalf("expected refusal when collateral is unreachable, got (%+v, %v)", rep, err)
	}
	if !errors.Is(err, ErrChainInvalid) {
		t.Errorf("collateral unreachable: want ErrChainInvalid, got %v", err)
	}
}

// TestTDX_Reject_StaleClock proves the verifier honors the verification clock
// and refuses material that is expired at that time.
func TestTDX_Reject_StaleClock(t *testing.T) {
	farFuture := time.Date(2053, time.July, 1, 1, 0, 0, 0, time.UTC)
	_, err := TDX{}.Verify(context.Background(), tdxProdQuote,
		WithKDSGetter(tdxReplayGetter{}), WithNow(farFuture))
	if err == nil {
		t.Fatal("expected refusal with an expired chain/collateral at far-future clock")
	}
	if !errors.Is(err, ErrChainInvalid) {
		t.Errorf("stale clock: want ErrChainInvalid, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Measurement extraction, fold, composite hash, and policy
// -----------------------------------------------------------------------------

func TestTDX_ExtractMeasurements_RealQuote(t *testing.T) {
	quote := mustParseQuote(t, tdxProdQuote)
	body := quote.GetTdQuoteBody()

	rep, err := buildTDXReport(quote, applyOptions())
	if err != nil {
		t.Fatalf("buildTDXReport: %v", err)
	}

	if rep.Kind != KindTDX {
		t.Errorf("Kind = %q, want %q", rep.Kind, KindTDX)
	}
	if rep.Vendor != tdxVendor {
		t.Errorf("Vendor = %q, want %q", rep.Vendor, tdxVendor)
	}

	// Measurement is the 48-byte fold over MRTD + the four RTMRs.
	if len(rep.Measurement) != tdxMrTdSize {
		t.Fatalf("Measurement len = %d, want %d", len(rep.Measurement), tdxMrTdSize)
	}
	wantFold := foldTDXMeasurement(body.GetMrTd(), body.GetRtmrs())
	if !bytes.Equal(rep.Measurement, wantFold) {
		t.Errorf("Measurement is not the MRTD+RTMR fold")
	}
	// The fold must not equal MRTD alone (proves the RTMRs are bound in).
	if bytes.Equal(rep.Measurement, body.GetMrTd()) {
		t.Errorf("Measurement equals raw MRTD; RTMRs are not folded in")
	}
	if bytes.Equal(rep.Measurement, make([]byte, tdxMrTdSize)) {
		t.Errorf("Measurement is all-zero")
	}

	// ReportData round-trips the verified 64-byte field.
	if len(rep.ReportData) != tdxReportDataLen {
		t.Errorf("ReportData len = %d, want %d", len(rep.ReportData), tdxReportDataLen)
	}
	if !bytes.Equal(rep.ReportData, body.GetReportData()) {
		t.Errorf("ReportData does not match the quote body")
	}

	// CompositeHash is non-zero and deterministic.
	var zero [32]byte
	if rep.CompositeHash == zero {
		t.Errorf("CompositeHash is zero")
	}
	rep2, _ := buildTDXReport(quote, applyOptions())
	if rep.CompositeHash != rep2.CompositeHash {
		t.Errorf("CompositeHash is not deterministic")
	}

	// Extra carries the raw registers for finer-grained policy/audit.
	for _, k := range []string{"tdx.mrtd", "tdx.rtmr0", "tdx.rtmr1", "tdx.rtmr2", "tdx.rtmr3", "tdx.tee_tcb_svn"} {
		if rep.Extra[k] == "" {
			t.Errorf("Extra missing key %q", k)
		}
	}
	t.Logf("TD measurement root (fold) = %x", rep.Measurement)
	t.Logf("CompositeHash             = %x", rep.CompositeHash)
}

func TestTDX_Policy_MeasurementAndReportDataBinding(t *testing.T) {
	quote := mustParseQuote(t, tdxProdQuote)
	body := quote.GetTdQuoteBody()
	goodFold := foldTDXMeasurement(body.GetMrTd(), body.GetRtmrs())
	goodRD := body.GetReportData()

	// Correct expected measurement -> accepted.
	if _, err := buildTDXReport(quote, applyOptions(WithExpectedMeasurement(goodFold))); err != nil {
		t.Errorf("correct expected measurement rejected: %v", err)
	}
	// Wrong expected measurement -> ErrPolicy.
	wrong := append([]byte(nil), goodFold...)
	wrong[0] ^= 0xFF
	if _, err := buildTDXReport(quote, applyOptions(WithExpectedMeasurement(wrong))); !errors.Is(err, ErrPolicy) {
		t.Errorf("wrong measurement: want ErrPolicy, got %v", err)
	}

	// Correct expected report data (nonce binding) -> accepted.
	if _, err := buildTDXReport(quote, applyOptions(WithExpectedReportData(goodRD))); err != nil {
		t.Errorf("correct expected report data rejected: %v", err)
	}
	// Wrong expected report data -> ErrPolicy.
	wrongRD := append([]byte(nil), goodRD...)
	wrongRD[0] ^= 0xFF
	if _, err := buildTDXReport(quote, applyOptions(WithExpectedReportData(wrongRD))); !errors.Is(err, ErrPolicy) {
		t.Errorf("wrong report data: want ErrPolicy, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Tamper rejection
// -----------------------------------------------------------------------------

// TestTDX_Tamper_MRTD_BreaksSignature flips a byte of MRTD and proves the TD
// report signature no longer verifies — i.e. the measurement is genuinely
// bound by the hardware signature, so a forged measurement is rejected.
func TestTDX_Tamper_MRTD_BreaksSignature(t *testing.T) {
	tampered := append([]byte(nil), tdxProdQuote...)
	tampered[tdxAbsMRTDOffset] ^= 0xFF

	any, err := abi.QuoteToProto(tampered)
	if err != nil {
		return // parser rejecting it is also a valid refusal
	}
	quote := any.(*tdxpb.QuoteV4)
	verr := verify.TdxQuote(quote, &verify.Options{GetCollateral: false, Now: tdxFixedNow()})
	if verr == nil {
		t.Fatal("tampered MRTD still verified — measurement not bound by signature")
	}
	if got := classifyTDXVerifyError(verr); !errors.Is(got, ErrSignatureInvalid) {
		t.Errorf("tampered MRTD: want ErrSignatureInvalid, got %v (raw: %v)", got, verr)
	}
}

// TestTDX_Tamper_Signature_Rejected flips a byte of the ECDSA signature and
// proves verification refuses.
func TestTDX_Tamper_Signature_Rejected(t *testing.T) {
	tampered := append([]byte(nil), tdxProdQuote...)
	tampered[tdxAbsSigOffset] ^= 0xFF

	any, err := abi.QuoteToProto(tampered)
	if err != nil {
		return // parser rejecting it is also a valid refusal
	}
	quote := any.(*tdxpb.QuoteV4)
	verr := verify.TdxQuote(quote, &verify.Options{GetCollateral: false, Now: tdxFixedNow()})
	if verr == nil {
		t.Fatal("tampered signature still verified")
	}
	if got := classifyTDXVerifyError(verr); !errors.Is(got, ErrSignatureInvalid) {
		t.Errorf("tampered signature: want ErrSignatureInvalid, got %v (raw: %v)", got, verr)
	}
}

// TestTDX_Reject_BadVersion proves an unsupported quote version is refused at
// the parse boundary as ErrInvalidEvidence (no getter needed).
func TestTDX_Reject_BadVersion(t *testing.T) {
	bad := append([]byte(nil), tdxProdQuote...)
	bad[0] = 0x03 // version is a little-endian uint16 at offset 0; 4 -> 3
	_, err := TDX{}.Verify(context.Background(), bad, WithNow(tdxFixedNow()))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("bad version: want ErrInvalidEvidence, got %v", err)
	}
}

// TestTDX_Reject_Truncated proves a too-short blob is refused before any trust
// decision.
func TestTDX_Reject_Truncated(t *testing.T) {
	_, err := TDX{}.Verify(context.Background(), tdxProdQuote[:abi.QuoteMinSize-1], WithNow(tdxFixedNow()))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("truncated: want ErrInvalidEvidence, got %v", err)
	}
}

// TestTDX_Reject_Garbage proves random bytes of sufficient length are refused.
func TestTDX_Reject_Garbage(t *testing.T) {
	garbage := make([]byte, abi.QuoteMinSize+16)
	for i := range garbage {
		garbage[i] = byte(i * 7)
	}
	_, err := TDX{}.Verify(context.Background(), garbage, WithNow(tdxFixedNow()))
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("garbage: want ErrInvalidEvidence, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Dispatch wiring + interface conformance
// -----------------------------------------------------------------------------

// TestTDX_DispatchRoutesToTDX proves Dispatch(KindTDX, ...) reaches this
// verifier (and, with a stale-TCB fixture, refuses just like a direct call).
func TestTDX_DispatchRoutesToTDX(t *testing.T) {
	_, err := Dispatch(context.Background(), KindTDX, tdxProdQuote,
		WithKDSGetter(tdxReplayGetter{}), WithNow(tdxFixedNow()))
	if !errors.Is(err, ErrPolicy) {
		t.Errorf("Dispatch(KindTDX): want ErrPolicy (stale TCB), got %v", err)
	}
}

func TestTDX_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := TDX{}.Verify(ctx, tdxProdQuote, WithKDSGetter(tdxReplayGetter{}), WithNow(tdxFixedNow()))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("canceled context: want context.Canceled, got %v", err)
	}
}
