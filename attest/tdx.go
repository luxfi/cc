// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"fmt"
)

// TDX is the Intel TDX verifier.
//
// Status: STUB — tracked at issue #222 stage 2.
//
// Production plan (intentionally not yet implemented):
//
//   - Parse the TDREPORT / quote via github.com/google/go-tdx-guest/abi.
//   - Fetch the PCK (Provisioning Certification Key) chain from the
//     Intel PCS at api.trustedservices.intel.com using the report's
//     FMSPC + PCEID.
//   - Validate the chain to Intel's pinned root certificate and check
//     the report signature against the PCK.
//   - Cross-check the QE Identity and TDX Module Identity against the
//     pinned values published by Intel.
//   - Extract MRTD, RTMRs, REPORTDATA, and the platform identity.
//   - Compose CompositeHash via the same domain-separated SHA-256 as
//     the SEV path (see verifier.go::computeCompositeHash).
//
// Verify returns ErrNotImplemented so the call site refuses the release
// without crashing the process. Callers MUST treat this exactly like
// any other refusal: do not release, do not fall back. A silent no-op
// or success would let the release gate accidentally accept evidence
// the verifier has not actually checked; the explicit error-return path
// preserves the same hard-refusal guarantee while letting Dispatch be
// invoked from request-handling goroutines without taking the whole
// process down.
type TDX struct{}

// Verify implements Verifier. NOT YET IMPLEMENTED — do not enable TDX
// dispatch in production until #222 stage 2 lands.
func (TDX) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	return nil, fmt.Errorf("%w: TDX attestation envelope verification not configured for this build (tracked at #222 stage 2: go-tdx-guest + Intel PCS)",
		ErrNotImplemented)
}

var _ Verifier = TDX{}
