// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package attest is the canonical TEE/GPU attestation verifier for the Lux
// confidential-compute control plane. It is the single attestation primitive
// shared by the MPC custody system (luxfi/mpc), the TEE custody extension
// (luxfi/tee), and the confidential-AI / proof-of-AI system (luxfi/ai). It
// depends on none of them — attestation is its own orthogonal concern.
//
// One verifier framework, orthogonal hardware Kinds. Each Kind is a complete,
// independent unit — its string tag, its Verifier implementation, and its
// init()-time self-registration live together in one file:
//
//   - KindSEVSNP (sev.go):  AMD SEV-SNP CPU. PRODUCTION. Live VCEK fetch from
//     the AMD KDS, full ARK→ASK→VCEK chain + report-signature verify via
//     google/go-sev-guest. Measurement: the 48-byte launch digest.
//   - KindTDX (tdx.go):     Intel TDX CPU. PRODUCTION. Full Intel DCAP v4 quote
//     verification via google/go-tdx-guest: PCK chain (embedded in the quote)
//     → Intel SGX Root CA, QE report signature, attestation-key binding, TD
//     report ECDSA-P256 signature, and Intel PCS collateral (TCB status +
//     revocation) — a downlevel or revoked platform is REFUSED. Measurement:
//     SHA-384(MRTD || RTMR0..3), a single 48-byte launch+runtime root.
//   - KindSGX (sgx.go):     Intel SGX enclave. PRODUCTION. Pure-Go DCAP ECDSA
//     v3 quote verification: PCK chain → pinned Intel SGX Root CA, QE report
//     signature, the DCAP attestation-key binding, and the ISV enclave-report
//     signature. Measurement: MRENCLAVE || MRSIGNER (64 bytes).
//   - KindNVTrust (nvtrust.go): NVIDIA GPU confidential compute. PRODUCTION,
//     two modes behind one Kind. ModeLocal (cloud-free): chain the GPU device
//     cert to an operator-pinned NVIDIA device root, verify the signed SPDM
//     measurement record, and match every measurement by index to an
//     NVIDIA-signed Reference Integrity Manifest. ModeNRAS: verify an NVIDIA
//     Remote Attestation Service EAT/JWT against pinned signer keys. The
//     fail-closed zero value is what self-registers; production callers build
//     a configured verifier with NewNVTrust.
//   - KindNitro (nitro.go): AWS Nitro Enclaves. PRODUCTION. CBOR/COSE_Sign1
//     (ES384) attestation-document verification, chain to the pinned AWS Nitro
//     Enclaves Root G1, with PCR / nonce / freshness policy. Measurement: PCR0
//     (the enclave image digest).
//   - KindARMCCA (armcca.go): ARM CCA realm. PRODUCTION. A CBOR/COSE CCA
//     attestation-token collection — the platform token (COSE_Sign1, signed by
//     the operator-pinned per-SoC CPAK/IAK) and the realm token (signed by the
//     realm RAK), with the platform↔realm binding H(RAK) enforced. The
//     fail-closed zero value is what self-registers; production callers set
//     ARMCCA.TrustAnchors (no pinned CPAK ⇒ refuse, no insecure mode).
//     Measurement: the realm initial measurement (RIM).
//
// Dispatch is a single registry lookup. Each Kind self-registers its verifier
// from its file's init() via registerVerifier; Dispatch and RegisteredVerifier
// resolve a Kind through that one registry. There is no switch to keep in sync,
// and an unregistered Kind is refused with ErrUnsupportedKind — fail-closed,
// never a silent pass.
//
// Layering:
//
//	caller (kms release gate, scheduler, AI trust-tier policy, indexer)
//	  └── cc/attest.Dispatch(ctx, kind, evidence, opts...)          ◄── this package
//	        │   (registry lookup — RegisteredVerifier(kind).Verify)
//	        ├── KindSEVSNP  → google/go-sev-guest + AMD KDS              (PROD)
//	        ├── KindTDX     → google/go-tdx-guest + Intel PCS (DCAP v4)  (PROD)
//	        ├── KindSGX     → pure-Go Intel DCAP ECDSA quote             (PROD)
//	        ├── KindNVTrust → attest/nvidia SPDM+device-chain+RIM (local)(PROD)
//	        │                 attest/nvidia EAT verify           (NRAS)  (PROD)
//	        ├── KindNitro   → CBOR/COSE_Sign1 → AWS Nitro Root G1        (PROD)
//	        └── KindARMCCA  → CBOR/COSE CCA platform+realm tokens        (PROD)
//
// The caller supplies the evidence Kind out-of-band (e.g. by an envelope's
// framing field) so the verifier never has to guess from byte heuristics.
// Evidence is NOT trusted until Verify returns without error: this package
// validates the chain/signature to the vendor root and extracts measurements.
//
// Security invariants:
//
//   - Trust anchors are pinned per-vendor, never trusted from the evidence
//     itself: AMD ARK/ASK ship embedded with go-sev-guest; the Intel SGX Root
//     CA is pinned (in-source for SGX, inside go-tdx-guest for TDX); the AWS
//     Nitro Enclaves Root G1 is pinned in-source and fingerprint-checked; the
//     NVIDIA device root and RIM signing keys, and the ARM CCA CPAK platform
//     keys, are operator-supplied (no insecure default — an empty root set is
//     refused).
//   - Tests do not hit the network. Vendor collateral (KDS / PCS responses,
//     RIM, EAT) is pre-fetched into testdata/ or generated against test roots,
//     and replayed via injected getters / overridden test roots.
//   - A failed verify never falls back to "best effort"; callers must treat
//     (nil, err) as "refuse the request". ErrNotImplemented is reserved for a
//     future fail-closed stub Kind and is just another refusal.
package attest
