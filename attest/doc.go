// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package attest is the canonical TEE/GPU attestation verifier for the Lux
// confidential-compute control plane. It is the single attestation primitive
// shared by the MPC custody system (luxfi/mpc), the TEE custody extension
// (luxfi/tee), and the confidential-AI / proof-of-AI system (luxfi/ai). It
// depends on none of them — attestation is its own orthogonal concern.
//
// One verifier, orthogonal hardware Kinds:
//   - KindSEVSNP:  AMD SEV-SNP CPU. PRODUCTION (live VCEK fetch from AMD KDS,
//                  full ARK→ASK→VCEK chain + report-signature verify).
//   - KindTDX:     Intel TDX CPU. STUB (tracked at #222 stage 2; go-tdx-guest
//                  + Intel PCS).
//   - KindNVTrust: NVIDIA GPU confidential compute. PRODUCTION local-RIM mode
//                  (cloud-free): parse the GPU evidence envelope, verify the
//                  NVIDIA-signed Reference Integrity Manifest against the
//                  operator-pinned key, and match every reported measurement
//                  to the signed golden value. See nvtrust.go for the honest
//                  scope (RIM-signature + measurement integrity; device-cert
//                  SPDM chaining is the remote nvidia.NRASClient primitive).
//
// Layering:
//
//	caller (kms release gate, scheduler, AI trust-tier policy, indexer)
//	  └── cc/attest.Verifier.Verify(ctx, evidence, opts...)        ◄── this package
//	        ├── SEV-SNP    → google/go-sev-guest + AMD KDS         (PROD)
//	        ├── Intel TDX  → google/go-tdx-guest + Intel PCS       (STUB)
//	        └── NVIDIA GPU → attest/nvidia RIM-match (local)       (PROD)
//	                         attest/nvidia.NRASClient (remote)     (primitive)
//
// The caller supplies the evidence Kind out-of-band (e.g. by an envelope's
// framing field) so the verifier never has to guess from byte heuristics.
// Evidence is NOT trusted until Verify returns without error: this package
// validates the chain/signature to the vendor root and extracts measurements.
//
// Security invariants:
//
//   - Trust anchors are pinned per-vendor, never trusted from the evidence
//     itself: AMD ARK/ASK ship embedded with go-sev-guest; the NVIDIA RIM
//     signing key is operator-supplied via WithNVTrustTrustRoots (no
//     insecure default — an empty root set is refused).
//   - Tests do not hit the network. KDS responses are pre-fetched
//     into testdata/ and replayed via a SimpleGetter map.
//   - A failed verify never falls back to "best effort"; callers must
//     treat (nil, err) as "refuse the request".
package attest
