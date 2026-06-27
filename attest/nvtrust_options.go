// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/luxfi/cc/attest/nvidia"
)

// NVTrustOption configures a NVTrust verifier at construction. These set
// the per-DEPLOYMENT trust anchors and mode — distinct from the per-CALL
// policy Options (WithNVTrustRIM, WithExpectedReportData, ...) passed to
// Verify. Trust anchors live on the instance because they are pinned once
// at startup and never vary per request; the RIM blob and freshness
// challenge vary per request and stay per-call.
type NVTrustOption func(*NVTrust)

// NewNVTrust builds a configured NVTrust verifier. The result implements
// Verifier and is the production entry point; the zero value (used by
// Dispatch) is intentionally fail-closed.
//
// Registration note: this module dispatches Kinds through the switch in
// Dispatch (KindNVTrust -> NVTrust{}). There is no init()-based registry in
// the base module, so a configured verifier is wired by the caller (the kms
// release gate / ai trust-tier policy) constructing NewNVTrust and using it
// as a Verifier. If the dispatch layer later becomes an init-registry, the
// nvtrust registration is one line — register NewNVTrust(defaults) — and
// belongs in this file.
func NewNVTrust(opts ...NVTrustOption) NVTrust {
	var n NVTrust // zero value: ModeLocal, no roots (fail-closed)
	for _, o := range opts {
		o(&n)
	}
	return n
}

// WithNVTrustMode selects ModeLocal (default) or ModeNRAS.
func WithNVTrustMode(m NVTrustMode) NVTrustOption {
	return func(n *NVTrust) { n.mode = m }
}

// WithNVTrustDeviceRoots pins the NVIDIA device-identity root CA pool that
// the GPU attestation leaf certificate must chain to in ModeLocal. The
// operator loads NVIDIA's published device root PEM here at startup. An
// unset pool makes ModeLocal refuse — there is no insecure mode.
func WithNVTrustDeviceRoots(pool *x509.CertPool) NVTrustOption {
	return func(n *NVTrust) { n.deviceRoots = pool }
}

// WithNVTrustNRASRoots pins the NRAS EAT signer public keys (looked up by
// the token's JWS kid) used in ModeNRAS.
func WithNVTrustNRASRoots(roots []nvidia.TrustRoot) NVTrustOption {
	return func(n *NVTrust) {
		n.nrasRoots = append([]nvidia.TrustRoot(nil), roots...)
	}
}

// WithNVTrustNRASRootCAs pins the NRAS root CA pool used to validate an EAT
// token's x5c certificate chain in ModeNRAS. Optional: when set and a token
// carries x5c, the chain is anchored here and the leaf key verifies the
// token; otherwise the kid-pinned WithNVTrustNRASRoots path is used.
func WithNVTrustNRASRootCAs(pool *x509.CertPool) NVTrustOption {
	return func(n *NVTrust) { n.nrasRootPool = pool }
}

// WithNVTrustClock sets the instance verification clock. Production leaves
// this unset (wall clock); tests pin it. Per-call WithNow still overrides.
func WithNVTrustClock(fn func() time.Time) NVTrustOption {
	return func(n *NVTrust) { n.now = fn }
}

// ErrNVTrustNoRootPEM is returned when a device-root PEM contains no
// usable certificate.
var ErrNVTrustNoRootPEM = errors.New("nvtrust: no certificate found in device-root PEM")

// NVTrustDeviceRootsFromPEM is an operator convenience that builds a
// device-root pool from one or more concatenated PEM certificates (NVIDIA's
// published device-identity root). It refuses an empty/garbage PEM so a
// misconfiguration fails loud at startup rather than silently producing an
// empty pool.
func NVTrustDeviceRootsFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, ErrNVTrustNoRootPEM
	}
	return pool, nil
}
