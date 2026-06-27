// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/cc/attest/nvidia"
)

// Kind tags the evidence framing the verifier dispatches on. Each Kind's
// string tag, its Verifier implementation, and its init()-time registration
// live together in that Kind's own file — sev.go, tdx.go, sgx.go, nvtrust.go,
// nitro.go, and (pending) armcca.go. This file owns only the framework: the
// registry, Dispatch, the shared config, the common options, VerifiedReport,
// and the error taxonomy. Adding a Kind is a new file plus one init() line; no
// central edit, no switch to extend.
type Kind string

// Errors returned by the verifier package. Callers should switch on
// errors.Is to distinguish refusal classes.
var (
	// ErrUnsupportedKind is returned when evidence carries a Kind no
	// installed verifier can handle.
	ErrUnsupportedKind = errors.New("attest: unsupported evidence kind")

	// ErrInvalidEvidence is returned when the bytes do not parse as the
	// claimed Kind. The C-ABI parser usually catches this earlier; we
	// recheck because the parser is C and we are about to make trust
	// decisions on its output.
	ErrInvalidEvidence = errors.New("attest: evidence failed to parse")

	// ErrChainInvalid is returned when the cryptographic chain from the
	// signing key (VCEK / PCK / NRAS signer) up to the vendor root
	// fails to validate.
	ErrChainInvalid = errors.New("attest: vendor chain validation failed")

	// ErrSignatureInvalid is returned when the report signature does not
	// match the verified leaf certificate.
	ErrSignatureInvalid = errors.New("attest: report signature invalid")

	// ErrPolicy is returned when the caller-supplied policy (expected
	// measurement, expected report data, max age) rejects the evidence
	// despite a cryptographically valid chain.
	ErrPolicy = errors.New("attest: policy rejected verified evidence")

	// ErrNotImplemented is the refusal sentinel a stub verifier returns so
	// it fails loud instead of silently passing evidence it never checked.
	// No shipped Kind is a stub today (SEV-SNP, TDX, SGX, NVTrust, and Nitro
	// are all real); the sentinel stays part of the API so a future Kind can
	// land as a fail-closed stub with its own test before its crypto does.
	// Callers must treat it exactly like any other refusal: do not release,
	// do not fall back.
	ErrNotImplemented = errors.New("attest: verifier not yet implemented")
)

// VerifiedReport is the canonical post-verification view of an evidence
// blob. Fields are kind-agnostic where possible; kind-specific fields
// land in the dedicated maps and are interpreted by the caller.
//
// CompositeHash is sha256(kind || verified-canonical-bytes). It is the
// integrity anchor a release gate, scheduler, or indexer logs as the
// attestation root. Two evidences with the same CompositeHash are
// guaranteed to have produced identical verifier output.
type VerifiedReport struct {
	// Kind echoes the verifier that produced this report.
	Kind Kind

	// Vendor is the canonical issuer ("amd.sev.snp", "intel.tdx",
	// "nvidia.nras.v1"). Stable across the wire.
	Vendor string

	// Measurement is the launch-measurement bytes the TEE attests to.
	// SEV-SNP: 48 bytes of LD digest. TDX: MRTD. NRAS: a derived
	// per-driver+VBIOS digest (defined per-verifier).
	Measurement []byte

	// ReportData is the 64-byte caller-supplied challenge field
	// (REPORT_DATA on SEV-SNP, REPORTDATA on TDX). The caller proved
	// freshness by binding their nonce here BEFORE attestation.
	ReportData []byte

	// HostData is the 32-byte host-supplied data field on SEV-SNP, or
	// equivalent on TDX. nil for verifiers that don't define it.
	HostData []byte

	// ChipID identifies the silicon: VCEK CHIP_ID on SEV-SNP, the PCK
	// platform descriptor on TDX, or per-GPU UUID on NRAS.
	ChipID []byte

	// IssuedAt is the verifier's wall-clock at successful verify. The
	// evidence itself does not in general carry an issued-at; this is
	// the time the chain check completed.
	IssuedAt time.Time

	// CompositeHash is sha256(string(Kind) || canonical(verified-bytes)).
	// See package doc. Logged by callers as the attestation root.
	CompositeHash [32]byte

	// Extra carries kind-specific fields that don't fit the common
	// shape. Keys are stable strings prefixed by the kind ("sev_snp.tcb",
	// "nras.driver_version", ...). Treated opaquely by callers that
	// don't recognise them.
	Extra map[string]string
}

// Option mutates verification policy for a single Verify call. Options
// compose; later options win on conflict.
type Option func(*config)

type config struct {
	// expectedReportData, if set, is compared byte-for-byte against the
	// REPORT_DATA / REPORTDATA field of the evidence. Length must match
	// the kind's natural size or the verifier returns ErrPolicy.
	expectedReportData []byte

	// expectedMeasurement, if set, must equal the verified Measurement.
	expectedMeasurement []byte

	// now is the wall clock to use for revocation / not-after checks.
	// Tests pin this; production leaves it zero so verifiers use
	// time.Now.
	now time.Time

	// kdsGetter is an HTTPSGetter override for SEV-SNP. Tests inject a
	// pre-populated map so the test suite does not hit the AMD KDS.
	// Production leaves this nil so the live AMD KDS is used.
	kdsGetter any // verify/trust.HTTPSGetter; typed in sev.go to avoid leaking the dep here

	// nvtrustRIM is the signed NVIDIA Reference Integrity Manifest the GPU
	// evidence must match. Required for KindNVTrust; ignored by other kinds.
	nvtrustRIM []byte

	// nvtrustTrustRoots are the public keys that may have signed the RIM.
	// Required for KindNVTrust; the verifier refuses an empty set (no
	// insecure mode).
	nvtrustTrustRoots []nvidia.TrustRoot

	// nitroRoots overrides the trust anchor for the KindNitro certificate
	// chain. Holds a *x509.CertPool; kept as any so verifier.go need not
	// import crypto/x509 (mirrors kdsGetter). nil ⇒ the pinned AWS Nitro
	// Enclaves root. Tests set a generated root; production leaves it nil.
	nitroRoots any

	// nitroExpectedPCRs, if non-empty, pins required KindNitro PCR values by
	// index. Every supplied index must be present and equal, or ErrPolicy.
	nitroExpectedPCRs map[uint][]byte

	// nitroMaxAge, if > 0, bounds KindNitro document freshness against the
	// document timestamp. Zero ⇒ no age bound.
	nitroMaxAge time.Duration
}

// nowOrWall returns the pinned verification clock when set, else the wall
// clock. Tests pin now via WithNow against committed fixtures; production
// leaves it zero.
func (c config) nowOrWall() time.Time {
	if !c.now.IsZero() {
		return c.now
	}
	return time.Now()
}

// WithExpectedReportData binds the verifier to refuse evidence whose
// REPORT_DATA does not equal want. Use this to enforce that the
// challenge nonce the gate issued was actually included in the quote.
func WithExpectedReportData(want []byte) Option {
	return func(c *config) {
		buf := make([]byte, len(want))
		copy(buf, want)
		c.expectedReportData = buf
	}
}

// WithExpectedMeasurement binds the verifier to refuse evidence whose
// MEASUREMENT does not equal want. Use to pin a known-good launch
// digest.
func WithExpectedMeasurement(want []byte) Option {
	return func(c *config) {
		buf := make([]byte, len(want))
		copy(buf, want)
		c.expectedMeasurement = buf
	}
}

// WithNow pins the verification clock. Production callers should not
// use this; it exists for deterministic tests against committed
// fixtures whose certificates have a fixed validity window.
func WithNow(t time.Time) Option {
	return func(c *config) { c.now = t }
}

// WithKDSGetter installs a custom HTTPSGetter for the certificate-fetching
// CPU paths. It is shared by SEV-SNP (AMD KDS) and TDX (Intel PCS/PCCS):
// tests inject a replay map so the suite runs offline, production leaves it
// nil so the live vendor service is used. The argument must implement the
// relevant go-{sev,tdx}-guest verify/trust.HTTPSGetter; the type is checked
// at each verifier boundary. Kind-specific options (WithNVTrust*, WithNitro*)
// live in their own files.
func WithKDSGetter(g any) Option {
	return func(c *config) { c.kdsGetter = g }
}

// Verifier verifies a single evidence blob.
//
// Verify means: bytes parse as the claimed Kind, the signing key chains
// to the pinned vendor root, the report signature is cryptographically
// valid, and any caller-supplied policy options pass. On success a
// VerifiedReport is returned with measurements extracted and the
// composite hash computed; on any failure the error is non-nil and the
// pointer is nil.
//
// Implementations MUST NOT return a partial VerifiedReport on error.
// Callers MUST refuse the originating request on any non-nil error.
type Verifier interface {
	Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error)
}

// -----------------------------------------------------------------------------
// Verifier registry — the single dispatch authority.
//
// Each Kind self-registers its verifier from its own file's init() via
// registerVerifier. Dispatch and RegisteredVerifier are the only ways to reach
// a verifier by Kind; there is no switch to keep in sync. An unregistered Kind
// is refused with ErrUnsupportedKind — fail-closed, never a silent pass.
// -----------------------------------------------------------------------------

var (
	registryMu sync.RWMutex
	registry   = map[Kind]Verifier{}
)

// registerVerifier installs v as the verifier for kind. It is called from a
// Kind file's init(); each Kind is registered in exactly one place. A
// duplicate registration is a programmer error that fails loud at startup
// rather than silently shadowing a verifier on the trust path.
func registerVerifier(kind Kind, v Verifier) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[kind]; dup {
		panic(fmt.Sprintf("attest: duplicate verifier registration for kind %q", kind))
	}
	registry[kind] = v
}

// RegisteredVerifier returns the verifier a Kind self-registered via init(),
// or (nil, false) when no verifier is installed for kind.
func RegisteredVerifier(kind Kind) (Verifier, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	v, ok := registry[kind]
	return v, ok
}

// Dispatch routes evidence to the verifier registered for kind. Kind is
// supplied out-of-band (e.g. by an evidence envelope's framing field) so the
// verifier never has to guess from byte heuristics. Routing is a single
// registry lookup — an unregistered Kind is refused with ErrUnsupportedKind,
// never a silent pass.
func Dispatch(ctx context.Context, kind Kind, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	v, ok := RegisteredVerifier(kind)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKind, string(kind))
	}
	return v.Verify(ctx, evidence, opts...)
}

// applyOptions builds an immutable config from defaults + opts.
func applyOptions(opts ...Option) config {
	c := config{}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// computeCompositeHash returns sha256(kind || canonical-bytes). The
// canonical bytes are the verifier-extracted, deterministic
// representation — never the raw evidence. This guarantees that a
// caller logging CompositeHash logs a value that was attested-to AND
// chain-validated, not whatever the wire happened to carry.
func computeCompositeHash(kind Kind, canonical []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(kind))
	h.Write([]byte{0x00}) // domain separator: zero byte between fields
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
