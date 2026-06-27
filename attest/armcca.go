// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	cbor "github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// KindARMCCA tags ARM Confidential Compute Architecture (CCA) Realm
// attestation evidence: a CBOR/COSE attestation-token collection produced by
// the Realm Management Monitor (RMM) under the Realm Management Extension
// (RME). See the ARMCCA verifier below for the wire shape and trust model.
const KindARMCCA Kind = "arm_cca"

// Top-level CBOR tags that frame a CCA attestation-token collection. A CCA
// token bundles two COSE_Sign1 tokens — the CCA platform token and the realm
// token — under one of these tags. Both are accepted; they differ only in the
// envelope, never in the inner tokens.
const (
	// tagCCACMW is the current CMW collection framing
	// (draft-ietf-rats-msg-wrap). Each map value is a CoAP-content-format-
	// tagged [int, bstr] pair whose bstr is the COSE_Sign1.
	tagCCACMW uint64 = 907
	// tagCCAEAT is the legacy EAT collection framing. Each map value is the
	// COSE_Sign1 bstr directly. Retained because deployed RMM firmware (e.g.
	// Trusted Firmware) still emits it.
	tagCCAEAT uint64 = 399
)

// CCA token CWT claim labels. The realm and platform tokens are CBOR Web
// Tokens whose claims are keyed by these integer labels (ARM CCA token format,
// aligned with the Veraison CCA reference). The challenge (10) and profile
// (265) labels are shared by both tokens; the rest are token-specific.
const (
	labelChallenge int64 = 10  // CWT nonce: platform binder / realm freshness
	labelProfile   int64 = 265 // EAT profile; presence selects the RAK encoding

	// CCA realm token claims.
	labelRealmInitialMeasurement int64 = 44238 // RIM
	labelRealmExtensibleMeas     int64 = 44239 // REM[]
	labelRealmHashAlgID          int64 = 44236
	labelRealmPubKey             int64 = 44237 // RAK
	labelRealmPubKeyHashAlgID    int64 = 44240 // binding hash algorithm

	// CCA platform token claims.
	labelPlatformInstID    int64 = 256
	labelPlatformConfig    int64 = 2401
	labelPlatformLifeCycle int64 = 2395
)

// ARMCCA verifies an ARM CCA Realm attestation-token collection per the IETF
// RATS model and the ARM CCA token format.
//
// # Wire shape
//
//	collection (CBOR tag 907 CMW, or tag 399 legacy EAT)
//	  ├─ 44234 → CCA platform token  (COSE_Sign1, signed by the CPAK)
//	  └─ 44241 → CCA realm token      (COSE_Sign1, signed by the RAK)
//
// The platform token is a CWT describing the platform (monitor/RMM + root
// world), signed by the silicon-provisioned CCA Platform Attestation Key
// (CPAK, a.k.a. IAK). The realm token is a CWT describing one Realm, signed by
// a per-Realm Realm Attestation Key (RAK) that the RMM generates and embeds in
// the realm claims. The platform token's challenge claim binds the two: it
// equals H(RAK), so a CPAK-rooted platform vouches for exactly this realm's
// signing key.
//
// # What Verify checks
//
//  1. The platform token COSE_Sign1 signature, against an operator-pinned CPAK
//     in TrustAnchors. (cryptographic chain to the ARM CCA root of trust)
//  2. The realm token COSE_Sign1 signature, against the RAK extracted from the
//     realm claims.
//  3. The platform↔realm binding: platform nonce == H_alg(RAK), where alg is
//     the realm's declared public-key hash algorithm. (a forged or mismatched
//     realm token is refused even when both signatures are individually valid)
//  4. The realm initial measurement (RIM) and extensible measurements (REM),
//     and the CCA platform config claim.
//  5. Freshness: the realm challenge claim is the relying party's nonce; pin
//     it with WithExpectedReportData. Pin the RIM with WithExpectedMeasurement.
//
// On success the RIM lands in VerifiedReport.Measurement, the realm challenge
// in ReportData, and the platform instance-id in ChipID. The REMs, config,
// lifecycle, and profiles land in Extra.
//
// # Implementation
//
// Built on exactly the two primitives of the Veraison/ARM CCA stack: CBOR
// (github.com/fxamacker/cbor/v2) for the collection envelope and CWT claim
// maps, and COSE (github.com/veraison/go-cose) for COSE_Sign1 signature
// verification and the COSE_Key realm-key decode. No higher-level token
// library is pulled into the trusted path; the claim labels are pinned here
// and cross-checked against the canonical reference in the test suite.
//
// # Trust model (the honest production scope)
//
// Unlike AMD SEV-SNP — where go-sev-guest embeds AMD's ARK and fetches the
// VCEK chain from the AMD KDS — there is NO universal ARM root baked into any
// library. The CPAK is provisioned per-SoC by the silicon vendor and endorsed
// out-of-band (a CCA platform endorsement / CoRIM from the vendor, or the
// platform's Hardware Enforced Security subsystem). The relying party MUST
// obtain the authentic CPAK public key through that supply chain and pin it in
// TrustAnchors. An empty TrustAnchors set is refused — there is no insecure
// mode, exactly as KindNVTrust refuses an empty trust-root set.
//
// This verifier proves the token is cryptographically authentic, internally
// consistent, bound, and fresh. It does NOT, on its own, judge whether the
// extracted RIM/REM/config correspond to a known-good Realm + platform image:
// that is reference-values policy (a CCA CoRIM from the Realm owner), supplied
// here as WithExpectedMeasurement or enforced by a matcher above this verifier.
// CPAK endorsement revocation is likewise an out-of-band concern. These are
// documented, not stubbed: the cryptographic verification is complete and real.
//
// TrustAnchors are construction-time configuration on the verifier value
// (the package centralises per-call policy options in verifier.go's config,
// which this Kind does not modify); per-call freshness/measurement policy
// still flows through the shared WithExpected* options.
type ARMCCA struct {
	// TrustAnchors are the operator-pinned CCA platform attestation public
	// keys (CPAK/IAK). The platform token must be signed by one of them.
	// Empty ⇒ Verify refuses with ErrPolicy. ECDSA P-256/P-384 keys, as
	// delivered by x509.ParsePKIXPublicKey, are the expected element type.
	TrustAnchors []crypto.PublicKey
}

// Verify implements Verifier for ARM CCA Realm attestation tokens.
func (v ARMCCA) Verify(ctx context.Context, evidence []byte, opts ...Option) (*VerifiedReport, error) {
	cfg := applyOptions(opts...)

	// No insecure mode: a pinned CPAK is mandatory. Refuse rather than fall
	// back to trusting whatever signed the platform token.
	if len(v.TrustAnchors) == 0 {
		return nil, fmt.Errorf("%w: arm cca requires pinned platform trust anchors (ARMCCA.TrustAnchors)", ErrPolicy)
	}

	// 1. Parse the collection envelope (CMW tag 907 or legacy EAT tag 399)
	//    into the two raw COSE_Sign1 tokens.
	platformTok, realmTok, err := decodeCCACollection(evidence)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}

	// 2. Verify the platform token signature against a pinned CPAK. This is
	//    the chain to the ARM CCA root of trust.
	platformSign1, err := decodeCOSESign1(platformTok)
	if err != nil {
		return nil, fmt.Errorf("%w: platform token: %v", ErrInvalidEvidence, err)
	}
	if err := verifyCOSESign1(platformSign1, v.TrustAnchors); err != nil {
		return nil, fmt.Errorf("platform token: %w", err)
	}

	// 3. Decode the (now signature-verified) platform claims.
	platformClaims, err := decodeClaimSet(platformSign1.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: platform claims: %v", ErrInvalidEvidence, err)
	}

	// 4. Decode the realm token + claims and extract the RAK. The RAK is
	//    self-asserted by the realm token; it only becomes trusted once the
	//    binding (step 6) ties it to the CPAK-rooted platform token.
	realmSign1, err := decodeCOSESign1(realmTok)
	if err != nil {
		return nil, fmt.Errorf("%w: realm token: %v", ErrInvalidEvidence, err)
	}
	realmClaims, err := decodeClaimSet(realmSign1.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: realm claims: %v", ErrInvalidEvidence, err)
	}
	rak, err := extractRAK(realmClaims)
	if err != nil {
		return nil, fmt.Errorf("%w: realm public key: %v", ErrInvalidEvidence, err)
	}

	// 5. Verify the realm token signature against the RAK.
	if err := verifyCOSESign1(realmSign1, []crypto.PublicKey{rak}); err != nil {
		return nil, fmt.Errorf("realm token: %w", err)
	}

	// 6. Verify the platform↔realm binding: platform nonce == H_alg(RAK).
	if err := checkCCABinding(platformClaims, realmClaims); err != nil {
		return nil, err
	}

	// 7. Extract the measurements and the freshness nonce.
	rim, ok := realmClaims.bytes(labelRealmInitialMeasurement)
	if !ok {
		return nil, fmt.Errorf("%w: realm initial measurement claim missing", ErrInvalidEvidence)
	}
	challenge, ok := realmClaims.bytes(labelChallenge)
	if !ok {
		return nil, fmt.Errorf("%w: realm challenge claim missing", ErrInvalidEvidence)
	}

	// 8. Caller policy on the verified fields.
	if cfg.expectedReportData != nil {
		if subtle.ConstantTimeCompare(cfg.expectedReportData, challenge) != 1 {
			return nil, fmt.Errorf("%w: realm challenge mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(challenge))
		}
	}
	if cfg.expectedMeasurement != nil {
		if subtle.ConstantTimeCompare(cfg.expectedMeasurement, rim) != 1 {
			return nil, fmt.Errorf("%w: realm initial measurement mismatch (got %s)",
				ErrPolicy, hex.EncodeToString(rim))
		}
	}

	instID, _ := platformClaims.bytes(labelPlatformInstID)

	out := &VerifiedReport{
		Kind:        KindARMCCA,
		Vendor:      "arm.cca",
		Measurement: cloneBytes(rim),
		ReportData:  cloneBytes(challenge),
		ChipID:      cloneBytes(instID),
		IssuedAt:    cfg.nowOrWall().UTC(),
		Extra:       buildCCAExtra(platformClaims, realmClaims),
	}
	out.CompositeHash = computeCompositeHash(KindARMCCA, canonicalCCABytes(platformClaims, realmClaims))
	return out, nil
}

// ccaClaimSet is a decoded CWT claims map keyed by integer label. Values are
// kept raw so each is decoded into its concrete type only on demand.
type ccaClaimSet map[int64]cbor.RawMessage

// decodeClaimSet decodes a COSE_Sign1 payload (a CWT claims map) into a
// label-keyed claim set.
func decodeClaimSet(payload []byte) (ccaClaimSet, error) {
	var m ccaClaimSet
	if err := cbor.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, errors.New("empty claim set")
	}
	return m, nil
}

func (c ccaClaimSet) has(label int64) bool {
	_, ok := c[label]
	return ok
}

// bytes decodes the claim at label as a CBOR byte string. Returns false if the
// claim is absent or is not a byte string.
func (c ccaClaimSet) bytes(label int64) ([]byte, bool) {
	raw, ok := c[label]
	if !ok {
		return nil, false
	}
	var b []byte
	if err := cbor.Unmarshal(raw, &b); err != nil {
		return nil, false
	}
	return b, true
}

// text decodes the claim at label as a CBOR text string.
func (c ccaClaimSet) text(label int64) (string, bool) {
	raw, ok := c[label]
	if !ok {
		return "", false
	}
	var s string
	if err := cbor.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// sliceBytes decodes the claim at label as a CBOR array of byte strings.
func (c ccaClaimSet) sliceBytes(label int64) ([][]byte, bool) {
	raw, ok := c[label]
	if !ok {
		return nil, false
	}
	var s [][]byte
	if err := cbor.Unmarshal(raw, &s); err != nil {
		return nil, false
	}
	return s, true
}

// uintVal decodes the claim at label as a CBOR unsigned integer.
func (c ccaClaimSet) uintVal(label int64) (uint64, bool) {
	raw, ok := c[label]
	if !ok {
		return 0, false
	}
	var u uint64
	if err := cbor.Unmarshal(raw, &u); err != nil {
		return 0, false
	}
	return u, true
}

// decodeCCACollection unwraps the CBOR collection (CMW tag 907 or legacy EAT
// tag 399) and returns the two inner COSE_Sign1 tokens. It tolerates no other
// top-level tag: the framing is supplied out-of-band by the Kind, so an
// unexpected tag is corruption, not an alternate format to sniff.
func decodeCCACollection(evidence []byte) (platformToken, realmToken []byte, err error) {
	var tag cbor.RawTag
	if err := tag.UnmarshalCBOR(evidence); err != nil {
		return nil, nil, fmt.Errorf("not a tagged CCA collection: %w", err)
	}

	switch tag.Number {
	case tagCCACMW:
		// CMW: each label maps to [coap-content-format, token-bstr].
		var c struct {
			Platform cmwEntry `cbor:"44234,keyasint"`
			Realm    cmwEntry `cbor:"44241,keyasint"`
		}
		if err := cbor.Unmarshal(tag.Content, &c); err != nil {
			return nil, nil, fmt.Errorf("decoding CMW collection: %w", err)
		}
		if len(c.Platform.Token) == 0 || len(c.Realm.Token) == 0 {
			return nil, nil, errors.New("CMW collection missing platform or realm token")
		}
		return c.Platform.Token, c.Realm.Token, nil

	case tagCCAEAT:
		// Legacy EAT: each label maps directly to the token bstr.
		var c struct {
			Platform []byte `cbor:"44234,keyasint"`
			Realm    []byte `cbor:"44241,keyasint"`
		}
		if err := cbor.Unmarshal(tag.Content, &c); err != nil {
			return nil, nil, fmt.Errorf("decoding EAT collection: %w", err)
		}
		if len(c.Platform) == 0 || len(c.Realm) == 0 {
			return nil, nil, errors.New("EAT collection missing platform or realm token")
		}
		return c.Platform, c.Realm, nil

	default:
		return nil, nil, fmt.Errorf("unexpected top-level CBOR tag %d (want %d CMW or %d EAT)",
			tag.Number, tagCCACMW, tagCCAEAT)
	}
}

// cmwEntry is one CMW collection value: a [coap-content-format, token] array.
// The content format (263 = application/eat+cwt for these tokens) is parsed
// for completeness but not load-bearing; the inner bstr is the COSE_Sign1.
type cmwEntry struct {
	_        struct{} `cbor:",toarray"`
	CoapType int
	Token    []byte
}

// decodeCOSESign1 parses a tagged COSE_Sign1 (CBOR tag 18) token.
func decodeCOSESign1(token []byte) (*cose.Sign1Message, error) {
	m := cose.NewSign1Message()
	if err := m.UnmarshalCBOR(token); err != nil {
		return nil, err
	}
	return m, nil
}

// verifyCOSESign1 verifies m's signature against the first candidate public
// key that both matches the token's declared COSE algorithm and validates the
// signature. CCA uses a zero-length external_aad. A token whose algorithm
// header is unreadable is ErrInvalidEvidence; a token no pinned key can verify
// is ErrSignatureInvalid.
func verifyCOSESign1(m *cose.Sign1Message, candidates []crypto.PublicKey) error {
	alg, err := m.Headers.Protected.Algorithm()
	if err != nil {
		return fmt.Errorf("%w: unreadable COSE algorithm: %v", ErrInvalidEvidence, err)
	}
	var lastErr error
	for _, key := range candidates {
		verifier, verr := cose.NewVerifier(alg, key)
		if verr != nil {
			lastErr = verr
			continue
		}
		if verr := m.Verify(nil, verifier); verr == nil {
			return nil
		} else {
			lastErr = verr
		}
	}
	return fmt.Errorf("%w: no pinned key verified the COSE_Sign1 (alg %v): %v",
		ErrSignatureInvalid, alg, lastErr)
}

// extractRAK decodes the Realm Attestation Key from the realm claims. The
// encoding depends on the presence of a realm profile claim: profile present ⇒
// CBOR-encoded COSE_Key; profile absent (legacy RMM) ⇒ raw 0x04||X||Y P-384
// point. This mirrors the ARM CCA token format exactly.
func extractRAK(realmClaims ccaClaimSet) (*ecdsa.PublicKey, error) {
	raw, ok := realmClaims.bytes(labelRealmPubKey)
	if !ok {
		return nil, errors.New("realm public key claim missing or malformed")
	}
	if realmClaims.has(labelProfile) {
		return ecdsaFromCOSEKey(raw)
	}
	return ecdsaFromRawP384(raw)
}

// ecdsaFromRawP384 decodes a raw 0x04||X||Y uncompressed P-384 point. The
// stdlib unmarshal rejects points that are not on the curve, foreclosing
// invalid-curve attacks on the realm signature check.
func ecdsaFromRawP384(b []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P384(), b) //nolint:staticcheck // uncompressed-point decode + on-curve check
	if x == nil {
		return nil, errors.New("realm public key is not a valid P-384 point")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
}

// ecdsaFromCOSEKey decodes a CBOR COSE_Key (EC2) into an ECDSA public key.
func ecdsaFromCOSEKey(b []byte) (*ecdsa.PublicKey, error) {
	var k cose.Key
	if err := k.UnmarshalCBOR(b); err != nil {
		return nil, err
	}
	if k.Type != cose.KeyTypeEC2 {
		return nil, fmt.Errorf("realm COSE_Key is not EC2 (type %v)", k.Type)
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	epk, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("realm COSE_Key is not an ECDSA public key")
	}
	return epk, nil
}

// checkCCABinding enforces the realm↔platform binding: the platform token's
// nonce claim must equal H_alg(RAK), where alg is the realm's declared
// public-key hash algorithm and RAK is the raw realm-public-key claim bytes.
// This is what makes a CPAK-rooted platform token vouch for THIS realm's
// signing key; without it, any valid realm token could be paired with any
// valid platform token. A mismatch is a broken chain (ErrChainInvalid).
func checkCCABinding(platformClaims, realmClaims ccaClaimSet) error {
	rak, ok := realmClaims.bytes(labelRealmPubKey)
	if !ok {
		return fmt.Errorf("%w: realm public key missing for binding", ErrInvalidEvidence)
	}
	algID, ok := realmClaims.text(labelRealmPubKeyHashAlgID)
	if !ok {
		return fmt.Errorf("%w: realm public-key hash algorithm missing", ErrInvalidEvidence)
	}
	h, err := ccaHashByName(algID)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	h.Write(rak)
	binder := h.Sum(nil)

	nonce, ok := platformClaims.bytes(labelChallenge)
	if !ok {
		return fmt.Errorf("%w: platform nonce claim missing", ErrInvalidEvidence)
	}
	if subtle.ConstantTimeCompare(binder, nonce) != 1 {
		return fmt.Errorf("%w: platform nonce does not match H_%s(RAK)", ErrChainInvalid, algID)
	}
	return nil
}

// ccaHashByName maps a CCA hash-algorithm string to a fresh hash.Hash. The
// set matches the algorithms the ARM CCA token format admits for the RAK hash.
func ccaHashByName(name string) (hash.Hash, error) {
	switch name {
	case "sha-224":
		return sha256.New224(), nil
	case "sha-256":
		return sha256.New(), nil
	case "sha-384":
		return sha512.New384(), nil
	case "sha-512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported CCA hash algorithm %q", name)
	}
}

// buildCCAExtra collects CCA-specific fields that don't fit the common shape.
// Keys are stable wire identifiers prefixed "arm_cca.".
func buildCCAExtra(platformClaims, realmClaims ccaClaimSet) map[string]string {
	extra := make(map[string]string, 10)

	if p, ok := platformClaims.text(labelProfile); ok && p != "" {
		extra["arm_cca.platform_profile"] = p
	}
	if p, ok := realmClaims.text(labelProfile); ok && p != "" {
		extra["arm_cca.realm_profile"] = p
	}
	if cfg, ok := platformClaims.bytes(labelPlatformConfig); ok && len(cfg) > 0 {
		extra["arm_cca.platform_config"] = hex.EncodeToString(cfg)
	}
	if lc, ok := platformClaims.uintVal(labelPlatformLifeCycle); ok {
		extra["arm_cca.platform_lifecycle"] = fmt.Sprintf("%#04x", lc)
	}
	if alg, ok := realmClaims.text(labelRealmHashAlgID); ok && alg != "" {
		extra["arm_cca.realm_hash_alg"] = alg
	}
	if alg, ok := realmClaims.text(labelRealmPubKeyHashAlgID); ok && alg != "" {
		extra["arm_cca.rak_hash_alg"] = alg
	}
	if rems, ok := realmClaims.sliceBytes(labelRealmExtensibleMeas); ok {
		extra["arm_cca.rem_count"] = fmt.Sprintf("%d", len(rems))
		for i, rem := range rems {
			extra[fmt.Sprintf("arm_cca.rem.%d", i)] = hex.EncodeToString(rem)
		}
	}
	return extra
}

// canonicalCCABytes returns the bytes that participate in CompositeHash. The
// verifier-extracted fields are hashed (never the raw token) in a fixed,
// length-prefixed order, so a consumer re-deriving the hash reproduces it iff
// the same evidence was verified against the same trust anchor and bindings.
func canonicalCCABytes(platformClaims, realmClaims ccaClaimSet) []byte {
	var buf []byte
	appendField := func(b []byte) {
		var l [4]byte
		n := uint32(len(b))
		l[0], l[1], l[2], l[3] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	field := func(c ccaClaimSet, label int64) []byte {
		b, _ := c.bytes(label)
		return b
	}
	textField := func(c ccaClaimSet, label int64) []byte {
		s, _ := c.text(label)
		return []byte(s)
	}

	appendField(textField(platformClaims, labelProfile))
	appendField(textField(realmClaims, labelProfile))
	appendField(field(platformClaims, labelPlatformConfig))
	appendField(field(platformClaims, labelPlatformInstID))
	appendField(field(platformClaims, labelChallenge)) // platform binder
	appendField(field(realmClaims, labelRealmInitialMeasurement))
	if rems, ok := realmClaims.sliceBytes(labelRealmExtensibleMeas); ok {
		for _, rem := range rems {
			appendField(rem)
		}
	}
	appendField(field(realmClaims, labelChallenge)) // realm freshness nonce
	appendField(field(realmClaims, labelRealmPubKey))
	appendField(textField(realmClaims, labelRealmPubKeyHashAlgID))
	appendField(textField(realmClaims, labelRealmHashAlgID))
	return buf
}

// extraVerifiers holds Verifiers that self-register from their own file via
// init(), rather than being hard-coded into Dispatch's switch in verifier.go.
// KindARMCCA registers here. This is the per-file registration substrate: a new
// Kind is added in exactly one file and edits no shared file. Dispatch still
// routes the original kinds via its built-in switch; consulting this map from
// Dispatch is a one-line follow-up deliberately left to the maintainer so this
// change stays within its own files (see VerifierFor).
var extraVerifiers = map[Kind]Verifier{}

// registerVerifier records v as the Verifier for kind. It panics on a
// duplicate so two files cannot silently claim the same Kind.
func registerVerifier(kind Kind, v Verifier) {
	if _, dup := extraVerifiers[kind]; dup {
		panic("attest: duplicate verifier registration for kind " + string(kind))
	}
	extraVerifiers[kind] = v
}

// VerifierFor returns the self-registered Verifier for kind. It is the lookup
// counterpart to registerVerifier and the intended seam for migrating Dispatch
// off its hard-coded switch onto per-file registration.
func VerifierFor(kind Kind) (Verifier, bool) {
	v, ok := extraVerifiers[kind]
	return v, ok
}

func init() { registerVerifier(KindARMCCA, ARMCCA{}) }

// Compile-time guard: ARMCCA satisfies Verifier.
var _ Verifier = ARMCCA{}
