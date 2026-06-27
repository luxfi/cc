// Copyright (c) 2026, Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/ccatoken"
)

// -----------------------------------------------------------------------------
// Real ARM CCA token vectors, committed verbatim so these tests need no live
// hardware, no RMM, and no network.
//
// Both vectors are taken from the canonical Veraison CCA stack
// (github.com/veraison/ccatoken test corpus) and were independently confirmed
// to verify with that library's own Evidence.Verify before being embedded
// here. They exercise complementary corners of the format:
//
//   - ccaRMMToken: a Trusted-Firmware RMM token
//     (derived from git.trustedfirmware.org/TF-M/tf-m-tools iat-verifier
//     cca_token.cbor). CMW collection framing (CBOR tag 907); platform token
//     signed by the TF-M cca_platform CPAK (ECDSA P-384 / ES384); realm key in
//     raw 0x04||X||Y form with no realm profile; RIM 32 bytes; binding hash
//     SHA-256.
//   - ccaGoodLegacyToken: the Veraison canonical good token, legacy EAT
//     collection framing (CBOR tag 399); platform token signed by an ECDSA
//     P-256 / ES256 IAK; realm key in CBOR COSE_Key form with a realm profile;
//     RIM 64 bytes; binding hash SHA-512.
//
// Between them they cover: both collection framings, both platform curves,
// both realm-key encodings (raw vs COSE_Key), and two binding hash algorithms.
// -----------------------------------------------------------------------------

const ccaRMMTokenHex = `
	d9038ba219acca82190107590293d28444a1013822a0590226a9190109781c687474703a2f2f
	61726d2e636f6d2f4343412d5353442f312e302e300a5820b5973cb68baa9fc55558786b7ec6
	7f69e40df5ba5aa921cd0c27f40587a011ea19095c58207f454c460201010000000000000000
	0003003e0001000000505800000000000019010058210107060504030201000f0e0d0c0b0a09
	0817161514131211101f1e1d1c1b1a191819096158210107060504030201000f0e0d0c0b0a09
	0817161514131211101f1e1d1c1b1a191819095b193003190962677368612d32353619095f84
	a50162424c05582007060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a
	19180465332e342e3202582007060504030201000f0e0d0c0b0a090817161514131211101f1e
	1d1c1b1a191806677368612d323536a401624d3105582007060504030201000f0e0d0c0b0a09
	0817161514131211101f1e1d1c1b1a19180463312e3202582007060504030201000f0e0d0c0b
	0a090817161514131211101f1e1d1c1b1a1918a401624d3205582007060504030201000f0e0d
	0c0b0a090817161514131211101f1e1d1c1b1a19180465312e322e3302582007060504030201
	000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918a401624d330558200706050403
	0201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a19180461310258200706050403
	0201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a19181909606c77686174657665
	722e636f6d5860201d3035e1cfa52abcf8b6d725a201018941bbe30f5019a86a3c5bd6305a39
	dd82d57a9dc645a831f78770dbc29b6c4d1313a43f159b846f172c7af1e1c8281bc3f777324c
	e0bcb0c9f150e4a6d8e4749857cede857597675b6be91c8868131b19acd182190107590223d2
	8444a1013822a05901b6a70a5840abababababababababababababababababababababababab
	abababababababababababababababababababababababababababababababababababababab
	abab19accc677368612d32353619acd0677368612d32353619accb584054686520717569636b
	2062726f776e20666f78206a756d7073206f766572203133206c617a7920646f67732e546865
	20717569636b2062726f776e20666f782019accd58610476f988091be585ed41801aecfab858
	548c63057e16b0e676120bbd0d2f9c29e056c5d41a0130eb9c21517899dc23146b28e1b062bd
	3ea4b315fd219f1cbb528cb6e74ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4228e
	50919544ae19acce582000000000000000000000000000000000000000000000000000000000
	0000000019accf84582000000000000000000000000000000000000000000000000000000000
	0000000058200000000000000000000000000000000000000000000000000000000000000000
	5820000000000000000000000000000000000000000000000000000000000000000058200000
	0000000000000000000000000000000000000000000000000000000000005860f3c498df6a8b
	bcc5824647c179536e86c4f9b9a27a7aa69a54f6db328592dee15ebc68d7dcb6d1d256ee3129
	f27255a17a7e197aa44db12f37593274f33280b838332ae048b9ac7789ce4f38aec49fdd1e23
	78a1f3f127f2ee3182ee414124c5
`

const ccaRMMCpakPEM = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEIShnxS4rlQiwpCCpBWDzlNLfqiG911FP
8akBr+fh94uxHU5m+Kijivp2r2oxxN6MhM4tr8mWQli1P61xh3T0ViDREbF26DGO
EYfbAjWjGNN7pZf+6A4OTHYqEryz6m7U
-----END PUBLIC KEY-----`

const ccaGoodLegacyTokenHex = `
	d9018fa219acca590199d28443a10126a059014da919010978237461673a61726d2e636f6d2c
	323032333a6363615f706c6174666f726d23312e302e300a5840f7951be801fe7eb0fc395610
	7058c916134ee0c65f75d03715bf23b96a1784dbca9cfe8fea1c46eff8bf63c4678988d02abf
	1a0abe72727e63a1a4f56b9bf79f19095c582000000000000000000000000000000000000000
	0000000000000000000000000019010058210102020202020202020202020202020202020202
	020202020202020202020202021909614301020319095b19300019095f81a202582003030303
	0303030303030303030303030303030303030303030303030303030305582004040404040404
	04040404040404040404040404040404040404040404040404190960782e68747470733a2f2f
	7665726169736f6e2e6578616d706c652f76312f6368616c6c656e67652d726573706f6e7365
	190962677368612d3235365840f271afdc87a47a7f347eb10677ed998681819ed5d6acf02781
	c6b649cc49a18859415eea87819ad0cfcdaba5ecfc37468b0d530db2c445e3542f5a43d222e8
	7619acd15902eed28444a1013822a0590281a8190109781c7461673a61726d2e636f6d2c3230
	32333a7265616c6d23312e302e300a5840414241424142414241424142414241424142414241
	4241424142414241424142414241424142414241424142414241424142414241424142414241
	424142414219accb584041444144414441444144414441444144414441444144414441444144
	41444144414441444144414441444144414441444144414441444144414441444144414419ac
	ce58404343434343434343434343434343434343434343434343434343434343434343434343
	434343434343434343434343434343434343434343434343434343434319accf845840434343
	4343434343434343434343434343434343434343434343434343434343434343434343434343
	4343434343434343434343434343434343434343434343584043434343434343434343434343
	4343434343434343434343434343434343434343434343434343434343434343434343434343
	4343434343434343434343434358404343434343434343434343434343434343434343434343
	4343434343434343434343434343434343434343434343434343434343434343434343434343
	4343435840434343434343434343434343434343434343434343434343434343434343434343
	4343434343434343434343434343434343434343434343434343434343434319accc67736861
	2d32353619accd586ba40102200221583081195880a2207fb956032a3cb97f5da5af726ffcb7
	15ee164784a7fb16c06096bdd9462a32650b2912a8551570d6ea1f2258303b2d1f7da8a275fa
	00330f0078618bc3e149549c8170d32ec55890a7f9ec789f1f18ae92eb15d222af971d971c96
	5af119acd0677368612d3531325860738916f034c55e6f033194425a4edfaeacdfa2da1ba4c7
	a05b3c9c5d9128e9980343a46ac95115b9cab3dbed54028676ba0d5d8eb6ce2b454db27ae75a
	0f234f102d189d47f966e00223b1d27a0ccd14d880f95da740e87794a0b9edd12e5660
`

const ccaGoodLegacyIakPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMKBCTNIcKUSDii11ySs3526iDZ8A
iTo7Tu6KPAqv7D7gS2XpJFbZiItSs3m9+9Ue6GnvHw/GW2ZZaVtszggXIw==
-----END PUBLIC KEY-----`

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func mustHexToken(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex vector: %v", err)
	}
	return b
}

func mustPubKey(t *testing.T, pemStr string) crypto.PublicKey {
	t.Helper()
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		t.Fatal("pem decode returned nil block")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatalf("parse PKIX public key: %v", err)
	}
	return pub
}

func armccaWith(pub crypto.PublicKey) ARMCCA {
	return ARMCCA{TrustAnchors: []crypto.PublicKey{pub}}
}

func rmmToken(t *testing.T) []byte          { return mustHexToken(t, ccaRMMTokenHex) }
func goodToken(t *testing.T) []byte         { return mustHexToken(t, ccaGoodLegacyTokenHex) }
func rmmCPAK(t *testing.T) crypto.PublicKey { return mustPubKey(t, ccaRMMCpakPEM) }
func goodIAK(t *testing.T) crypto.PublicKey { return mustPubKey(t, ccaGoodLegacyIakPEM) }

// rewrapEAT re-encodes two inner COSE_Sign1 tokens as a legacy EAT (tag 399)
// CCA collection. Used to build adversarial collections (tampered or spliced
// inner tokens) from real, individually-valid tokens.
func rewrapEAT(t *testing.T, platformTok, realmTok []byte) []byte {
	t.Helper()
	type coll struct {
		Platform []byte `cbor:"44234,keyasint"`
		Realm    []byte `cbor:"44241,keyasint"`
	}
	b, err := cbor.Marshal(cbor.Tag{Number: tagCCAEAT, Content: coll{platformTok, realmTok}})
	if err != nil {
		t.Fatalf("rewrap EAT: %v", err)
	}
	return b
}

func flipLastByte(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[len(out)-1] ^= 0x01
	return out
}

// flipFirstValue flips the first byte equal to want, returning a copy. Used to
// mutate a known measurement byte (e.g. the 0x43 run that is the RIM/REM) so
// the change lands inside the realm token's signed payload.
func flipFirstValue(t *testing.T, b []byte, want byte) []byte {
	t.Helper()
	out := append([]byte(nil), b...)
	for i, c := range out {
		if c == want {
			out[i] ^= 0x01
			return out
		}
	}
	t.Fatalf("byte %#x not found", want)
	return nil
}

// -----------------------------------------------------------------------------
// self-registration
// -----------------------------------------------------------------------------

func TestARMCCA_SelfRegisteredViaInit(t *testing.T) {
	v, ok := VerifierFor(KindARMCCA)
	if !ok {
		t.Fatal("KindARMCCA did not self-register via init()")
	}
	if _, isCCA := v.(ARMCCA); !isCCA {
		t.Fatalf("registered verifier for KindARMCCA is %T, want ARMCCA", v)
	}
}

// -----------------------------------------------------------------------------
// real-vector happy paths
// -----------------------------------------------------------------------------

func TestARMCCA_Verify_RealRMMToken_CMW_P384(t *testing.T) {
	rep, err := armccaWith(rmmCPAK(t)).Verify(context.Background(), rmmToken(t))
	if err != nil {
		t.Fatalf("verify RMM token: %v", err)
	}
	if rep.Kind != KindARMCCA {
		t.Errorf("kind = %q, want %q", rep.Kind, KindARMCCA)
	}
	if rep.Vendor != "arm.cca" {
		t.Errorf("vendor = %q, want arm.cca", rep.Vendor)
	}
	// RIM → Measurement (32 zero bytes in this vector).
	if !bytes.Equal(rep.Measurement, make([]byte, 32)) {
		t.Errorf("measurement = %x, want 32 zero bytes", rep.Measurement)
	}
	// Realm challenge → ReportData (64 bytes of 0xab).
	if want := bytes.Repeat([]byte{0xab}, 64); !bytes.Equal(rep.ReportData, want) {
		t.Errorf("report_data = %x, want 64 bytes of 0xab", rep.ReportData)
	}
	if len(rep.ChipID) == 0 {
		t.Error("chip_id (platform instance id) is empty")
	}
	if rep.CompositeHash == ([32]byte{}) {
		t.Error("composite hash is zero")
	}
	if rep.IssuedAt.IsZero() {
		t.Error("issued_at not set")
	}
	if got := rep.Extra["arm_cca.rem_count"]; got != "4" {
		t.Errorf("rem_count = %q, want 4", got)
	}
	if got := rep.Extra["arm_cca.rak_hash_alg"]; got != "sha-256" {
		t.Errorf("rak_hash_alg = %q, want sha-256 (binding hash)", got)
	}
	if got := rep.Extra["arm_cca.platform_profile"]; got != "http://arm.com/CCA-SSD/1.0.0" {
		t.Errorf("platform_profile = %q", got)
	}
	if _, ok := rep.Extra["arm_cca.platform_config"]; !ok {
		t.Error("missing platform_config in Extra")
	}
}

func TestARMCCA_Verify_RealGoodLegacyToken_EAT_P256(t *testing.T) {
	rep, err := armccaWith(goodIAK(t)).Verify(context.Background(), goodToken(t))
	if err != nil {
		t.Fatalf("verify good legacy token: %v", err)
	}
	// RIM → Measurement (64 bytes of 0x43 in this vector).
	if want := bytes.Repeat([]byte{0x43}, 64); !bytes.Equal(rep.Measurement, want) {
		t.Errorf("measurement = %x, want 64 bytes of 0x43", rep.Measurement)
	}
	// This vector carries a realm profile and uses the COSE_Key RAK encoding +
	// SHA-512 binding — the complementary corners to the RMM vector.
	if got := rep.Extra["arm_cca.realm_profile"]; got != "tag:arm.com,2023:realm#1.0.0" {
		t.Errorf("realm_profile = %q", got)
	}
	if got := rep.Extra["arm_cca.rak_hash_alg"]; got != "sha-512" {
		t.Errorf("rak_hash_alg = %q, want sha-512 (binding hash)", got)
	}
}

// TestARMCCA_Verify_AgreesWithCanonicalReference cross-checks our independent
// (cbor + go-cose) verifier against the canonical veraison/ccatoken
// implementation on the same real token: both must accept, and the RIM our
// verifier surfaces must equal the one the reference decoder reports. This is
// the conformance anchor — it rules out our verifier silently diverging from
// the ARM CCA reference semantics.
func TestARMCCA_Verify_AgreesWithCanonicalReference(t *testing.T) {
	tok := rmmToken(t)
	cpak := rmmCPAK(t)

	rep, err := armccaWith(cpak).Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("our verifier rejected a token the reference accepts: %v", err)
	}

	ev, err := ccatoken.DecodeAndValidateEvidenceFromCBOR(tok)
	if err != nil {
		t.Fatalf("reference decode: %v", err)
	}
	if err := ev.Verify(cpak); err != nil {
		t.Fatalf("reference verify: %v", err)
	}
	rimRef, err := ev.RealmClaims.GetInitialMeasurement()
	if err != nil {
		t.Fatalf("reference RIM: %v", err)
	}
	if !bytes.Equal(rep.Measurement, rimRef) {
		t.Errorf("measurement disagreement: ours %x, reference %x", rep.Measurement, rimRef)
	}
}

// TestARMCCA_Verify_EnvelopeEquivalence proves the verifier is framing-agnostic
// and that rewrapEAT (used by the adversarial tests) is faithful: decoding the
// CMW (tag 907) RMM token, re-wrapping its inner tokens as legacy EAT (tag 399),
// and re-verifying yields the same Measurement and CompositeHash.
func TestARMCCA_Verify_EnvelopeEquivalence(t *testing.T) {
	tok := rmmToken(t)
	cpak := rmmCPAK(t)

	repCMW, err := armccaWith(cpak).Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("verify CMW: %v", err)
	}

	platformTok, realmTok, err := decodeCCACollection(tok)
	if err != nil {
		t.Fatalf("decode collection: %v", err)
	}
	repEAT, err := armccaWith(cpak).Verify(context.Background(), rewrapEAT(t, platformTok, realmTok))
	if err != nil {
		t.Fatalf("verify rewrapped EAT: %v", err)
	}
	if !bytes.Equal(repCMW.Measurement, repEAT.Measurement) {
		t.Errorf("measurement differs across framings: %x vs %x", repCMW.Measurement, repEAT.Measurement)
	}
	if repCMW.CompositeHash != repEAT.CompositeHash {
		t.Errorf("composite hash differs across framings: %x vs %x", repCMW.CompositeHash, repEAT.CompositeHash)
	}
}

func TestARMCCA_Verify_DeterministicCompositeHash(t *testing.T) {
	cpak := rmmCPAK(t)
	r1, err := armccaWith(cpak).Verify(context.Background(), rmmToken(t))
	if err != nil {
		t.Fatalf("verify 1: %v", err)
	}
	r2, err := armccaWith(cpak).Verify(context.Background(), rmmToken(t))
	if err != nil {
		t.Fatalf("verify 2: %v", err)
	}
	if r1.CompositeHash != r2.CompositeHash {
		t.Errorf("composite hash not deterministic: %x vs %x", r1.CompositeHash, r2.CompositeHash)
	}
	// Distinct tokens must not collide.
	rg, err := armccaWith(goodIAK(t)).Verify(context.Background(), goodToken(t))
	if err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if r1.CompositeHash == rg.CompositeHash {
		t.Error("composite hash collision across distinct tokens")
	}
}

// -----------------------------------------------------------------------------
// caller policy (freshness + measurement pinning)
// -----------------------------------------------------------------------------

func TestARMCCA_Verify_AcceptsPinnedNonceAndMeasurement(t *testing.T) {
	_, err := armccaWith(rmmCPAK(t)).Verify(
		context.Background(), rmmToken(t),
		WithExpectedReportData(bytes.Repeat([]byte{0xab}, 64)),
		WithExpectedMeasurement(make([]byte, 32)),
	)
	if err != nil {
		t.Fatalf("verify with correct pins: %v", err)
	}
}

func TestARMCCA_Verify_RejectsStaleNonce(t *testing.T) {
	_, err := armccaWith(rmmCPAK(t)).Verify(
		context.Background(), rmmToken(t),
		WithExpectedReportData(bytes.Repeat([]byte{0xFF}, 64)),
	)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestARMCCA_Verify_RejectsWrongMeasurement(t *testing.T) {
	_, err := armccaWith(rmmCPAK(t)).Verify(
		context.Background(), rmmToken(t),
		WithExpectedMeasurement(bytes.Repeat([]byte{0xAB}, 32)),
	)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

// -----------------------------------------------------------------------------
// refusal: trust anchors
// -----------------------------------------------------------------------------

func TestARMCCA_Verify_RefusesWithoutTrustAnchors(t *testing.T) {
	// No insecure mode: an empty anchor set is refused before any parsing.
	_, err := ARMCCA{}.Verify(context.Background(), rmmToken(t))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("err = %v, want ErrPolicy", err)
	}
}

func TestARMCCA_Verify_RejectsWrongTrustAnchor(t *testing.T) {
	// Pin the P-256 IAK against the RMM token (signed by the P-384 CPAK).
	_, err := armccaWith(goodIAK(t)).Verify(context.Background(), rmmToken(t))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSignatureInvalid", err)
	}
}

// -----------------------------------------------------------------------------
// refusal: tampering
// -----------------------------------------------------------------------------

func assertRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected refusal, got nil error and a report")
	}
	// Any of these is a hard refusal; which one depends on where the
	// corruption trips. What matters is no *VerifiedReport is returned.
	if !errors.Is(err, ErrSignatureInvalid) &&
		!errors.Is(err, ErrChainInvalid) &&
		!errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want Signature|Chain|Invalid refusal", err)
	}
}

func TestARMCCA_Verify_RejectsTamperedPlatformSignature(t *testing.T) {
	platformTok, realmTok, err := decodeCCACollection(rmmToken(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	bad := rewrapEAT(t, flipLastByte(platformTok), realmTok)
	_, err = armccaWith(rmmCPAK(t)).Verify(context.Background(), bad)
	assertRefused(t, err)
}

func TestARMCCA_Verify_RejectsTamperedRealmSignature(t *testing.T) {
	platformTok, realmTok, err := decodeCCACollection(rmmToken(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	bad := rewrapEAT(t, platformTok, flipLastByte(realmTok))
	_, err = armccaWith(rmmCPAK(t)).Verify(context.Background(), bad)
	assertRefused(t, err)
}

// TestARMCCA_Verify_RejectsTamperedMeasurement mutates a measurement byte (the
// 0x43 run that is the RIM/REM) inside the realm token's signed payload. The
// realm COSE_Sign1 signature must then fail: a measurement cannot be altered
// without invalidating the realm token.
func TestARMCCA_Verify_RejectsTamperedMeasurement(t *testing.T) {
	platformTok, realmTok, err := decodeCCACollection(goodToken(t))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	bad := rewrapEAT(t, platformTok, flipFirstValue(t, realmTok, 0x43))
	_, err = armccaWith(goodIAK(t)).Verify(context.Background(), bad)
	assertRefused(t, err)
}

// TestARMCCA_Verify_RejectsBrokenBinding splices a platform token from one
// realm/platform pair with a realm token from another. Both signatures verify
// in isolation (platform under the pinned CPAK, realm under its own RAK), but
// the platform's nonce binds the *other* realm's key, so the platform↔realm
// binding fails. This is the attack the binding check exists to stop: it must
// be rejected as a broken chain even though every signature is valid.
func TestARMCCA_Verify_RejectsBrokenBinding(t *testing.T) {
	platformRMM, _, err := decodeCCACollection(rmmToken(t))
	if err != nil {
		t.Fatalf("decode rmm: %v", err)
	}
	_, realmGood, err := decodeCCACollection(goodToken(t))
	if err != nil {
		t.Fatalf("decode good: %v", err)
	}
	spliced := rewrapEAT(t, platformRMM, realmGood)

	_, err = armccaWith(rmmCPAK(t)).Verify(context.Background(), spliced)
	if !errors.Is(err, ErrChainInvalid) {
		t.Fatalf("err = %v, want ErrChainInvalid (broken platform↔realm binding)", err)
	}
}

// -----------------------------------------------------------------------------
// refusal: malformed framing
// -----------------------------------------------------------------------------

func TestARMCCA_Verify_RejectsGarbage(t *testing.T) {
	cpak := rmmCPAK(t)
	cases := map[string][]byte{
		"not cbor":        []byte("this is not a cca token"),
		"empty":           {},
		"truncated token": rmmToken(t)[:40],
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := armccaWith(cpak).Verify(context.Background(), ev); !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("err = %v, want ErrInvalidEvidence", err)
			}
		})
	}
}

func TestARMCCA_Verify_RejectsUnexpectedTopLevelTag(t *testing.T) {
	// A valid CBOR map under an unrelated tag is not a CCA collection.
	wrong, err := cbor.Marshal(cbor.Tag{Number: 999, Content: map[int]int{1: 2}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := armccaWith(rmmCPAK(t)).Verify(context.Background(), wrong); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("err = %v, want ErrInvalidEvidence", err)
	}
}
