// Algorithm-substitution defense tests for verifyJWS (Red audit F3 /
// CVE-2015-9235 family). The eight cases below pin down the alg ↔
// key-type matrix at the dispatch layer:
//
//  1. EdDSA + ed25519.PublicKey                 → PASS
//  2. ES256 + *ecdsa.PublicKey on P-256         → PASS
//  3. PS256 + *rsa.PublicKey                    → PASS
//  4. EdDSA paired with RSA pub                 → ErrAlgKeyTypeMismatch
//  5. ES256 paired with ed25519 pub             → ErrAlgKeyTypeMismatch
//  6. ES256 paired with ecdsa P-384             → ErrAlgKeyTypeMismatch
//  7. alg=none                                  → ErrAlgNoneRefused
//  8. alg=Unknown                               → ErrUnknownAlg
//
// Cases 4-6 are the substitution attack: a forged JWS header that
// names a different alg than the trust-root's key actually supports.
// Pre-fix, dispatch ran by alg but verification ran by key type, so
// an attacker who could choose the alg got to pick which primitive
// ran against which key. The test for case 4 is the canonical
// reproducer in the audit narrative.
package nvidia

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
	"testing"
)

func TestVerifyJWS_EdDSA_Valid(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signedInput := []byte("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0")
	sig := ed25519.Sign(priv, signedInput)
	if err := verifyJWS(pub, "EdDSA", signedInput, sig); err != nil {
		t.Fatalf("expected PASS, got %v", err)
	}
}

func TestVerifyJWS_ES256_Valid(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signedInput := []byte("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
	digest := sha256.Sum256(signedInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := joseConcat(r, s, 32) // P-256 coord size = 32 bytes

	if err := verifyJWS(&priv.PublicKey, "ES256", signedInput, sig); err != nil {
		t.Fatalf("expected PASS, got %v", err)
	}
}

func TestVerifyJWS_PS256_Valid(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signedInput := []byte("eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0")
	digest := sha256.Sum256(signedInput)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := verifyJWS(&priv.PublicKey, "PS256", signedInput, sig); err != nil {
		t.Fatalf("expected PASS, got %v", err)
	}
}

// === Algorithm-substitution attacks ===

// alg=EdDSA paired with an RSA trust-root for the same kid. The forged
// header tells the verifier "this is an Ed25519 signature"; the trust
// root holds an *rsa.PublicKey. Pre-fix, verifySignature dispatched by
// key type and ran RSA-PSS on the attacker-chosen signedInput. Post-fix,
// the alg=EdDSA branch type-asserts ed25519.PublicKey and refuses.
func TestVerifyJWS_EdDSA_AgainstRSAPub_Rejected(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	signedInput := []byte("attacker-chosen")
	// Attacker can produce *anything* for sig — verifier must reject
	// before looking at sig at all.
	sig := []byte{0xAA, 0xBB, 0xCC}
	err = verifyJWS(&rsaPriv.PublicKey, "EdDSA", signedInput, sig)
	if !errors.Is(err, ErrAlgKeyTypeMismatch) {
		t.Fatalf("expected ErrAlgKeyTypeMismatch, got %v", err)
	}
}

// alg=ES256 paired with ed25519 pub.
func TestVerifyJWS_ES256_AgainstEd25519Pub_Rejected(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	err = verifyJWS(pub, "ES256", []byte("input"), []byte{0x00})
	if !errors.Is(err, ErrAlgKeyTypeMismatch) {
		t.Fatalf("expected ErrAlgKeyTypeMismatch, got %v", err)
	}
}

// alg=ES256 paired with ecdsa P-384 pub. Curve mismatch — even though
// both are *ecdsa.PublicKey, ES256 is bound to P-256 only.
func TestVerifyJWS_ES256_AgainstP384Pub_Rejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	// Construct a real ES384-shaped signature so the failure is
	// proven to come from the curve check, not from a malformed sig.
	signedInput := []byte("input")
	digest := sha512.Sum384(signedInput)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := joseConcat(r, s, 48) // P-384 coord size = 48 bytes

	err = verifyJWS(&priv.PublicKey, "ES256", signedInput, sig)
	if !errors.Is(err, ErrAlgKeyTypeMismatch) {
		t.Fatalf("expected ErrAlgKeyTypeMismatch (curve), got %v", err)
	}
}

// alg=none must be refused unconditionally regardless of trust-root key.
func TestVerifyJWS_AlgNone_Refused(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	for _, alg := range []string{"none", "None", "NONE", ""} {
		err := verifyJWS(pub, alg, []byte("input"), []byte("sig"))
		if !errors.Is(err, ErrAlgNoneRefused) {
			t.Fatalf("alg=%q: expected ErrAlgNoneRefused, got %v", alg, err)
		}
	}
}

// Unknown alg must be refused.
func TestVerifyJWS_UnknownAlg_Refused(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	err = verifyJWS(pub, "HS256", []byte("input"), []byte("sig"))
	if !errors.Is(err, ErrUnknownAlg) {
		t.Fatalf("expected ErrUnknownAlg, got %v", err)
	}
}

// === helpers ===

// joseConcat encodes (r, s) as fixed-width big-endian r||s (RFC 7515 §3.4).
func joseConcat(r, s *big.Int, size int) []byte {
	out := make([]byte, size*2)
	rB := r.Bytes()
	sB := s.Bytes()
	copy(out[size-len(rB):size], rB)
	copy(out[size*2-len(sB):], sB)
	return out
}
