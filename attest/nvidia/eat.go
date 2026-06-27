// NRAS EAT (Entity Attestation Token) verification — the remote NVIDIA
// trust path.
//
// In the NRAS deployment model the host POSTs GPU evidence to the NVIDIA
// Remote Attestation Service, which performs the SPDM + device-chain
// verification on its side and returns a signed EAT: a JWS-compact JWT
// whose claims are NVIDIA's attestation verdict (overall result, per-
// measurement results, GPU identity, a freshness nonce). The relying party
// trusts NVIDIA's cloud and only has to verify the token.
//
// VerifyEAT performs exactly that, with no network call (the HTTP fetch is
// NRASClient's job — separation of concerns):
//
//   - signature: JWS verified against operator-pinned NRAS signer keys
//     (by kid) with a strict alg<->key-type binding; OR, when the token
//     carries an x5c header and an NRAS root pool is pinned, the x5c chain
//     is validated to that root and the leaf key verifies the JWS.
//   - chain: the x5c path anchors the signer to NVIDIA's NRAS root CA.
//   - claims: exp/nbf freshness, eat_nonce binding to the caller's
//     challenge, and (when present) the overall attestation result must
//     be positive.
//
// Clean-room: no NVIDIA keys are vendored; the NRAS signer key / root CA
// is operator-pinned, exactly like the local device root.
package nvidia

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors returned by EAT verification.
var (
	ErrEATBadJWT         = errors.New("nvidia/eat: token is not a valid JWS compact serialization")
	ErrEATBadSignature   = errors.New("nvidia/eat: token signature verification failed")
	ErrEATNoSigner       = errors.New("nvidia/eat: no signer key (kid not pinned and no verifiable x5c)")
	ErrEATExpired        = errors.New("nvidia/eat: token expired")
	ErrEATNotYetValid    = errors.New("nvidia/eat: token not yet valid (nbf in the future)")
	ErrEATNonceMismatch  = errors.New("nvidia/eat: eat_nonce does not match challenge")
	ErrEATResultNegative = errors.New("nvidia/eat: NVIDIA overall attestation result is negative")
	ErrEATChainUntrusted = errors.New("nvidia/eat: x5c chain does not anchor to a pinned NRAS root")
)

// EATResult is the verified projection of an NRAS EAT.
type EATResult struct {
	SignerKeyID   string                     // kid that verified the token (or x5c leaf subject)
	Nonce         [32]byte                   // eat_nonce, when present
	HasNonce      bool                       // whether a 32-byte nonce claim was present
	Measurement   []byte                     // measurement root (see note in VerifyEAT)
	OverallResult string                     // x-nvidia-overall-att-result / measres, when present
	IssuedAt      time.Time                  // iat
	NotBefore     time.Time                  // nbf
	ExpiresAt     time.Time                  // exp
	Claims        map[string]json.RawMessage // full claim set, for audit/policy
}

// VerifyEAT verifies an NRAS-issued EAT token.
//
// roots are the pinned NRAS signer public keys (looked up by the JWS kid).
// rootPool, when non-nil, pins the NRAS root CA so a token carrying an x5c
// header is anchored by chain validation (the leaf key then verifies the
// JWS). challenge, when non-nil, must equal the token's eat_nonce. now is
// the verification clock.
//
// Measurement mapping: NVIDIA's EAT expresses measurement results across
// many submodule claims rather than a single root. VerifyEAT surfaces an
// explicit measurement-root claim when present ("x-nvidia-gpu-measurements-
// root" hex) and otherwise binds Measurement to sha256(token) — a stable,
// signature-covered root the caller can pin. The exact production claim
// name is documented NVIDIA collateral; callers needing a specific
// submeasurement read it from Claims.
func VerifyEAT(token string, roots []TrustRoot, rootPool *x509.CertPool, challenge *[32]byte, now time.Time) (*EATResult, error) {
	hdrBytes, payload, sig, signedInput, err := splitJWS(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEATBadJWT, err)
	}
	var hdr struct {
		Alg string   `json:"alg"`
		Kid string   `json:"kid"`
		X5c []string `json:"x5c"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrEATBadJWT, err)
	}

	signerPub, signerID, err := eatSignerKey(hdr.Kid, hdr.X5c, roots, rootPool, now)
	if err != nil {
		return nil, err
	}
	if err := verifyJWS(signerPub, hdr.Alg, signedInput, sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEATBadSignature, err)
	}

	// Decode claims twice: once into known fields, once as a raw map for
	// audit / policy on top.
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrEATBadJWT, err)
	}
	res := &EATResult{SignerKeyID: signerID, Claims: claims}

	if t, ok := eatUnixClaim(claims, "iat"); ok {
		res.IssuedAt = t
	}
	if t, ok := eatUnixClaim(claims, "nbf"); ok {
		res.NotBefore = t
		if now.Before(t) {
			return nil, fmt.Errorf("%w: nbf=%s now=%s", ErrEATNotYetValid, t, now.UTC())
		}
	}
	if t, ok := eatUnixClaim(claims, "exp"); ok {
		res.ExpiresAt = t
		if now.After(t) {
			return nil, fmt.Errorf("%w: exp=%s now=%s", ErrEATExpired, t, now.UTC())
		}
	}

	// Nonce binding. NVIDIA uses "eat_nonce"; accept "nonce" as an alias.
	if nb, ok := eatHexClaim(claims, "eat_nonce", "nonce"); ok {
		if len(nb) == 32 {
			copy(res.Nonce[:], nb)
			res.HasNonce = true
		}
		if challenge != nil {
			if len(nb) != 32 || !bytesEqual(nb, challenge[:]) {
				return nil, ErrEATNonceMismatch
			}
		}
	} else if challenge != nil {
		// A challenge was demanded but the token carries no nonce.
		return nil, ErrEATNonceMismatch
	}

	// Overall result, when present, must be positive.
	if r, ok := eatResultClaim(claims); ok {
		res.OverallResult = r
		if !eatResultPositive(r) {
			return nil, fmt.Errorf("%w: %q", ErrEATResultNegative, r)
		}
	}

	// Measurement root: explicit claim if present, else token-bound.
	if mb, ok := eatHexClaim(claims, "x-nvidia-gpu-measurements-root", "measurement_root"); ok {
		res.Measurement = mb
	} else {
		h := sha256.Sum256([]byte(token))
		res.Measurement = h[:]
	}
	return res, nil
}

// eatSignerKey resolves the public key that must verify the JWS: by pinned
// kid, or by validating an x5c chain to the pinned NRAS root pool.
func eatSignerKey(kid string, x5c []string, roots []TrustRoot, rootPool *x509.CertPool, now time.Time) (crypto.PublicKey, string, error) {
	// Prefer the pinned-kid path: deterministic, no chain processing.
	if kid != "" {
		if root, ok := findTrustRoot(roots, kid); ok {
			return root.Public, root.KeyID, nil
		}
	}
	// x5c path: anchor to the NRAS root pool, use the leaf key.
	if len(x5c) > 0 && rootPool != nil {
		chain, err := parseX5C(x5c)
		if err != nil {
			return nil, "", err
		}
		intermediates := x509.NewCertPool()
		for _, ic := range chain[1:] {
			intermediates.AddCert(ic)
		}
		leaf := chain[0]
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, "", fmt.Errorf("%w: %v", ErrEATChainUntrusted, err)
		}
		return leaf.PublicKey, leaf.Subject.String(), nil
	}
	return nil, "", ErrEATNoSigner
}

// parseX5C parses an RFC 7515 x5c header (array of base64-STD DER certs,
// leaf first).
func parseX5C(x5c []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(x5c))
	for i, b64 := range x5c {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrEATChainUntrusted, i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: x5c[%d]: %v", ErrEATChainUntrusted, i, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, ErrEATChainUntrusted
	}
	return out, nil
}

func eatUnixClaim(claims map[string]json.RawMessage, name string) (time.Time, bool) {
	raw, ok := claims[name]
	if !ok {
		return time.Time{}, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0).UTC(), true
}

// eatHexClaim returns the first present claim among names, hex-decoded.
func eatHexClaim(claims map[string]json.RawMessage, names ...string) ([]byte, bool) {
	for _, name := range names {
		raw, ok := claims[name]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue
		}
		b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		if err != nil {
			continue
		}
		return b, true
	}
	return nil, false
}

// eatResultClaim extracts NVIDIA's overall attestation result, accepting a
// boolean or a string verdict under a few documented claim names.
func eatResultClaim(claims map[string]json.RawMessage) (string, bool) {
	for _, name := range []string{"x-nvidia-overall-att-result", "measres", "overall_result"} {
		raw, ok := claims[name]
		if !ok {
			continue
		}
		var b bool
		if err := json.Unmarshal(raw, &b); err == nil {
			if b {
				return "true", true
			}
			return "false", true
		}
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s, true
		}
	}
	return "", false
}

func eatResultPositive(r string) bool {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "true", "success", "comparison-successful", "pass", "passed":
		return true
	default:
		return false
	}
}
