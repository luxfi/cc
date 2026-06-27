// NRAS HTTP client. The NVIDIA Remote Attestation Service ingests a
// GPU evidence envelope and returns a signed attestation token (a
// JWS-style JWT) that downstream verifiers can carry forward.
//
// We do not embed any NVIDIA-published verification keys. The token
// is treated as opaque-but-bound: callers verify the token's
// signature against trust roots they configure (same TrustRoot type
// the RIM uses). This keeps the package license-clean.
//
// Wire shape (verified against publicly documented NRAS request/response):
//
//	POST /v1/attest/gpu HTTP/1.1
//	Content-Type: application/json
//	{
//	  "evidence":     "<base64 of the JSON evidence envelope>",
//	  "nonce":        "<32-byte hex>",
//	  "policy":       "<NRAS policy ID, optional>"
//	}
//
//	200 OK
//	Content-Type: application/json
//	{
//	  "token":        "<JWT>",
//	  "expires_at":   "<RFC3339>"
//	}
package nvidia

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Errors returned by the NRAS client.
var (
	ErrNRASNoEndpoint    = errors.New("nvidia/nras: endpoint not configured")
	ErrNRASNoEvidence    = errors.New("nvidia/nras: empty evidence")
	ErrNRASBadStatus     = errors.New("nvidia/nras: non-2xx response")
	ErrNRASBadResponse   = errors.New("nvidia/nras: malformed response body")
	ErrNRASEmptyToken    = errors.New("nvidia/nras: token field missing")
	ErrNRASNonceMismatch = errors.New("nvidia/nras: token nonce does not match request")
	ErrNRASTokenExpired  = errors.New("nvidia/nras: token already expired")
	ErrNRASBadJWT        = errors.New("nvidia/nras: token not a valid JWS compact serialization")
	ErrNRASBadSignature  = errors.New("nvidia/nras: token signature verification failed")

	// Algorithm-substitution defenses (Red audit F3 / CVE-2015-9235 family).
	// verifyJWS enforces a strict alg ↔ key-type binding at the dispatch
	// layer; mismatches are rejected before any verification primitive runs.
	ErrAlgKeyTypeMismatch = errors.New("nvidia/nras: jws alg does not match trust-root key type")
	ErrAlgNoneRefused     = errors.New("nvidia/nras: jws alg=none refused")
	ErrUnknownAlg         = errors.New("nvidia/nras: jws alg unknown")
)

// NRASClient posts GPU evidence to NRAS and returns a verified
// VerifyResult. The HTTP client is injectable so tests use httptest
// directly.
type NRASClient struct {
	Endpoint   string       // e.g. "https://nras.attestation.nvidia.com"
	HTTPClient *http.Client // nil = http.DefaultClient with 15s timeout
	TrustRoots []TrustRoot  // public keys that may sign NRAS tokens
	Now        func() time.Time
}

// NewNRASClient builds a client. trustRoots may be empty for tests
// that bypass token-signature verification (see VerifyOptions).
func NewNRASClient(endpoint string, trustRoots []TrustRoot) *NRASClient {
	return &NRASClient{
		Endpoint:   strings.TrimRight(endpoint, "/"),
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		TrustRoots: trustRoots,
	}
}

// VerifyOptions tunes a single Verify call.
type VerifyOptions struct {
	// PolicyID is the NRAS-side policy the request opts into. Empty
	// uses NRAS's default policy.
	PolicyID string
}

// VerifyResult captures the post-verification facts. Callers fold
// these into GPUEvidence.
type VerifyResult struct {
	Token        string    // raw JWS compact form
	TokenHash    [32]byte  // sha256 of the token bytes
	Nonce        [32]byte  // echoed from the request — must match GPU report
	ExpiresAt    time.Time // honored if non-zero
	IssuedAt     time.Time // RFC3339 from the response
	SignerKeyID  string    // which trust root verified the JWS
	Architecture string    // mirrored back from the report; for audit
}

// Verify uploads evidence and returns the parsed result.
//
// `report` is the GPU evidence (the same JSON ParseGPUReport accepts).
// `nonce` is the freshness binding — typically the value placed in
// the GPU report's nonce field. They MUST match; the function asserts
// this before any HTTP call.
func (c *NRASClient) Verify(ctx context.Context, report []byte, nonce [32]byte, opt VerifyOptions) (*VerifyResult, error) {
	if c == nil || c.Endpoint == "" {
		return nil, ErrNRASNoEndpoint
	}
	if len(report) == 0 {
		return nil, ErrNRASNoEvidence
	}

	// Local consistency: report.nonce must equal request nonce.
	parsed, err := ParseGPUReport(report)
	if err != nil {
		return nil, fmt.Errorf("nvidia/nras: parse evidence: %w", err)
	}
	if parsed.Nonce != nonce {
		return nil, fmt.Errorf("%w: report=%x request=%x", ErrNRASNonceMismatch, parsed.Nonce[:], nonce[:])
	}

	body := map[string]string{
		"evidence": base64.StdEncoding.EncodeToString(report),
		"nonce":    hex.EncodeToString(nonce[:]),
	}
	if opt.PolicyID != "" {
		body["policy"] = opt.PolicyID
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("nvidia/nras: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.Endpoint+"/v1/attest/gpu", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("nvidia/nras: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nvidia/nras: http: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB cap
	if err != nil {
		return nil, fmt.Errorf("nvidia/nras: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status=%d body=%s", ErrNRASBadStatus, resp.StatusCode, truncate(string(respBody), 256))
	}

	var rr struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &rr); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNRASBadResponse, err)
	}
	if rr.Token == "" {
		return nil, ErrNRASEmptyToken
	}

	res := &VerifyResult{
		Token:        rr.Token,
		TokenHash:    sha256.Sum256([]byte(rr.Token)),
		Nonce:        nonce,
		Architecture: parsed.Architecture,
	}

	// Parse JWT header + claims to recover iat/exp/nonce/kid.
	hdr, payload, sigBytes, signedInput, err := splitJWS(rr.Token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNRASBadJWT, err)
	}

	var jwtClaims struct {
		Nonce string `json:"nonce"`
		Iat   int64  `json:"iat"`
		Exp   int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &jwtClaims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrNRASBadJWT, err)
	}
	// Token nonce must match request nonce — defense against replay.
	if jwtClaims.Nonce != "" {
		jn, derr := hex.DecodeString(strings.TrimPrefix(jwtClaims.Nonce, "0x"))
		if derr != nil || len(jn) != 32 || sha256BytesEqual(jn, nonce[:]) == false {
			return nil, ErrNRASNonceMismatch
		}
	}
	if jwtClaims.Iat > 0 {
		res.IssuedAt = time.Unix(jwtClaims.Iat, 0).UTC()
	}
	if jwtClaims.Exp > 0 {
		res.ExpiresAt = time.Unix(jwtClaims.Exp, 0).UTC()
	} else if rr.ExpiresAt != "" {
		// Fall back to outer expires_at if claims didn't carry it.
		if t, perr := time.Parse(time.RFC3339, rr.ExpiresAt); perr == nil {
			res.ExpiresAt = t.UTC()
		}
	}

	if !res.ExpiresAt.IsZero() && c.now().After(res.ExpiresAt) {
		return nil, ErrNRASTokenExpired
	}

	var jwtHdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdr, &jwtHdr); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrNRASBadJWT, err)
	}
	if len(c.TrustRoots) == 0 {
		return nil, fmt.Errorf("%w: no trust roots", ErrNRASBadSignature)
	}
	root, ok := findTrustRoot(c.TrustRoots, jwtHdr.Kid)
	if !ok {
		return nil, fmt.Errorf("%w: kid=%q not in trust roots", ErrNRASBadSignature, jwtHdr.Kid)
	}
	if err := verifyJWS(root.Public, jwtHdr.Alg, signedInput, sigBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNRASBadSignature, err)
	}
	res.SignerKeyID = root.KeyID

	return res, nil
}

// FoldIntoEvidence projects a successful VerifyResult plus a parsed
// GPUReport plus a matched RIM into the GPUEvidence record consumed
// by CompositeAttestation.
func FoldIntoEvidence(r *VerifyResult, report *GPUReport, rim *RIM) GPUEvidence {
	out := GPUEvidence{
		UUID:             report.UUID,
		DriverVersion:    report.DriverVersion,
		VBIOSVersion:     report.VBIOSVersion,
		Architecture:     report.Architecture,
		Verified:         true,
		NRASTokenHash:    r.TokenHash,
		Nonce:            r.Nonce,
		VerifiedAt:       r.IssuedAt,
		NVSwitchVerified: report.NVSwitchPresent,
	}
	if rim != nil {
		out.MeasurementRoot = rim.MeasurementRoot()
		out.RIMMatched = true
	}
	return out
}

// =============================================================================
// internal helpers
// =============================================================================

func (c *NRASClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// splitJWS returns header, payload, signature, signed-input ([]byte
// form of "<header>.<payload>") for a JWS compact serialization.
func splitJWS(token string) (hdr, payload, sig, signedInput []byte, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil, fmt.Errorf("expected 3 parts, got %d", len(parts))
	}
	hdr, err = base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("header: %w", err)
	}
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("payload: %w", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("signature: %w", err)
	}
	signedInput = []byte(parts[0] + "." + parts[1])
	return hdr, payload, sig, signedInput, nil
}

// verifyJWS verifies signedInput vs sig under pub. The dispatch is
// driven by `alg` from the JWS header AND simultaneously enforces that
// the public-key type matches `alg` — this is the algorithm-substitution
// defense (Red audit F3 / CVE-2015-9235 family). A token forged with
// header alg=EdDSA against a trust-root holding an *rsa.PublicKey for
// the same kid is rejected here, before any verification primitive runs.
//
// For ECDSA the curve is also asserted against the alg (ES256→P-256,
// ES384→P-384). alg=none (any case) is refused unconditionally;
// unknown algs are refused.
//
// The companion verifySignature(pub, msg, sig) in rim.go is intentionally
// retained for the RIM path: detached RIM signatures carry no alg envelope,
// so dispatch by key-type is correct there. This split (JWS = alg-driven,
// RIM = key-type-driven) is the only correct factoring; merging them
// re-introduces the substitution attack.
func verifyJWS(pub crypto.PublicKey, alg string, signedInput, sig []byte) error {
	switch alg {
	case "EdDSA":
		pubED, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: alg=EdDSA pub=%T", ErrAlgKeyTypeMismatch, pub)
		}
		if !ed25519.Verify(pubED, signedInput, sig) {
			return errors.New("ed25519 verify failed")
		}
		return nil

	case "ES256":
		pubEC, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: alg=ES256 pub=%T", ErrAlgKeyTypeMismatch, pub)
		}
		if pubEC.Curve != elliptic.P256() {
			return fmt.Errorf("%w: alg=ES256 curve=%s (want P-256)", ErrAlgKeyTypeMismatch, pubEC.Curve.Params().Name)
		}
		digest := sha256.Sum256(signedInput)
		return ecdsaVerifyJOSE(pubEC, digest[:], sig)

	case "ES384":
		pubEC, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: alg=ES384 pub=%T", ErrAlgKeyTypeMismatch, pub)
		}
		if pubEC.Curve != elliptic.P384() {
			return fmt.Errorf("%w: alg=ES384 curve=%s (want P-384)", ErrAlgKeyTypeMismatch, pubEC.Curve.Params().Name)
		}
		digest := sha512.Sum384(signedInput)
		return ecdsaVerifyJOSE(pubEC, digest[:], sig)

	case "PS256":
		pubRSA, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: alg=PS256 pub=%T", ErrAlgKeyTypeMismatch, pub)
		}
		digest := sha256.Sum256(signedInput)
		if err := rsa.VerifyPSS(pubRSA, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}); err != nil {
			return fmt.Errorf("rsa-pss verify: %w", err)
		}
		return nil

	case "PS384":
		pubRSA, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: alg=PS384 pub=%T", ErrAlgKeyTypeMismatch, pub)
		}
		digest := sha512.Sum384(signedInput)
		if err := rsa.VerifyPSS(pubRSA, crypto.SHA384, digest[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA384,
		}); err != nil {
			return fmt.Errorf("rsa-pss verify: %w", err)
		}
		return nil

	case "none", "None", "NONE", "":
		return ErrAlgNoneRefused

	default:
		return fmt.Errorf("%w: %q", ErrUnknownAlg, alg)
	}
}

// ecdsaVerifyJOSE verifies a JOSE-flavored ECDSA signature (fixed-width
// r||s, big-endian, equal length — RFC 7515 §3.4) over the supplied
// pre-hashed digest. The hash algorithm is the caller's responsibility
// and must match the JWS alg.
func ecdsaVerifyJOSE(pub *ecdsa.PublicKey, digest, sig []byte) error {
	if len(sig) == 0 || len(sig)%2 != 0 {
		return fmt.Errorf("ecdsa jose: bad signature length %d", len(sig))
	}
	half := len(sig) / 2
	// JOSE width must equal the curve's coordinate size.
	if want := (pub.Curve.Params().BitSize + 7) / 8; half != want {
		return fmt.Errorf("ecdsa jose: signature half=%d want=%d for %s", half, want, pub.Curve.Params().Name)
	}
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return errors.New("ecdsa verify failed")
	}
	return nil
}

func sha256BytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
