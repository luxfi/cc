package nvidia

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockServer returns a stub NRAS that signs an EdDSA token.
type mockServer struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	keyID     string
	now       func() time.Time
	wantNonce *[32]byte
	failHTTP  int
	failBody  bool
}

func newMockServer(t *testing.T) *mockServer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return &mockServer{
		priv:  priv,
		pub:   pub,
		keyID: "nras-test-1",
		now:   func() time.Time { return time.Unix(1735689600, 0).UTC() },
	}
}

func (m *mockServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/attest/gpu" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Evidence string `json:"evidence"`
			Nonce    string `json:"nonce"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if m.wantNonce != nil {
			if req.Nonce != hex.EncodeToString((*m.wantNonce)[:]) {
				http.Error(w, "nonce mismatch", http.StatusBadRequest)
				return
			}
		}
		if m.failHTTP != 0 {
			http.Error(w, "configured failure", m.failHTTP)
			return
		}

		// Build a tiny JWT.
		hdr := map[string]string{"alg": "EdDSA", "kid": m.keyID, "typ": "JWT"}
		hdrJSON, _ := json.Marshal(hdr)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)

		now := m.now()
		claims := map[string]interface{}{
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
			"nonce": req.Nonce,
		}
		clmJSON, _ := json.Marshal(claims)
		clmB64 := base64.RawURLEncoding.EncodeToString(clmJSON)

		signedInput := hdrB64 + "." + clmB64
		sig := ed25519.Sign(m.priv, []byte(signedInput))
		token := signedInput + "." + base64.RawURLEncoding.EncodeToString(sig)

		resp := map[string]string{
			"token":      token,
			"expires_at": now.Add(time.Hour).Format(time.RFC3339),
		}
		if m.failBody {
			w.Write([]byte("{not json"))
			return
		}
		out, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}
}

// helper — build a valid GPU report bound to nonce.
func reportBytes(nonce [32]byte) []byte {
	return []byte(fmt.Sprintf(`{
  "evidence_version": "2.1",
  "gpu_uuid": "GPU-AAAA-BBBB",
  "architecture": "Hopper",
  "driver_version": "535.104.05",
  "vbios_version": "96.00.74.00.01",
  "nonce": "%s",
  "measurements": [{"name":"FW","value":"00"}]
}`, hex.EncodeToString(nonce[:])))
}

func TestNRAS_HappyPath(t *testing.T) {
	m := newMockServer(t)
	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	roots := []TrustRoot{{KeyID: m.keyID, Public: m.pub}}
	c := NewNRASClient(srv.URL, roots)
	c.Now = m.now

	var nonce [32]byte
	rand.Read(nonce[:])
	m.wantNonce = &nonce

	res, err := c.Verify(context.Background(), reportBytes(nonce), nonce, VerifyOptions{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Token == "" || res.SignerKeyID != m.keyID {
		t.Fatalf("bad result: %+v", res)
	}
	if res.Nonce != nonce {
		t.Fatalf("nonce drift: got %x want %x", res.Nonce, nonce)
	}
	if res.IssuedAt.IsZero() || res.ExpiresAt.IsZero() {
		t.Fatalf("times unset: %+v", res)
	}
	wantHash := sha256.Sum256([]byte(res.Token))
	if res.TokenHash != wantHash {
		t.Fatal("token hash drift")
	}
}

func TestNRAS_RejectsNonceMismatch(t *testing.T) {
	m := newMockServer(t)
	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	roots := []TrustRoot{{KeyID: m.keyID, Public: m.pub}}
	c := NewNRASClient(srv.URL, roots)
	c.Now = m.now

	var nonceA, nonceB [32]byte
	rand.Read(nonceA[:])
	rand.Read(nonceB[:])

	// Report carries nonceA, request says nonceB → reject locally.
	_, err := c.Verify(context.Background(), reportBytes(nonceA), nonceB, VerifyOptions{})
	if !errors.Is(err, ErrNRASNonceMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestNRAS_RejectsBadStatus(t *testing.T) {
	m := newMockServer(t)
	m.failHTTP = http.StatusUnauthorized
	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	c := NewNRASClient(srv.URL, []TrustRoot{{KeyID: m.keyID, Public: m.pub}})
	c.Now = m.now

	var nonce [32]byte
	rand.Read(nonce[:])
	_, err := c.Verify(context.Background(), reportBytes(nonce), nonce, VerifyOptions{})
	if !errors.Is(err, ErrNRASBadStatus) {
		t.Fatalf("got %v", err)
	}
}

func TestNRAS_RejectsMalformedBody(t *testing.T) {
	m := newMockServer(t)
	m.failBody = true
	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	c := NewNRASClient(srv.URL, []TrustRoot{{KeyID: m.keyID, Public: m.pub}})
	c.Now = m.now

	var nonce [32]byte
	rand.Read(nonce[:])
	_, err := c.Verify(context.Background(), reportBytes(nonce), nonce, VerifyOptions{})
	if !errors.Is(err, ErrNRASBadResponse) {
		t.Fatalf("got %v", err)
	}
}

func TestNRAS_RejectsExpiredToken(t *testing.T) {
	m := newMockServer(t)
	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	roots := []TrustRoot{{KeyID: m.keyID, Public: m.pub}}
	c := NewNRASClient(srv.URL, roots)
	// client clock 25h after server's "now"
	c.Now = func() time.Time { return m.now().Add(25 * time.Hour) }

	var nonce [32]byte
	rand.Read(nonce[:])
	_, err := c.Verify(context.Background(), reportBytes(nonce), nonce, VerifyOptions{})
	if !errors.Is(err, ErrNRASTokenExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestNRAS_RejectsNoTrustRoots(t *testing.T) {
	m := newMockServer(t)
	srv := httptest.NewServer(m.handler())
	defer srv.Close()

	c := NewNRASClient(srv.URL, nil)
	c.Now = m.now

	var nonce [32]byte
	rand.Read(nonce[:])
	_, err := c.Verify(context.Background(), reportBytes(nonce), nonce, VerifyOptions{})
	if !errors.Is(err, ErrNRASBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestNRAS_RejectsNoEndpoint(t *testing.T) {
	c := NewNRASClient("", nil)
	var n [32]byte
	if _, err := c.Verify(context.Background(), []byte("x"), n, VerifyOptions{}); !errors.Is(err, ErrNRASNoEndpoint) {
		t.Fatalf("got %v", err)
	}
}

func TestNRAS_RejectsEmptyEvidence(t *testing.T) {
	c := NewNRASClient("https://x", nil)
	var n [32]byte
	if _, err := c.Verify(context.Background(), nil, n, VerifyOptions{}); !errors.Is(err, ErrNRASNoEvidence) {
		t.Fatalf("got %v", err)
	}
}

// JOSE ECDSA path — token signed with ES256 must parse + verify after
// the JOSE-to-ASN.1 conversion in verifyJWS.
func TestNRAS_ECDSAToken(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	keyID := "ecdsa-server"
	now := time.Unix(1735689600, 0).UTC()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/gpu", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct{ Nonce string }
		_ = json.Unmarshal(body, &req)

		hdr := map[string]string{"alg": "ES256", "kid": keyID, "typ": "JWT"}
		hdrJSON, _ := json.Marshal(hdr)
		hdrB64 := base64.RawURLEncoding.EncodeToString(hdrJSON)
		claims := map[string]interface{}{
			"iat":   now.Unix(),
			"exp":   now.Add(time.Hour).Unix(),
			"nonce": req.Nonce,
		}
		clmJSON, _ := json.Marshal(claims)
		clmB64 := base64.RawURLEncoding.EncodeToString(clmJSON)
		signedInput := hdrB64 + "." + clmB64
		digest := sha256.Sum256([]byte(signedInput))
		// JOSE ES256: r||s, fixed 32 bytes each.
		r2, s2, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jose := joseEncode(r2, s2, 32)
		token := signedInput + "." + base64.RawURLEncoding.EncodeToString(jose)
		out, _ := json.Marshal(map[string]string{
			"token":      token,
			"expires_at": now.Add(time.Hour).Format(time.RFC3339),
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewNRASClient(srv.URL, []TrustRoot{{KeyID: keyID, Public: &priv.PublicKey}})
	c.Now = func() time.Time { return now }

	var nonce [32]byte
	rand.Read(nonce[:])
	if _, err := c.Verify(context.Background(), reportBytes(nonce), nonce, VerifyOptions{}); err != nil {
		t.Fatalf("verify ecdsa: %v", err)
	}
}

func joseEncode(r, s *big.Int, sz int) []byte {
	out := make([]byte, sz*2)
	rB := r.Bytes()
	sB := s.Bytes()
	copy(out[sz-len(rB):sz], rB)
	copy(out[sz*2-len(sB):], sB)
	return out
}

func TestFoldIntoEvidence(t *testing.T) {
	report, err := ParseGPUReport(goodReportJSON())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rim := &RIM{
		Architecture:  "Hopper",
		DriverVersion: "535.104.05",
		VBIOSVersion:  "96.00.74.00.01",
		Entries: []RIMEntry{
			{Name: "FW_RUNTIME", ValueHex: "deadbeef00112233"},
			{Name: "VBIOS_RT", ValueHex: "cafebabe44556677"},
		},
	}
	res := &VerifyResult{
		Token: "abc.def.ghi", TokenHash: sha256.Sum256([]byte("abc.def.ghi")),
		Nonce: report.Nonce, IssuedAt: time.Now(),
	}
	ev := FoldIntoEvidence(res, report, rim)
	if !ev.Verified || !ev.RIMMatched {
		t.Fatalf("not verified: %+v", ev)
	}
	if ev.MeasurementRoot != rim.MeasurementRoot() {
		t.Fatal("measurement root drift")
	}
	if !strings.HasPrefix(ev.UUID, "GPU-") {
		t.Fatalf("uuid: %s", ev.UUID)
	}
}
