// Unit tests for device-chain parsing/validation and the EAT x5c branch.
package nvidia

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func testNow() time.Time { return time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC) }

func mkTestCert(t *testing.T, tmpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

func toPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// chain3 builds root -> intermediate -> leaf (P-384).
func chain3(t *testing.T, now time.Time) (root, interm, leaf *x509.Certificate) {
	t.Helper()
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	lk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	root = mkTestCert(t, rt, rt, rk.Public(), rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "interm"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	interm = mkTestCert(t, it, root, ik.Public(), rk)
	lt := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	leaf = mkTestCert(t, lt, interm, lk.Public(), ik)
	return
}

func TestParseCertChainPEM_Errors(t *testing.T) {
	if _, err := ParseCertChainPEM(nil); !errors.Is(err, ErrChainEmpty) {
		t.Fatalf("nil: %v", err)
	}
	if _, err := ParseCertChainPEM([]string{"not pem"}); !errors.Is(err, ErrChainEmpty) {
		t.Fatalf("garbage: %v", err)
	}
}

func TestVerifyDeviceChain_Valid(t *testing.T) {
	now := testNow()
	root, interm, leaf := chain3(t, now)
	chain, err := ParseCertChainPEM([]string{toPEM(leaf), toPEM(interm)})
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	got, err := VerifyDeviceChain(chain, pool, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject.CommonName != "leaf" {
		t.Fatalf("leaf = %q", got.Subject.CommonName)
	}
}

func TestVerifyDeviceChain_Untrusted(t *testing.T) {
	now := testNow()
	_, interm, leaf := chain3(t, now)
	chain, _ := ParseCertChainPEM([]string{toPEM(leaf), toPEM(interm)})
	// Empty pool -> leaf cannot chain to any pinned root.
	if _, err := VerifyDeviceChain(chain, x509.NewCertPool(), now); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("err = %v, want ErrChainUntrusted", err)
	}
	if _, err := VerifyDeviceChain(chain, nil, now); !errors.Is(err, ErrChainNoRoots) {
		t.Fatalf("nil roots: err = %v, want ErrChainNoRoots", err)
	}
}

func TestVerifyDeviceChain_Expired(t *testing.T) {
	now := testNow()
	root, interm, leaf := chain3(t, now)
	chain, _ := ParseCertChainPEM([]string{toPEM(leaf), toPEM(interm)})
	pool := x509.NewCertPool()
	pool.AddCert(root)
	// Two hours later, the 1-hour-validity certs are expired.
	if _, err := VerifyDeviceChain(chain, pool, now.Add(2*time.Hour)); !errors.Is(err, ErrChainUntrusted) {
		t.Fatalf("err = %v, want ErrChainUntrusted (expired)", err)
	}
}

// EAT x5c branch: a token whose x5c chains to the pinned NRAS root pool is
// accepted via the leaf key (no kid pin needed).
func TestVerifyEAT_X5CChain(t *testing.T) {
	now := testNow()
	// The leaf key signs the JWS; build a dedicated NRAS chain with a known
	// leaf key (root -> interm -> leaf) and pin the NRAS root.
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "nras-leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	ik, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "nras-interm"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	rk, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(6), Subject: pkix.Name{CommonName: "nras-root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	nrasRoot := mkTestCert(t, rt, rt, rk.Public(), rk)
	nrasInterm := mkTestCert(t, it, nrasRoot, ik.Public(), rk)
	nrasLeaf := mkTestCert(t, lt, nrasInterm, lk.Public(), ik)

	hdr := map[string]any{
		"alg": "ES256",
		"x5c": []string{
			base64.StdEncoding.EncodeToString(nrasLeaf.Raw),
			base64.StdEncoding.EncodeToString(nrasInterm.Raw),
		},
	}
	claims := map[string]any{"exp": now.Add(time.Hour).Unix(), "x-nvidia-overall-att-result": true}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signedInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signedInput))
	r, s, _ := ecdsa.Sign(rand.Reader, lk, sum[:])
	token := signedInput + "." + base64.RawURLEncoding.EncodeToString(joseConcat(r, s, 32))

	pool := x509.NewCertPool()
	pool.AddCert(nrasRoot)
	res, err := VerifyEAT(token, nil, pool, nil, now)
	if err != nil {
		t.Fatalf("eat x5c verify: %v", err)
	}
	if res.OverallResult != "true" {
		t.Fatalf("result = %q", res.OverallResult)
	}

	// A token whose x5c does NOT chain to the pinned pool is refused.
	if _, err := VerifyEAT(token, nil, x509.NewCertPool(), nil, now); !errors.Is(err, ErrEATChainUntrusted) {
		t.Fatalf("untrusted x5c: err = %v, want ErrEATChainUntrusted", err)
	}
}
