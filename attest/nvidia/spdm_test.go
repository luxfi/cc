// Unit tests for the DSP0274 SPDM measurement-report parser and signature
// verifier. These exercise the primitive directly (the cc/attest end-to-end
// tests drive it through the NVTrust Kind); the focus here is wire-parse
// robustness and the algorithm <-> key-type substitution defense.
package nvidia

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"
)

func le16b(v int) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(v))
	return b
}

func le24b(v int) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16)} }

// buildSPDM builds a (request, response) pair: a single measurement block
// at the given index/value, signed with leafPriv (ECDSA P-384, SPDM 1.1).
func buildSPDM(t *testing.T, leafPriv *ecdsa.PrivateKey, idx uint8, value []byte) (req, resp []byte) {
	t.Helper()
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	req = []byte{0x11, 0xE0, 0x01, 0xFF}
	req = append(req, nonce[:]...)
	req = append(req, 0x00)

	dmtf := []byte{0x00}
	dmtf = append(dmtf, le16b(len(value))...)
	dmtf = append(dmtf, value...)
	blk := []byte{idx, 0x01}
	blk = append(blk, le16b(len(dmtf))...)
	blk = append(blk, dmtf...)

	var respNonce [32]byte
	body := []byte{0x11, 0x60, 0x00, 0x00, 1}
	body = append(body, le24b(len(blk))...)
	body = append(body, blk...)
	body = append(body, respNonce[:]...)
	body = append(body, le16b(0)...)

	h := sha512.New384()
	h.Write(req)
	h.Write(body)
	digest := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, leafPriv, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := joseConcat(r, s, 48)
	return req, append(body, sig...)
}

func TestSPDM_VerifyValid_ExtractsMeasurement(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	val := bytes.Repeat([]byte{0xAB}, 48)
	req, resp := buildSPDM(t, priv, 7, val)

	parsed, err := VerifySPDMMeasurementSignature(&priv.PublicKey, SPDMAsymECDSAP384SHA384, req, resp)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(parsed.Measurements) != 1 || parsed.Measurements[0].Index != 7 {
		t.Fatalf("measurements = %+v", parsed.Measurements)
	}
	if !bytes.Equal(parsed.Measurements[0].Value, val) {
		t.Fatalf("value = %x want %x", parsed.Measurements[0].Value, val)
	}
}

func TestSPDM_RejectsTamperedSignature(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	req, resp := buildSPDM(t, priv, 0, bytes.Repeat([]byte{0x01}, 48))
	resp[len(resp)-1] ^= 0xFF
	_, err := VerifySPDMMeasurementSignature(&priv.PublicKey, SPDMAsymECDSAP384SHA384, req, resp)
	if !errors.Is(err, ErrSPDMSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSPDMSignatureInvalid", err)
	}
}

func TestSPDM_RejectsWrongKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	req, resp := buildSPDM(t, priv, 0, bytes.Repeat([]byte{0x01}, 48))
	_, err := VerifySPDMMeasurementSignature(&other.PublicKey, SPDMAsymECDSAP384SHA384, req, resp)
	if !errors.Is(err, ErrSPDMSignatureInvalid) {
		t.Fatalf("err = %v, want ErrSPDMSignatureInvalid", err)
	}
}

// Algorithm-substitution defense: a P-384 algo paired with a non-P-384 key
// is refused before verification (mirrors the JWS alg<->key binding).
func TestSPDM_AlgKeyTypeMismatch(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	req, resp := buildSPDM(t, p384, 0, bytes.Repeat([]byte{0x01}, 48))

	// P-384 algo, P-256 key.
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := VerifySPDMMeasurementSignature(&p256.PublicKey, SPDMAsymECDSAP384SHA384, req, resp); !errors.Is(err, ErrSPDMAlgKeyMismatch) {
		t.Fatalf("p256 key: err = %v, want ErrSPDMAlgKeyMismatch", err)
	}
	// P-384 algo, RSA key.
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := VerifySPDMMeasurementSignature(&rsaKey.PublicKey, SPDMAsymECDSAP384SHA384, req, resp); !errors.Is(err, ErrSPDMAlgKeyMismatch) {
		t.Fatalf("rsa key: err = %v, want ErrSPDMAlgKeyMismatch", err)
	}
}

func TestSPDM_RejectsTruncated(t *testing.T) {
	if _, err := ParseSPDMMeasurementResponse([]byte{0x11, 0x60, 0, 0}, 96); !errors.Is(err, ErrSPDMShort) {
		t.Fatalf("short header: err = %v, want ErrSPDMShort", err)
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, resp := buildSPDM(t, priv, 0, bytes.Repeat([]byte{0x01}, 48))
	if _, err := ParseSPDMMeasurementResponse(resp[:len(resp)-10], 96); !errors.Is(err, ErrSPDMTruncated) {
		t.Fatalf("truncated body: err = %v, want ErrSPDMTruncated", err)
	}
}

func TestSPDM_RejectsBadResponseCode(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, resp := buildSPDM(t, priv, 0, bytes.Repeat([]byte{0x01}, 48))
	resp[1] = 0x61 // not MEASUREMENTS
	if _, err := ParseSPDMMeasurementResponse(resp, 96); !errors.Is(err, ErrSPDMBadCode) {
		t.Fatalf("err = %v, want ErrSPDMBadCode", err)
	}
}

func TestSPDM_RequestNonce(t *testing.T) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}
	req := []byte{0x11, 0xE0, 0x01, 0xFF}
	req = append(req, nonce[:]...)
	req = append(req, 0x00)
	v, got, err := SPDMRequestNonce(req)
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if v != 0x11 || got != nonce {
		t.Fatalf("version=0x%02x nonce=%x", v, got)
	}
	// A request that did not ask for a signature is refused.
	req[2] = 0x00
	if _, _, err := SPDMRequestNonce(req); !errors.Is(err, ErrSPDMNoSignature) {
		t.Fatalf("no-sig: err = %v, want ErrSPDMNoSignature", err)
	}
}
