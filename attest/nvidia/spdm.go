// SPDM (DMTF DSP0274) measurement-report parsing and signature
// verification — the cryptographic core of NVIDIA GPU confidential-compute
// local attestation.
//
// An NVIDIA CC-capable GPU (Hopper H100/H200, Blackwell B100/B200/GB200)
// produces an attestation report that is a signed SPDM MEASUREMENTS
// response (RequestResponseCode 0x60, DSP0274). The report carries the
// DMTF measurement blocks the GPU firmware measured, a responder nonce,
// optional opaque data, and a signature produced by the GPU's attestation
// key. The matching GET_MEASUREMENTS request (0xE0) carries the requester
// nonce (the host's freshness challenge). The signature covers the
// transcript request || response[:-signature], so verifying it binds the
// measurement record AND the requester nonce to the GPU attestation key.
//
// This file implements:
//   - the DSP0274 wire parse of the 0xE0 request and 0x60 response,
//   - extraction of DMTF measurement blocks (index + signed digest),
//   - the DSP0274 transcript / signing-context construction for SPDM 1.1
//     and 1.2, and
//   - signature verification with a strict algorithm <-> key-type binding
//     (the same algorithm-substitution defense the NRAS JWS path uses).
//
// What makes the result trustworthy is the COMBINATION with devicechain.go:
// the public key that verifies the SPDM signature is the leaf of a cert
// chain that VerifyDeviceChain anchors to an operator-pinned NVIDIA device-
// identity root. SPDM signature alone proves "some key signed these
// measurements"; the chain proves "that key is a genuine NVIDIA GPU key".
//
// Clean-room: this is an implementation of the publicly documented DMTF
// DSP0274 schema. No NVIDIA proprietary code or keys are vendored.
package nvidia

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// Errors returned by the SPDM parser / verifier.
var (
	ErrSPDMShort            = errors.New("nvidia/spdm: message shorter than header")
	ErrSPDMBadCode          = errors.New("nvidia/spdm: unexpected RequestResponseCode")
	ErrSPDMBadVersion       = errors.New("nvidia/spdm: unsupported SPDM version")
	ErrSPDMTruncated        = errors.New("nvidia/spdm: message truncated mid-field")
	ErrSPDMNoSignature      = errors.New("nvidia/spdm: response carries no signature")
	ErrSPDMBadMeasRecord    = errors.New("nvidia/spdm: malformed measurement record")
	ErrSPDMUnsupportedAlgo  = errors.New("nvidia/spdm: unsupported asym/hash algorithm")
	ErrSPDMAlgKeyMismatch   = errors.New("nvidia/spdm: asym algo does not match leaf key type")
	ErrSPDMSignatureInvalid = errors.New("nvidia/spdm: measurement-report signature invalid")
	ErrSPDMNonceLength      = errors.New("nvidia/spdm: request nonce not present / wrong length")
)

// SPDM message opcodes (DSP0274).
const (
	spdmGetMeasurements byte = 0xE0 // request
	spdmMeasurements    byte = 0x60 // response
)

// Supported SPDM version bytes. The version byte is encoded as
// (major<<4)|minor: 0x11 = SPDM 1.1, 0x12 = SPDM 1.2. Hopper attestation
// uses 1.1; Blackwell uses 1.2.
const (
	spdmVersion11 byte = 0x11
	spdmVersion12 byte = 0x12
)

// SPDMAsymAlgo names the asymmetric signature algorithm the GPU used to
// sign the MEASUREMENTS response. It binds three things together —
// signature length (needed to split the signed body from the trailing
// signature), the hash used in the transcript, and the public-key type
// the verifier must hold — so an attacker cannot substitute one for
// another. NVIDIA Hopper/Blackwell attestation keys are ECDSA P-384.
type SPDMAsymAlgo uint8

const (
	// SPDMAsymECDSAP384SHA384 — ECDSA on NIST P-384 with SHA-384. The
	// NVIDIA Hopper/Blackwell GPU attestation-key algorithm. Signature is
	// fixed-width r||s, 96 bytes.
	SPDMAsymECDSAP384SHA384 SPDMAsymAlgo = iota + 1
	// SPDMAsymECDSAP256SHA256 — ECDSA P-256 / SHA-256, 64-byte r||s.
	SPDMAsymECDSAP256SHA256
	// SPDMAsymRSAPSS3072SHA384 — RSASSA-PSS, 3072-bit, SHA-384, 384-byte sig.
	SPDMAsymRSAPSS3072SHA384
)

// ParseSPDMAsymAlgo maps the envelope's wire string to an algo. Unknown
// strings are refused (no silent default — the asym algo is a security
// parameter).
func ParseSPDMAsymAlgo(s string) (SPDMAsymAlgo, error) {
	switch s {
	case "ecdsa-p384-sha384", "ecdsa-p384", "ECDSA_P384", "":
		// Empty string defaults to the NVIDIA production algorithm
		// (ECDSA P-384), the only algo current CC GPUs emit. This is a
		// convenience for the common case, not an insecure fallback: the
		// signature still must verify under a P-384 leaf key, and a non-
		// P-384 leaf is refused by the alg<->key binding below.
		return SPDMAsymECDSAP384SHA384, nil
	case "ecdsa-p256-sha256", "ecdsa-p256", "ECDSA_P256":
		return SPDMAsymECDSAP256SHA256, nil
	case "rsa-pss-3072-sha384", "rsapss3072":
		return SPDMAsymRSAPSS3072SHA384, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrSPDMUnsupportedAlgo, s)
	}
}

// sigLen returns the fixed signature length in bytes for the algo.
func (a SPDMAsymAlgo) sigLen() int {
	switch a {
	case SPDMAsymECDSAP384SHA384:
		return 96
	case SPDMAsymECDSAP256SHA256:
		return 64
	case SPDMAsymRSAPSS3072SHA384:
		return 384
	default:
		return 0
	}
}

// newHash returns a fresh hash for the algo's transcript hash function.
func (a SPDMAsymAlgo) newHash() hash.Hash {
	switch a {
	case SPDMAsymECDSAP256SHA256:
		return sha256.New()
	default: // P-384 and RSA-PSS-3072 use SHA-384
		return sha512.New384()
	}
}

func (a SPDMAsymAlgo) String() string {
	switch a {
	case SPDMAsymECDSAP384SHA384:
		return "ecdsa-p384-sha384"
	case SPDMAsymECDSAP256SHA256:
		return "ecdsa-p256-sha256"
	case SPDMAsymRSAPSS3072SHA384:
		return "rsa-pss-3072-sha384"
	default:
		return "unknown"
	}
}

// SPDMMeasurement is one DMTF measurement block extracted from a verified
// MEASUREMENTS response. Index is the SPDM measurement index (the stable
// identifier the RIM keys golden values by). Value is the raw measurement
// value (a SHA-384 digest for the digest value-type, or raw bytes for the
// raw value-type).
type SPDMMeasurement struct {
	Index     uint8
	ValueType uint8 // DMTFSpecMeasurementValueType (bit7 = raw, bits[6:0]=type)
	Value     []byte
}

// IsRaw reports whether the block carries a raw value (bit7 set) rather
// than a digest.
func (m SPDMMeasurement) IsRaw() bool { return m.ValueType&0x80 != 0 }

// SPDMResponse is a parsed (not yet signature-verified) MEASUREMENTS
// response.
type SPDMResponse struct {
	Version        byte
	NumberOfBlocks uint8
	Measurements   []SPDMMeasurement
	ResponderNonce [32]byte
	OpaqueData     []byte
	Signature      []byte

	// signedBody is response[:len-sigLen] — the bytes the signature
	// covers. Retained so the verifier hashes exactly what was signed.
	signedBody []byte
}

// ParseSPDMMeasurementResponse parses a MEASUREMENTS (0x60) response,
// splitting off a trailing signature of sigLen bytes. It validates the
// header, walks the measurement record into typed blocks, and locates the
// nonce / opaque / signature fields by their DSP0274 offsets.
//
// sigLen must be the negotiated signature size; a response shorter than
// header+record+nonce+opaque+sigLen is rejected as truncated.
func ParseSPDMMeasurementResponse(msg []byte, sigLen int) (*SPDMResponse, error) {
	if sigLen <= 0 {
		return nil, ErrSPDMUnsupportedAlgo
	}
	// Fixed header: version, code, param1, param2, numblocks, recordlen(3).
	if len(msg) < 8 {
		return nil, ErrSPDMShort
	}
	version := msg[0]
	if version != spdmVersion11 && version != spdmVersion12 {
		return nil, fmt.Errorf("%w: 0x%02x", ErrSPDMBadVersion, version)
	}
	if msg[1] != spdmMeasurements {
		return nil, fmt.Errorf("%w: got 0x%02x want 0x60", ErrSPDMBadCode, msg[1])
	}
	numBlocks := msg[4]
	recordLen := int(msg[5]) | int(msg[6])<<8 | int(msg[7])<<16 // 3-byte LE

	off := 8
	if off+recordLen+32+2+sigLen > len(msg) {
		return nil, fmt.Errorf("%w: record=%d nonce=32 sig=%d total=%d", ErrSPDMTruncated, recordLen, sigLen, len(msg))
	}
	record := msg[off : off+recordLen]
	off += recordLen

	var responderNonce [32]byte
	copy(responderNonce[:], msg[off:off+32])
	off += 32

	opaqueLen := int(binary.LittleEndian.Uint16(msg[off : off+2]))
	off += 2
	if off+opaqueLen+sigLen > len(msg) {
		return nil, fmt.Errorf("%w: opaque=%d sig=%d total=%d", ErrSPDMTruncated, opaqueLen, sigLen, len(msg))
	}
	opaque := msg[off : off+opaqueLen]
	off += opaqueLen

	// The signature occupies the final sigLen bytes; anything after it is
	// trailing garbage and rejected.
	if off+sigLen != len(msg) {
		return nil, fmt.Errorf("%w: %d trailing bytes after signature", ErrSPDMTruncated, len(msg)-(off+sigLen))
	}
	sig := msg[off : off+sigLen]

	blocks, err := parseMeasurementBlocks(record, int(numBlocks))
	if err != nil {
		return nil, err
	}

	return &SPDMResponse{
		Version:        version,
		NumberOfBlocks: numBlocks,
		Measurements:   blocks,
		ResponderNonce: responderNonce,
		OpaqueData:     append([]byte(nil), opaque...),
		Signature:      append([]byte(nil), sig...),
		signedBody:     append([]byte(nil), msg[:len(msg)-sigLen]...),
	}, nil
}

// parseMeasurementBlocks walks the DMTF measurement record into numBlocks
// blocks. Each block: Index(1) MeasurementSpecification(1)
// MeasurementSize(2 LE) Measurement(MeasurementSize). The DMTF Measurement
// is itself ValueType(1) ValueSize(2 LE) Value(ValueSize).
func parseMeasurementBlocks(record []byte, numBlocks int) ([]SPDMMeasurement, error) {
	out := make([]SPDMMeasurement, 0, numBlocks)
	off := 0
	for i := 0; i < numBlocks; i++ {
		if off+4 > len(record) {
			return nil, fmt.Errorf("%w: block %d header past end", ErrSPDMBadMeasRecord, i)
		}
		index := record[off]
		// record[off+1] = MeasurementSpecification; we only support DMTF
		// (bit0). We do not hard-fail on the spec byte: NVIDIA always sets
		// DMTF, and the value-type below is what we actually consume.
		measSize := int(binary.LittleEndian.Uint16(record[off+2 : off+4]))
		off += 4
		if off+measSize > len(record) {
			return nil, fmt.Errorf("%w: block %d value past end", ErrSPDMBadMeasRecord, i)
		}
		dmtf := record[off : off+measSize]
		off += measSize

		if len(dmtf) < 3 {
			return nil, fmt.Errorf("%w: block %d dmtf shorter than 3", ErrSPDMBadMeasRecord, i)
		}
		valType := dmtf[0]
		valSize := int(binary.LittleEndian.Uint16(dmtf[1:3]))
		if 3+valSize != len(dmtf) {
			return nil, fmt.Errorf("%w: block %d dmtf value size %d != %d", ErrSPDMBadMeasRecord, i, valSize, len(dmtf)-3)
		}
		out = append(out, SPDMMeasurement{
			Index:     index,
			ValueType: valType,
			Value:     append([]byte(nil), dmtf[3:]...),
		})
	}
	if off != len(record) {
		return nil, fmt.Errorf("%w: %d trailing record bytes", ErrSPDMBadMeasRecord, len(record)-off)
	}
	return out, nil
}

// SPDMRequestNonce extracts the requester nonce from a GET_MEASUREMENTS
// (0xE0) request that requested a signature. The nonce is the host's
// freshness challenge; it lives at offset 4..36 when Param1 bit0 (signature
// requested) is set. Returns the nonce and the SPDM version.
//
// The request is part of the signed transcript, so a verified signature
// proves this nonce was bound by the GPU. Callers compare it to the
// challenge they issued (WithExpectedReportData).
func SPDMRequestNonce(req []byte) (version byte, nonce [32]byte, err error) {
	if len(req) < 4 {
		return 0, nonce, ErrSPDMShort
	}
	version = req[0]
	if version != spdmVersion11 && version != spdmVersion12 {
		return 0, nonce, fmt.Errorf("%w: 0x%02x", ErrSPDMBadVersion, version)
	}
	if req[1] != spdmGetMeasurements {
		return 0, nonce, fmt.Errorf("%w: got 0x%02x want 0xE0", ErrSPDMBadCode, req[1])
	}
	sigRequested := req[2]&0x01 != 0
	if !sigRequested {
		return 0, nonce, fmt.Errorf("%w: request did not ask for a signature", ErrSPDMNoSignature)
	}
	if len(req) < 4+32 {
		return 0, nonce, ErrSPDMNonceLength
	}
	copy(nonce[:], req[4:4+32])
	return version, nonce, nil
}

// VerifySPDMMeasurementSignature verifies the MEASUREMENTS response
// signature over the DSP0274 transcript request || response[:-sig] using
// leafPub, under the named algo. It returns the parsed, signature-verified
// response on success.
//
// The algo binds the signature length, the hash, AND the leaf key type:
// a P-384 algo against an RSA leaf (or vice versa) is refused before any
// verification primitive runs (ErrSPDMAlgKeyMismatch) — the same
// algorithm-substitution defense the NRAS JWS path applies.
func VerifySPDMMeasurementSignature(leafPub crypto.PublicKey, algo SPDMAsymAlgo, requestMsg, responseMsg []byte) (*SPDMResponse, error) {
	sigLen := algo.sigLen()
	if sigLen == 0 {
		return nil, ErrSPDMUnsupportedAlgo
	}
	resp, err := ParseSPDMMeasurementResponse(responseMsg, sigLen)
	if err != nil {
		return nil, err
	}
	// The request version must match the response version (a transcript
	// spanning two SPDM versions is malformed).
	reqVersion, _, err := SPDMRequestNonce(requestMsg)
	if err != nil {
		return nil, err
	}
	if reqVersion != resp.Version {
		return nil, fmt.Errorf("%w: request 0x%02x response 0x%02x", ErrSPDMBadVersion, reqVersion, resp.Version)
	}

	digest := spdmMeasurementDigest(algo, resp.Version, requestMsg, resp.signedBody)

	switch algo {
	case SPDMAsymECDSAP384SHA384, SPDMAsymECDSAP256SHA256:
		pub, ok := leafPub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: algo=%s leaf=%T", ErrSPDMAlgKeyMismatch, algo, leafPub)
		}
		wantCurve := "P-384"
		if algo == SPDMAsymECDSAP256SHA256 {
			wantCurve = "P-256"
		}
		if pub.Curve.Params().Name != wantCurve {
			return nil, fmt.Errorf("%w: algo=%s leaf curve=%s", ErrSPDMAlgKeyMismatch, algo, pub.Curve.Params().Name)
		}
		if err := ecdsaVerifyRaw(pub, digest, resp.Signature); err != nil {
			return nil, err
		}
		return resp, nil

	case SPDMAsymRSAPSS3072SHA384:
		pub, ok := leafPub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: algo=%s leaf=%T", ErrSPDMAlgKeyMismatch, algo, leafPub)
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA384, digest, resp.Signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA384,
		}); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSPDMSignatureInvalid, err)
		}
		return resp, nil

	default:
		return nil, ErrSPDMUnsupportedAlgo
	}
}

// spdmMeasurementDigest returns the digest the asymmetric primitive
// verifies against, per DSP0274:
//
//	M  = requestMsg || responseSignedBody          (the transcript L)
//	1.1: digest = Hash(M)
//	1.2: digest = Hash( SPDMSignedContext || Hash(M) )
//
// where SPDMSignedContext is the 100-byte responder-measurements signing
// context defined by DSP0274 1.2 (see spdmSigningContext).
func spdmMeasurementDigest(algo SPDMAsymAlgo, version byte, requestMsg, responseSignedBody []byte) []byte {
	h := algo.newHash()
	h.Write(requestMsg)
	h.Write(responseSignedBody)
	th := h.Sum(nil)

	ctx := spdmSigningContext(version)
	if ctx == nil {
		return th // SPDM 1.1: sign over Hash(M)
	}
	h2 := algo.newHash()
	h2.Write(ctx)
	h2.Write(th)
	return h2.Sum(nil) // SPDM 1.2: sign over Hash(ctx || Hash(M))
}

// spdmSigningContext builds the DSP0274 1.2 "SPDMSignedContext" prefix for
// a responder MEASUREMENTS signature. Returns nil for SPDM < 1.2 (which
// signs Hash(transcript) directly, no prefix).
//
// Layout (100 bytes total, per DSP0274 1.2 and libspdm/spdm-rs):
//
//	[0:64]   four copies of the 16-byte ASCII "dmtf-spdm-v1.2.*"
//	[64:70]  six zero bytes
//	[70:100] the 30-byte context "responder-measurements signing"
//
// NOTE (production integration): this prefix construction matches the DMTF
// spec and reference implementations. Confirming byte-exact agreement with
// a real Blackwell (SPDM 1.2) attestation report — including whether
// NVIDIA's firmware folds the VCA (GET_VERSION/CAPABILITIES/ALGORITHMS)
// transcript into M — requires a real B200/GB200 vector (documented
// collateral). Hopper (SPDM 1.1, the current production target) uses the
// no-prefix path and is fully exercised by the test vectors.
func spdmSigningContext(version byte) []byte {
	if version < spdmVersion12 {
		return nil
	}
	const prefixUnit = "dmtf-spdm-v1.2.*" // exactly 16 bytes
	const context = "responder-measurements signing"
	ctx := make([]byte, 100)
	for i := 0; i < 4; i++ {
		copy(ctx[i*16:(i+1)*16], prefixUnit)
	}
	// ctx[64:70] left zero; context is right-aligned in the 100-byte buffer.
	copy(ctx[100-len(context):], context)
	return ctx
}

// ecdsaVerifyRaw verifies a fixed-width r||s ECDSA signature (big-endian,
// equal halves — the SPDM/JOSE encoding, NOT DER) over a pre-computed
// digest.
func ecdsaVerifyRaw(pub *ecdsa.PublicKey, digest, sig []byte) error {
	coord := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*coord {
		return fmt.Errorf("%w: sig len %d != 2*%d", ErrSPDMSignatureInvalid, len(sig), coord)
	}
	r := new(big.Int).SetBytes(sig[:coord])
	s := new(big.Int).SetBytes(sig[coord:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return ErrSPDMSignatureInvalid
	}
	return nil
}
