// GPU evidence-report parser. The NVIDIA Confidential Compute stack
// produces a JSON-encoded "evidence" envelope that the host forwards
// to the NVIDIA Remote Attestation Service (NRAS). The envelope wraps
// a binary attestation report signed by the GPU's confidential-compute
// firmware plus the GPU's certificate chain.
//
// This parser is a clean-room implementation of the publicly
// documented schema (see nvTrust, NVIDIA Apache-2 release). We do NOT
// vendor NVIDIA proprietary code. Field names mirror the public spec
// so downstream code reads naturally against the documentation.
package nvidia

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by the parser.
var (
	ErrReportEmpty          = errors.New("nvidia/report: empty input")
	ErrReportBadJSON        = errors.New("nvidia/report: bad JSON envelope")
	ErrReportBadVersion     = errors.New("nvidia/report: unsupported evidence_version")
	ErrReportMissingNonce   = errors.New("nvidia/report: missing nonce")
	ErrReportBadNonce       = errors.New("nvidia/report: nonce must be 32 bytes hex")
	ErrReportMissingArch    = errors.New("nvidia/report: missing architecture")
	ErrReportUnknownArch    = errors.New("nvidia/report: unknown architecture")
	ErrReportNoMeasurements = errors.New("nvidia/report: no measurements present")
	ErrReportBadSPDM        = errors.New("nvidia/report: malformed SPDM request/response encoding")
)

// SupportedEvidenceVersions enumerates the report-envelope versions
// this parser understands. Bumped when NVIDIA ships a new schema.
var SupportedEvidenceVersions = map[string]bool{
	"2.0": true, // Hopper H100 GA
	"2.1": true, // Hopper post-launch fixes
	"3.0": true, // Blackwell B100/B200
}

// SupportedArchitectures enumerates the GPU architectures we recognise.
var SupportedArchitectures = map[string]bool{
	"Hopper":    true,
	"Blackwell": true,
}

// Measurement is one entry in the GPU's measurement list. PCRIndex
// follows the spec's natural numbering. Value is the raw measurement
// bytes (typically a 48-byte SHA-384 digest).
type Measurement struct {
	PCRIndex uint8  `json:"pcr_index"`
	Name     string `json:"name"`
	Value    []byte `json:"-"` // decoded from ValueHex
	ValueHex string `json:"value"`
}

// rawReport is the on-the-wire envelope. Field names are the
// canonical lower-snake spelling used by the NVIDIA evidence schema.
type rawReport struct {
	EvidenceVersion string        `json:"evidence_version"`
	GPUUUID         string        `json:"gpu_uuid"`
	Architecture    string        `json:"architecture"`
	DriverVersion   string        `json:"driver_version"`
	VBIOSVersion    string        `json:"vbios_version"`
	NonceHex        string        `json:"nonce"`
	Measurements    []Measurement `json:"measurements"`
	CertChain       []string      `json:"cert_chain"`        // PEM blocks, leaf first
	Quote           string        `json:"attestation_quote"` // legacy alias for spdm_response
	SPDMRequest     string        `json:"spdm_request"`      // base64: GET_MEASUREMENTS (0xE0)
	SPDMResponse    string        `json:"spdm_response"`     // base64: signed MEASUREMENTS (0x60)
	SPDMAsymAlgo    string        `json:"spdm_asym_algo"`    // e.g. "ecdsa-p384-sha384"
	NVSwitchPresent bool          `json:"nvswitch_present"`
}

// GPUReport is the parsed, validated GPU evidence report — every field
// downstream verification logic needs, with no JSON-specific shape.
type GPUReport struct {
	EvidenceVersion string
	UUID            string
	Architecture    string
	DriverVersion   string
	VBIOSVersion    string
	Nonce           [32]byte
	Measurements    []Measurement // CLAIMED measurements (untrusted labels); the
	// trusted values come from the signed SPDM record, not from here.
	CertChain []string // leaf-first PEM blocks; chained to the pinned NVIDIA root

	// SPDMRequest / SPDMResponse are the binary SPDM GET_MEASUREMENTS (0xE0)
	// request and signed MEASUREMENTS (0x60) response. These ARE the GPU's
	// cryptographic evidence — the local verifier checks the response
	// signature with the leaf key and extracts measurements from the signed
	// record. Empty for an NRAS-only envelope.
	SPDMRequest  []byte
	SPDMResponse []byte
	SPDMAsymAlgo string // negotiated signature algorithm name (may be empty -> P-384)

	NVSwitchPresent bool
}

// ParseGPUReport reads the JSON envelope and returns a validated
// GPUReport. All structural problems are caught here so downstream
// consumers (NRAS client, RIM matcher, composite) deal only with
// well-formed input.
func ParseGPUReport(data []byte) (*GPUReport, error) {
	if len(data) == 0 {
		return nil, ErrReportEmpty
	}
	var r rawReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReportBadJSON, err)
	}
	if !SupportedEvidenceVersions[r.EvidenceVersion] {
		return nil, fmt.Errorf("%w: %q", ErrReportBadVersion, r.EvidenceVersion)
	}
	if r.Architecture == "" {
		return nil, ErrReportMissingArch
	}
	if !SupportedArchitectures[r.Architecture] {
		return nil, fmt.Errorf("%w: %q", ErrReportUnknownArch, r.Architecture)
	}
	if r.NonceHex == "" {
		return nil, ErrReportMissingNonce
	}
	nonceBytes, err := hex.DecodeString(strings.TrimPrefix(r.NonceHex, "0x"))
	if err != nil || len(nonceBytes) != 32 {
		return nil, ErrReportBadNonce
	}
	if len(r.Measurements) == 0 {
		return nil, ErrReportNoMeasurements
	}
	for i := range r.Measurements {
		raw, err := hex.DecodeString(strings.TrimPrefix(r.Measurements[i].ValueHex, "0x"))
		if err != nil {
			return nil, fmt.Errorf("nvidia/report: bad measurement[%d] hex: %v", i, err)
		}
		r.Measurements[i].Value = raw
	}

	// The signed SPDM response is carried under "spdm_response"; the legacy
	// "attestation_quote" key is accepted as an alias. Decode both SPDM
	// fields if present (they are optional at parse time — the local
	// verifier enforces their presence, the NRAS path ignores them).
	respB64 := r.SPDMResponse
	if respB64 == "" {
		respB64 = r.Quote
	}
	spdmResp, err := decodeOptionalB64(respB64)
	if err != nil {
		return nil, fmt.Errorf("%w: spdm_response: %v", ErrReportBadSPDM, err)
	}
	spdmReq, err := decodeOptionalB64(r.SPDMRequest)
	if err != nil {
		return nil, fmt.Errorf("%w: spdm_request: %v", ErrReportBadSPDM, err)
	}

	rep := &GPUReport{
		EvidenceVersion: r.EvidenceVersion,
		UUID:            r.GPUUUID,
		Architecture:    r.Architecture,
		DriverVersion:   r.DriverVersion,
		VBIOSVersion:    r.VBIOSVersion,
		Measurements:    r.Measurements,
		CertChain:       r.CertChain,
		SPDMRequest:     spdmReq,
		SPDMResponse:    spdmResp,
		SPDMAsymAlgo:    r.SPDMAsymAlgo,
		NVSwitchPresent: r.NVSwitchPresent,
	}
	copy(rep.Nonce[:], nonceBytes)
	return rep, nil
}

// decodeOptionalB64 decodes a base64 field that may be empty. It accepts
// both standard and raw (unpadded) base64, returning nil for empty input.
func decodeOptionalB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// MeasurementMap returns measurements indexed by Name for fast lookup
// during RIM matching. Names are case-sensitive per spec.
func (r *GPUReport) MeasurementMap() map[string]Measurement {
	out := make(map[string]Measurement, len(r.Measurements))
	for _, m := range r.Measurements {
		out[m.Name] = m
	}
	return out
}
