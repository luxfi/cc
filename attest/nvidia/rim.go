// Reference Integrity Manifest (RIM) validation. The RIM is the
// signed list of measurement values NVIDIA publishes for each
// driver/VBIOS combination. Match every measurement in a parsed GPU
// report against its RIM entry; reject any non-match.
//
// The signature on the RIM blob is verified against the supplied
// trust roots. We do not bake in NVIDIA's signing keys — operators
// supply them via deployment config. This keeps the package
// license-clean (Apache-2 nvTrust schema only, no NVIDIA cert PEMs
// vendored) and lets enterprises pin their own RIM trust path.
package nvidia

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Errors returned by RIM validation.
var (
	ErrRIMEmpty           = errors.New("nvidia/rim: empty manifest")
	ErrRIMBadJSON         = errors.New("nvidia/rim: bad JSON manifest")
	ErrRIMBadSignature    = errors.New("nvidia/rim: signature verification failed")
	ErrRIMNoTrustRoots    = errors.New("nvidia/rim: no trust roots configured")
	ErrRIMMissingEntry    = errors.New("nvidia/rim: measurement not in manifest")
	ErrRIMValueMismatch   = errors.New("nvidia/rim: measurement value mismatch")
	ErrRIMArchMismatch    = errors.New("nvidia/rim: architecture mismatch")
	ErrRIMVersionMismatch = errors.New("nvidia/rim: driver/vbios version mismatch")
)

// RIMEntry is one row in the manifest: an expected measurement value.
// Name is a human/audit label. Index, when present, is the SPDM
// measurement index this golden value pins — the binding the signed-record
// path (MatchSPDM) uses, since SPDM measurement blocks are keyed by index,
// not name. Index is a pointer so that index 0 is distinguishable from
// "no index", and omitempty keeps name-only manifests byte-identical on
// the wire (their detached signatures are unaffected).
type RIMEntry struct {
	Name     string `json:"name"`
	ValueHex string `json:"value"`
	Index    *uint8 `json:"index,omitempty"`
}

// rawRIM is the on-the-wire JSON. The signature block is detachable:
// signers compute it over the canonical body bytes (sorted keys, no
// whitespace) and append the signature alongside.
type rawRIM struct {
	Architecture  string     `json:"architecture"`
	DriverVersion string     `json:"driver_version"`
	VBIOSVersion  string     `json:"vbios_version"`
	Entries       []RIMEntry `json:"entries"`
	SignerKeyID   string     `json:"signer_key_id,omitempty"`
	SignatureB64  string     `json:"signature,omitempty"`
}

// RIM is a parsed, signature-verified Reference Integrity Manifest.
type RIM struct {
	Architecture  string
	DriverVersion string
	VBIOSVersion  string
	Entries       []RIMEntry

	// SignerKeyID identifies which trust root verified the manifest.
	// Empty if the manifest was loaded with VerifySignature disabled
	// (development only).
	SignerKeyID string
}

// TrustRoot is a public key registered to validate RIM signatures.
// Algorithm is inferred from the key type at verify time — we accept
// Ed25519, ECDSA P-256/P-384, and RSA-PSS (SHA-256). Operators wire
// their NVIDIA RIM signing keys here at startup.
type TrustRoot struct {
	KeyID  string
	Public crypto.PublicKey
}

// ParseAndVerifyRIM parses the manifest bytes and verifies the
// detached signature against trustRoots. If trustRoots is empty,
// returns ErrRIMNoTrustRoots — there is no insecure mode.
//
// On success, returns a *RIM with SignerKeyID set to the trust root
// that produced a valid signature.
func ParseAndVerifyRIM(data []byte, trustRoots []TrustRoot) (*RIM, error) {
	if len(data) == 0 {
		return nil, ErrRIMEmpty
	}
	if len(trustRoots) == 0 {
		return nil, ErrRIMNoTrustRoots
	}
	var raw rawRIM
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRIMBadJSON, err)
	}
	if raw.SignatureB64 == "" {
		return nil, fmt.Errorf("%w: missing signature", ErrRIMBadSignature)
	}
	if raw.SignerKeyID == "" {
		return nil, fmt.Errorf("%w: missing signer_key_id", ErrRIMBadSignature)
	}

	// Re-encode the body (sans signature fields) deterministically so
	// the signature is over a stable canonical form.
	body := rawRIM{
		Architecture:  raw.Architecture,
		DriverVersion: raw.DriverVersion,
		VBIOSVersion:  raw.VBIOSVersion,
		Entries:       raw.Entries,
	}
	canon, err := canonicalJSON(body)
	if err != nil {
		return nil, fmt.Errorf("nvidia/rim: canonicalize: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(raw.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad base64: %v", ErrRIMBadSignature, err)
	}

	root, ok := findTrustRoot(trustRoots, raw.SignerKeyID)
	if !ok {
		return nil, fmt.Errorf("%w: signer %q not in trust roots", ErrRIMBadSignature, raw.SignerKeyID)
	}

	if err := verifySignature(root.Public, canon, sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRIMBadSignature, err)
	}

	return &RIM{
		Architecture:  raw.Architecture,
		DriverVersion: raw.DriverVersion,
		VBIOSVersion:  raw.VBIOSVersion,
		Entries:       raw.Entries,
		SignerKeyID:   raw.SignerKeyID,
	}, nil
}

// Match validates that every measurement in report has an entry in
// rim with the same value. Architecture + driver + VBIOS must match
// the manifest's preconditions.
//
// Returns nil iff every measurement matches AND the GPU's
// driver/VBIOS line up with the manifest. Any divergence returns the
// most-specific error so audit logs can categorize failures.
func (rim *RIM) Match(report *GPUReport) error {
	if rim == nil || report == nil {
		return errors.New("nvidia/rim: nil rim or report")
	}
	if rim.Architecture != report.Architecture {
		return fmt.Errorf("%w: rim=%s report=%s", ErrRIMArchMismatch, rim.Architecture, report.Architecture)
	}
	if rim.DriverVersion != report.DriverVersion || rim.VBIOSVersion != report.VBIOSVersion {
		return fmt.Errorf("%w: rim=%s/%s report=%s/%s", ErrRIMVersionMismatch,
			rim.DriverVersion, rim.VBIOSVersion, report.DriverVersion, report.VBIOSVersion)
	}
	want := make(map[string][]byte, len(rim.Entries))
	for _, e := range rim.Entries {
		v, err := hex.DecodeString(strings.TrimPrefix(e.ValueHex, "0x"))
		if err != nil {
			return fmt.Errorf("nvidia/rim: bad entry hex %q: %w", e.Name, err)
		}
		want[e.Name] = v
	}
	for _, m := range report.Measurements {
		exp, ok := want[m.Name]
		if !ok {
			return fmt.Errorf("%w: name=%s", ErrRIMMissingEntry, m.Name)
		}
		if !bytesEqual(exp, m.Value) {
			return fmt.Errorf("%w: name=%s", ErrRIMValueMismatch, m.Name)
		}
	}
	return nil
}

// ErrRIMEntryNoIndex is returned by MatchSPDM when a RIM entry lacks the
// index needed to bind it to a signed SPDM measurement block.
var ErrRIMEntryNoIndex = errors.New("nvidia/rim: entry has no index for SPDM matching")

// MatchSPDM validates that every golden value in the manifest is present
// — by SPDM measurement index — among the cryptographically signed blocks
// extracted from a verified MEASUREMENTS response. This is the trusted
// match: blocks come from VerifySPDMMeasurementSignature, so a passing
// match means "the GPU's signed measurements include exactly NVIDIA's
// golden values for this driver/VBIOS".
//
// arch/driver/vbios are the envelope's claimed preconditions and must
// equal the manifest's; the cryptographic gate, however, is value
// equality against the SIGNED blocks. Extra signed blocks not named by the
// manifest are allowed (NVIDIA reports more indices than any single RIM
// pins); every manifest entry MUST be covered (completeness), which closes
// the drop-a-bad-measurement attack.
func (rim *RIM) MatchSPDM(arch, driver, vbios string, blocks []SPDMMeasurement) error {
	if rim == nil {
		return errors.New("nvidia/rim: nil rim")
	}
	if rim.Architecture != arch {
		return fmt.Errorf("%w: rim=%s report=%s", ErrRIMArchMismatch, rim.Architecture, arch)
	}
	if rim.DriverVersion != driver || rim.VBIOSVersion != vbios {
		return fmt.Errorf("%w: rim=%s/%s report=%s/%s", ErrRIMVersionMismatch,
			rim.DriverVersion, rim.VBIOSVersion, driver, vbios)
	}
	signed := make(map[uint8][]byte, len(blocks))
	for _, b := range blocks {
		signed[b.Index] = b.Value
	}
	for _, e := range rim.Entries {
		if e.Index == nil {
			return fmt.Errorf("%w: name=%s", ErrRIMEntryNoIndex, e.Name)
		}
		want, err := hex.DecodeString(strings.TrimPrefix(e.ValueHex, "0x"))
		if err != nil {
			return fmt.Errorf("nvidia/rim: bad entry hex %q: %w", e.Name, err)
		}
		got, ok := signed[*e.Index]
		if !ok {
			return fmt.Errorf("%w: name=%s index=%d (no signed block)", ErrRIMMissingEntry, e.Name, *e.Index)
		}
		if !bytesEqual(want, got) {
			return fmt.Errorf("%w: name=%s index=%d", ErrRIMValueMismatch, e.Name, *e.Index)
		}
	}
	return nil
}

// MeasurementRoot returns sha256(name||value) folded into a single
// root over a deterministic ordering. Used as the canonical
// MeasurementRoot in GPUEvidence.
func (rim *RIM) MeasurementRoot() [32]byte {
	// Sort entries by Name so the root is deterministic regardless of
	// list order in the manifest.
	names := make([]string, 0, len(rim.Entries))
	values := make(map[string][]byte, len(rim.Entries))
	for _, e := range rim.Entries {
		names = append(names, e.Name)
		v, _ := hex.DecodeString(strings.TrimPrefix(e.ValueHex, "0x"))
		values[e.Name] = v
	}
	sortStrings(names)
	h := sha256.New()
	for _, n := range names {
		_, _ = h.Write([]byte(n))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(values[n])
		_, _ = h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// =============================================================================
// internal helpers
// =============================================================================

// canonicalJSON re-encodes v with sorted keys and no whitespace. The
// stdlib's encoding/json already sorts struct fields by source order
// and map keys alphabetically; for our struct shape that is sufficient.
// We reject any nested map[string]interface{} that would require deeper
// canonicalization than stdlib provides.
func canonicalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func findTrustRoot(roots []TrustRoot, keyID string) (TrustRoot, bool) {
	for _, r := range roots {
		if r.KeyID == keyID {
			return r, true
		}
	}
	return TrustRoot{}, false
}

func verifySignature(pub crypto.PublicKey, msg, sig []byte) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(k, msg, sig) {
			return errors.New("ed25519 verify failed")
		}
		return nil
	case *ecdsa.PublicKey:
		// ASN.1 DER signature over sha256(msg).
		digest := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return errors.New("ecdsa verify failed")
		}
		return nil
	case *rsa.PublicKey:
		digest := sha256.Sum256(msg)
		// PSS with SHA-256, salt length = hash length.
		err := rsa.VerifyPSS(k, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			return fmt.Errorf("rsa verify: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported trust root key type %T", pub)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func sortStrings(s []string) {
	// insertion sort — n is tiny (measurement count per RIM), avoids
	// pulling in sort just for this.
	for i := 1; i < len(s); i++ {
		v := s[i]
		j := i - 1
		for j >= 0 && s[j] > v {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = v
	}
}
