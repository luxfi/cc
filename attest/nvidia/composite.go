// Package nvidia provides NVIDIA Confidential-Compute attestation
// primitives: the GPU evidence-report parser, NVIDIA Remote
// Attestation Service (NRAS) HTTP client, Reference Integrity
// Manifest (RIM) validator, and the verified-bundle root that
// AND-combines a CPU TEE quote (SEV-SNP / TDX) with the GPU result.
//
// Wire format and field names mirror the public nvTrust / NVIDIA
// Confidential Compute documentation (Apache-2 licensed). No NVIDIA
// proprietary code is vendored — every parser is a clean-room
// implementation of the publicly documented schema.
//
// Relationship to pkg/attestation.CompositeAttestation (sibling v0.60):
// the canonical wire envelope lives in pkg/attestation. This package
// is the NVIDIA-specific verifier that turns one of those envelopes'
// EvidenceGPUNRASReport blobs into a verified GPUEvidence record.
// VerifiedBundle is the post-verification CPU+GPU bind that is folded
// into the scheduler's Worker fields — it is NOT the canonical wire
// envelope.
//
// The root entry point is VerifiedBundle.Verify(): it returns
// nil iff every component verifies AND every reference value matches.
// Callers feed the resulting VerifiedResult into the scheduler's
// Worker fields (TrustMode, GPUAttested, CPUAttested,
// KernelManifestRoot).
package nvidia

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// TEEKind identifies the CPU confidential-compute platform.
type TEEKind uint8

const (
	// TEENone — no CPU TEE; only acceptable for development.
	TEENone TEEKind = iota
	// TEESEVSNP — AMD SEV-SNP.
	TEESEVSNP
	// TEETDX — Intel TDX.
	TEETDX
)

// String returns the canonical name for the TEE kind.
func (t TEEKind) String() string {
	switch t {
	case TEENone:
		return "none"
	case TEESEVSNP:
		return "sev_snp"
	case TEETDX:
		return "tdx"
	}
	return "invalid"
}

// CPUQuote is the verified output of a CPU TEE attestation. The bytes
// of the raw quote (SEV-SNP attestation report or TDX TD report) are
// not retained here; this struct holds only the post-verification
// projection that downstream gates need.
type CPUQuote struct {
	Kind            TEEKind   // SEV-SNP or TDX
	Verified        bool      // verifier confirmed the signature chain
	MeasurementHash [32]byte  // launch measurement (MRTD or LAUNCH_MEASUREMENT)
	ReportData      [32]byte  // freshness binding (e.g. nonce hash)
	VerifiedAt      time.Time // when the verifier signed off
	VendorCertChain [][]byte  // AMD or Intel vendor cert chain (DER)
}

// GPUEvidence is the verified output of an NVIDIA GPU attestation.
// Populated by GPUReport.Parse + NRASClient.Verify + RIM.Match.
type GPUEvidence struct {
	UUID             string    // GPU UUID, e.g. "GPU-1234..."
	DriverVersion    string    // e.g. "535.104.05"
	VBIOSVersion     string    // e.g. "96.00.74.00.01"
	Architecture     string    // "Hopper" | "Blackwell"
	Verified         bool      // NRAS returned a valid token
	NRASTokenHash    [32]byte  // sha256 of the NRAS token bytes
	MeasurementRoot  [32]byte  // root over the measurement list
	RIMMatched       bool      // every measurement matched the RIM
	Nonce            [32]byte  // freshness nonce echoed in report
	VerifiedAt       time.Time // when NRAS signed the token
	NVSwitchVerified bool      // multi-GPU NVSwitch attested (optional)
}

// VerifiedBundle binds a CPU TEE quote to a GPU evidence record
// for a single worker, plus the kernel manifest root that the
// scheduler matches against the workload's approved set.
//
// The composite is what the scheduler ultimately consumes: a single
// struct that carries every fact the workload-policy gate needs.
type VerifiedBundle struct {
	WorkerID           string
	CPU                CPUQuote
	GPU                GPUEvidence
	KernelManifestRoot [32]byte // root of the approved kernel manifest
	BuiltAt            time.Time
}

// VerifiedResult is the projection a Worker is built from. Callers
// pass these fields into scheduler.Worker.
type VerifiedResult struct {
	WorkerID           string
	CPUAttested        bool
	GPUAttested        bool
	NVSwitchAttested   bool
	KernelManifestRoot [32]byte
}

// Errors returned by Verify, in the order they are checked.
var (
	ErrBundleMissingWorker  = errors.New("nvidia: composite missing worker ID")
	ErrBundleNoCPUQuote     = errors.New("nvidia: composite missing CPU quote")
	ErrBundleBadCPU         = errors.New("nvidia: CPU quote not verified")
	ErrBundleBadGPU         = errors.New("nvidia: GPU evidence not verified")
	ErrBundleRIMMismatch    = errors.New("nvidia: RIM mismatch on GPU measurements")
	ErrBundleBindingMissing = errors.New("nvidia: CPU report_data does not bind GPU nonce")
	ErrBundleStale          = errors.New("nvidia: composite older than freshness window")
)

// Verify checks every component of the composite. The freshness
// argument bounds how old the CPU/GPU verifications may be; pass 0
// to disable the freshness check (test-only).
//
// A successful Verify returns the projection ready for scheduler
// consumption.
func (c *VerifiedBundle) Verify(now time.Time, freshness time.Duration) (VerifiedResult, error) {
	var zero VerifiedResult
	if c == nil {
		return zero, errors.New("nvidia: nil composite")
	}
	if c.WorkerID == "" {
		return zero, ErrBundleMissingWorker
	}
	if c.CPU.Kind == TEENone {
		return zero, ErrBundleNoCPUQuote
	}
	if !c.CPU.Verified {
		return zero, ErrBundleBadCPU
	}
	if !c.GPU.Verified {
		return zero, ErrBundleBadGPU
	}
	if !c.GPU.RIMMatched {
		return zero, ErrBundleRIMMismatch
	}

	// Bind GPU nonce to CPU report_data. Standard pattern: report_data
	// is sha256(workerID || gpuUUID || gpuNonce). If a different shape
	// is required, callers can override binding by setting the CPU's
	// ReportData themselves and skipping the helper.
	expected := bindCPUReportData(c.WorkerID, c.GPU.UUID, c.GPU.Nonce)
	if c.CPU.ReportData != expected {
		return zero, ErrBundleBindingMissing
	}

	if freshness > 0 {
		if c.CPU.VerifiedAt.IsZero() || now.Sub(c.CPU.VerifiedAt) > freshness {
			return zero, fmt.Errorf("%w: cpu age=%v", ErrBundleStale, now.Sub(c.CPU.VerifiedAt))
		}
		if c.GPU.VerifiedAt.IsZero() || now.Sub(c.GPU.VerifiedAt) > freshness {
			return zero, fmt.Errorf("%w: gpu age=%v", ErrBundleStale, now.Sub(c.GPU.VerifiedAt))
		}
	}

	return VerifiedResult{
		WorkerID:           c.WorkerID,
		CPUAttested:        true,
		GPUAttested:        true,
		NVSwitchAttested:   c.GPU.NVSwitchVerified,
		KernelManifestRoot: c.KernelManifestRoot,
	}, nil
}

// bindCPUReportData computes the canonical binding hash that ties the
// CPU TEE report_data field to the GPU evidence nonce. Callers MUST
// use this when constructing the CPU quote so the composite verifies.
//
// Layout: sha256( "luxfi/mpc/composite\x00" || workerID || "\x00" ||
//
//	gpuUUID || "\x00" || gpuNonce ).
//
// The leading domain string + null separators prevent cross-domain
// reuse of the same hash (a SEV-SNP report bound this way cannot be
// repurposed for any other binding).
func bindCPUReportData(workerID, gpuUUID string, gpuNonce [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("luxfi/mpc/composite\x00"))
	_, _ = h.Write([]byte(workerID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(gpuUUID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(gpuNonce[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BindCPUReportData is the exported helper for callers building a CPU
// quote. The returned 32-byte digest must be placed in REPORT_DATA
// (SEV-SNP) or REPORTDATA (TDX) before the quote is fetched.
func BindCPUReportData(workerID, gpuUUID string, gpuNonce [32]byte) [32]byte {
	return bindCPUReportData(workerID, gpuUUID, gpuNonce)
}
