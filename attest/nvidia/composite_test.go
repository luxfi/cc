package nvidia

import (
	"errors"
	"testing"
	"time"
)

// helper — fully verified composite.
func okBundle() VerifiedBundle {
	gpuNonce := [32]byte{1, 2, 3, 4}
	workerID := "worker-7"
	gpuUUID := "GPU-DEAD-BEEF"
	cpuRD := BindCPUReportData(workerID, gpuUUID, gpuNonce)
	return VerifiedBundle{
		WorkerID: workerID,
		CPU: CPUQuote{
			Kind:            TEESEVSNP,
			Verified:        true,
			MeasurementHash: [32]byte{0x11},
			ReportData:      cpuRD,
			VerifiedAt:      time.Now().Add(-1 * time.Minute),
		},
		GPU: GPUEvidence{
			UUID:            gpuUUID,
			DriverVersion:   "535.104.05",
			VBIOSVersion:    "96.00.74.00.01",
			Architecture:    "Hopper",
			Verified:        true,
			RIMMatched:      true,
			Nonce:           gpuNonce,
			VerifiedAt:      time.Now().Add(-2 * time.Minute),
			MeasurementRoot: [32]byte{0x22},
		},
		KernelManifestRoot: [32]byte{0x33, 0x44},
		BuiltAt:            time.Now(),
	}
}

func TestVerifiedBundle_HappyPath(t *testing.T) {
	c := okBundle()
	res, err := c.Verify(time.Now(), time.Hour)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.CPUAttested || !res.GPUAttested {
		t.Fatalf("expected attested, got %+v", res)
	}
	if res.KernelManifestRoot != c.KernelManifestRoot {
		t.Fatalf("kernel root drift")
	}
}

func TestVerifiedBundle_NilReceiver(t *testing.T) {
	var c *VerifiedBundle
	if _, err := c.Verify(time.Now(), 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifiedBundle_RejectsTEENone(t *testing.T) {
	c := okBundle()
	c.CPU.Kind = TEENone
	if _, err := c.Verify(time.Now(), 0); !errors.Is(err, ErrBundleNoCPUQuote) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsUnverifiedCPU(t *testing.T) {
	c := okBundle()
	c.CPU.Verified = false
	if _, err := c.Verify(time.Now(), 0); !errors.Is(err, ErrBundleBadCPU) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsUnverifiedGPU(t *testing.T) {
	c := okBundle()
	c.GPU.Verified = false
	if _, err := c.Verify(time.Now(), 0); !errors.Is(err, ErrBundleBadGPU) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsRIMMismatch(t *testing.T) {
	c := okBundle()
	c.GPU.RIMMatched = false
	if _, err := c.Verify(time.Now(), 0); !errors.Is(err, ErrBundleRIMMismatch) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsBindingMismatch(t *testing.T) {
	c := okBundle()
	c.CPU.ReportData = [32]byte{0xff} // wrong binding
	if _, err := c.Verify(time.Now(), 0); !errors.Is(err, ErrBundleBindingMissing) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsStaleCPU(t *testing.T) {
	c := okBundle()
	c.CPU.VerifiedAt = time.Now().Add(-25 * time.Hour)
	if _, err := c.Verify(time.Now(), time.Hour); !errors.Is(err, ErrBundleStale) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsStaleGPU(t *testing.T) {
	c := okBundle()
	c.GPU.VerifiedAt = time.Now().Add(-25 * time.Hour)
	if _, err := c.Verify(time.Now(), time.Hour); !errors.Is(err, ErrBundleStale) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifiedBundle_RejectsMissingWorker(t *testing.T) {
	c := okBundle()
	c.WorkerID = ""
	if _, err := c.Verify(time.Now(), 0); !errors.Is(err, ErrBundleMissingWorker) {
		t.Fatalf("got %v", err)
	}
}

func TestBindCPUReportData_StableAcrossInputs(t *testing.T) {
	a := BindCPUReportData("w", "u", [32]byte{1})
	b := BindCPUReportData("w", "u", [32]byte{1})
	c := BindCPUReportData("w", "u", [32]byte{2})
	if a != b {
		t.Fatalf("not deterministic")
	}
	if a == c {
		t.Fatalf("nonce collision")
	}
}

func TestTEEKind_String(t *testing.T) {
	cases := map[TEEKind]string{
		TEENone:     "none",
		TEESEVSNP:   "sev_snp",
		TEETDX:      "tdx",
		TEEKind(99): "invalid",
	}
	for k, want := range cases {
		if k.String() != want {
			t.Fatalf("k=%d got %s want %s", k, k.String(), want)
		}
	}
}
