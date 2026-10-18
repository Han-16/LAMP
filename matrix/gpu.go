package matrix

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GPUStats contains helper-reported device timings and complete Go call time.
// Compute includes packing, IPC, subprocess startup, GPU setup, transfers,
// kernel execution, synchronization and unpacking. Setup/Kernel are subsets.
type GPUStats struct {
	Device   string        `json:"device_name"`
	SetupMS  float64       `json:"setup_ms"`
	KernelMS float64       `json:"kernel_ms"`
	Compute  time.Duration `json:"-"`
}

func MultiplyGPU(a, b Matrix, backend, helper string) (Matrix, GPUStats, error) {
	start := time.Now()
	var stats GPUStats
	k := Dimension(a, "GPU left matrix")
	if Dimension(b, "GPU right matrix") != k {
		return nil, stats, fmt.Errorf("GPU matrix dimensions differ")
	}
	if backend != "metal" && backend != "cuda" {
		return nil, stats, fmt.Errorf("unknown GPU backend %q", backend)
	}
	if backend == "metal" && runtime.GOOS != "darwin" {
		return nil, stats, fmt.Errorf("Metal requires native macOS, not an Ubuntu container")
	}
	if helper == "" {
		helper = filepath.Join("bin", "lamp-"+backend)
	}
	helper, err := filepath.Abs(helper)
	if err != nil {
		return nil, stats, err
	}
	args := []string{}
	if backend == "metal" {
		args = append(args, filepath.Join(filepath.Dir(helper), "matmul-runtime.metal"))
	}
	var input, output, diagnostics bytes.Buffer
	// Reserve once: geometric growth duplicates large buffers during packing.
	input.Grow(4 + 128*k*k)
	_ = binary.Write(&input, binary.LittleEndian, uint32(k))
	// Transfer Montgomery values directly. Public dataset files remain canonical.
	var packed [64]byte
	for _, m := range []Matrix{a, b} {
		for _, row := range m {
			for _, v := range row {
				for limb := 0; limb < 16; limb++ {
					binary.LittleEndian.PutUint32(packed[limb*4:], uint32((v[limb/4]>>uint(16*(limb%4)))&65535))
				}
				input.Write(packed[:])
			}
		}
	}
	cmd := exec.Command(helper, args...)
	cmd.Stdin = &input
	cmd.Stdout = &output
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		return nil, stats, fmt.Errorf("%s GPU helper failed (no CPU fallback): %w; %s", backend, err, diagnostics.String())
	}
	if err := json.Unmarshal(diagnostics.Bytes(), &stats); err != nil {
		return nil, stats, fmt.Errorf("GPU metrics: %w", err)
	}
	if stats.Device == "" || math.IsNaN(stats.KernelMS) || stats.KernelMS < 0 || stats.SetupMS < 0 {
		return nil, stats, fmt.Errorf("invalid GPU metrics")
	}
	if output.Len() != k*k*64 {
		return nil, stats, fmt.Errorf("GPU output length %d, expected %d", output.Len(), k*k*64)
	}
	c := New(k)
	raw := output.Bytes()
	offset := 0
	// Check each returned Montgomery integer is reduced, before using field ops.
	modulus := fr.Modulus().FillBytes(make([]byte, 32))
	var bigEndian [32]byte
	for i := range c {
		for j := range c[i] {
			for limb := 0; limb < 16; limb++ {
				v := binary.LittleEndian.Uint32(raw[offset:])
				offset += 4
				if v > 65535 {
					return nil, stats, fmt.Errorf("invalid GPU limb")
				}
				c[i][j][limb/4] |= uint64(v) << uint(16*(limb%4))
			}
			for l := 0; l < 4; l++ {
				binary.BigEndian.PutUint64(bigEndian[(3-l)*8:], c[i][j][l])
			}
			if bytes.Compare(bigEndian[:], modulus) >= 0 {
				return nil, stats, fmt.Errorf("unreduced GPU result")
			}
		}
	}
	stats.Compute = time.Since(start)
	return c, stats, nil
}

// CheckProductRandom uses fresh field coefficients after C is computed.
// A false product passes one round with probability at most 1/|Fr| under
// independent randomness. This catches computation errors; it is not a SNARK.
func CheckProductRandom(a, b, c Matrix) error {
	k := Dimension(a, "A")
	if Dimension(b, "B") != k || Dimension(c, "C") != k {
		return fmt.Errorf("product check dimensions differ")
	}
	r := make([]fr.Element, k)
	for i := range r {
		if _, err := r[i].SetRandom(); err != nil {
			return err
		}
	}
	lhs := LeftMultiply(LeftMultiply(r, a), b)
	rhs := LeftMultiply(r, c)
	for i := range lhs {
		if !lhs[i].Equal(&rhs[i]) {
			return fmt.Errorf("GPU product check failed")
		}
	}
	return nil
}

// GPUSelfTest checks actual device execution, including edge values and partial
// tiles. Run it before generating research data on a new machine/build.
func GPUSelfTest(backend, helper string) error {
	for _, k := range []int{1, 7, 8, 9, 17} {
		a, err := Random(k)
		if err != nil {
			return err
		}
		b, err := Random(k)
		if err != nil {
			return err
		}
		a[0][0].SetZero()
		b[0][0].SetOne()
		if k > 1 {
			a[0][1].SetOne()
			a[0][1].Neg(&a[0][1])
			b[1][0] = a[0][1]
		}
		got, _, err := MultiplyGPU(a, b, backend, helper)
		if err != nil {
			return err
		}
		want := MultiplyWithWorkers(a, b, 1)
		for i := range got {
			for j := range got[i] {
				if !got[i][j].Equal(&want[i][j]) {
					return fmt.Errorf("GPU self-test mismatch k=%d row=%d col=%d", k, i, j)
				}
			}
		}
	}
	// Exercise disk blocks, padding, accumulation and the final file check too.
	dir, err := os.MkdirTemp("", "lamp-gpu-self-test-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := FilePath(dir, 9)
	if _, err := GenerateGPUFile(path, 9, 4, backend, helper, nil); err != nil {
		return err
	}
	a, b, got, err := Load(path, 9)
	if err != nil {
		return err
	}
	want := MultiplyWithWorkers(a, b, 1)
	for i := range got {
		for j := range got[i] {
			if !got[i][j].Equal(&want[i][j]) {
				return fmt.Errorf("GPU file self-test mismatch row=%d col=%d", i, j)
			}
		}
	}
	return nil
}
