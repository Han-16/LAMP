package matrix

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// GPUFileStats separates sampling, computation, checking and file writes.
// Sample includes writing A/B; Compute includes reading input blocks.
type GPUFileStats struct {
	GPU                           GPUStats
	Sample, Compute, Check, Write time.Duration
}

// GenerateGPUFile computes a dense dataset with O(block^2 + k) host memory.
// A/B/C stay on disk; each GPU call handles one padded square block product.
// Only a complete, checked file is published, without replacing an existing one.
func GenerateGPUFile(path string, k, block int, backend, helper string, progress io.Writer) (stats GPUFileStats, err error) {
	if k < 1 || k > 1<<27 || block < 1 || block > 4096 {
		return stats, fmt.Errorf("require 1 <= K <= 2^27 and 1 <= GPU block size <= 4096")
	}
	if backend != "metal" && backend != "cuda" {
		return stats, fmt.Errorf("unknown GPU backend %q", backend)
	}
	if block > k {
		block = k
	}
	if _, err := os.Lstat(path); err == nil {
		return stats, fmt.Errorf("dataset already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return stats, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return stats, err
	}
	size := int64(16) + 96*int64(k)*int64(k)
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return stats, err
	}
	available := uint64(fs.Bavail) * uint64(fs.Bsize)
	if uint64(size) > available {
		return stats, fmt.Errorf("dataset requires %.2f GiB; only %.2f GiB available", float64(size)/(1<<30), float64(available)/(1<<30))
	}
	f, err := os.CreateTemp(dir, ".matrices-*.partial")
	if err != nil {
		return stats, err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	if err := f.Truncate(size); err != nil {
		return stats, err
	}
	start := time.Now()
	if err := sampleGPUFile(f, k); err != nil {
		return stats, err
	}
	stats.Sample = time.Since(start)
	if progress != nil {
		fmt.Fprintf(progress, "Sample A,B to disk: %.2f s; GPU block size: %d\n", stats.Sample.Seconds(), block)
	}
	start = time.Now()
	stats.GPU, stats.Write, err = multiplyGPUFile(f, k, block, backend, helper, progress)
	stats.Compute = time.Since(start) - stats.Write
	if err != nil {
		return stats, err
	}
	start = time.Now()
	if err := checkGPUFileProduct(f, k); err != nil {
		return stats, err
	}
	stats.Check = time.Since(start)
	start = time.Now()
	if err := f.Close(); err != nil {
		return stats, err
	}
	// A hard link publishes atomically and fails if another writer won the name.
	if err := os.Link(f.Name(), path); err != nil {
		return stats, err
	}
	stats.Write += time.Since(start)
	return stats, nil
}

func sampleGPUFile(f *os.File, k int) error {
	w := bufio.NewWriterSize(f, 1<<20)
	if _, err := w.WriteString(matrixMagic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint64(k)); err != nil {
		return err
	}
	var v fr.Element
	for matrix := 0; matrix < 2; matrix++ {
		for i := int64(0); i < int64(k)*int64(k); i++ {
			if _, err := v.SetRandom(); err != nil {
				return err
			}
			encoded := v.Bytes()
			if _, err := w.Write(encoded[:]); err != nil {
				return err
			}
		}
	}
	return w.Flush()
}

func matrixFileOffset(k, matrix, row, col int) int64 {
	return 16 + 32*((int64(matrix)*int64(k)+int64(row))*int64(k)+int64(col))
}

func readGPUFileBlock(f *os.File, k, matrix, row, col, block int) (Matrix, error) {
	m := New(block)
	cols := min(block, k-col)
	raw := make([]byte, cols*fr.Bytes)
	for i := 0; i < min(block, k-row); i++ {
		if _, err := f.ReadAt(raw, matrixFileOffset(k, matrix, row+i, col)); err != nil {
			return nil, err
		}
		for j := 0; j < cols; j++ {
			if err := m[i][j].SetBytesCanonical(raw[j*fr.Bytes : (j+1)*fr.Bytes]); err != nil {
				return nil, fmt.Errorf("noncanonical matrix entry: %w", err)
			}
		}
	}
	return m, nil
}

func writeGPUFileBlock(f *os.File, k, row, col int, m Matrix) error {
	cols := min(len(m), k-col)
	raw := make([]byte, cols*fr.Bytes)
	for i := 0; i < min(len(m), k-row); i++ {
		for j := 0; j < cols; j++ {
			encoded := m[i][j].Bytes()
			copy(raw[j*fr.Bytes:], encoded[:])
		}
		if _, err := f.WriteAt(raw, matrixFileOffset(k, 2, row+i, col)); err != nil {
			return err
		}
	}
	return nil
}

func multiplyGPUFile(f *os.File, k, block int, backend, helper string, progress io.Writer) (stats GPUStats, writeTime time.Duration, err error) {
	tiles := (k + block - 1) / block
	completed := 0
	for row := 0; row < k; row += block {
		for col := 0; col < k; col += block {
			c := New(block)
			for inner := 0; inner < k; inner += block {
				a, err := readGPUFileBlock(f, k, 0, row, inner, block)
				if err != nil {
					return stats, writeTime, err
				}
				b, err := readGPUFileBlock(f, k, 1, inner, col, block)
				if err != nil {
					return stats, writeTime, err
				}
				product, call, err := MultiplyGPU(a, b, backend, helper)
				if err != nil {
					return stats, writeTime, fmt.Errorf("GPU block row=%d col=%d inner=%d: %w", row, col, inner, err)
				}
				stats.Device = call.Device
				stats.SetupMS += call.SetupMS
				stats.KernelMS += call.KernelMS
				stats.Compute += call.Compute
				for i := range c {
					for j := range c[i] {
						c[i][j].Add(&c[i][j], &product[i][j])
					}
				}
			}
			start := time.Now()
			if err := writeGPUFileBlock(f, k, row, col, c); err != nil {
				return stats, writeTime, err
			}
			writeTime += time.Since(start)
			completed++
			if progress != nil {
				fmt.Fprintf(progress, "GPU output block %d/%d complete\n", completed, tiles*tiles)
			}
		}
	}
	return stats, writeTime, nil
}

func leftMultiplyGPUFile(f *os.File, k, matrix int, v []fr.Element) ([]fr.Element, error) {
	out := make([]fr.Element, k)
	raw := make([]byte, k*fr.Bytes)
	for row := 0; row < k; row++ {
		if _, err := f.ReadAt(raw, matrixFileOffset(k, matrix, row, 0)); err != nil {
			return nil, err
		}
		for col := 0; col < k; col++ {
			var entry, product fr.Element
			if err := entry.SetBytesCanonical(raw[col*fr.Bytes : (col+1)*fr.Bytes]); err != nil {
				return nil, fmt.Errorf("noncanonical matrix entry: %w", err)
			}
			product.Mul(&v[row], &entry)
			out[col].Add(&out[col], &product)
		}
	}
	return out, nil
}

func checkGPUFileProduct(f *os.File, k int) error {
	r := make([]fr.Element, k)
	for i := range r {
		if _, err := r[i].SetRandom(); err != nil {
			return err
		}
	}
	lhs, err := leftMultiplyGPUFile(f, k, 0, r)
	if err != nil {
		return err
	}
	lhs, err = leftMultiplyGPUFile(f, k, 1, lhs)
	if err != nil {
		return err
	}
	rhs, err := leftMultiplyGPUFile(f, k, 2, r)
	if err != nil {
		return err
	}
	for i := range lhs {
		if !lhs[i].Equal(&rhs[i]) {
			return fmt.Errorf("GPU product check failed")
		}
	}
	return nil
}
