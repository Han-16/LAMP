package matrix

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Format v1: 8-byte magic (including version), uint64 K (big endian),
// then A, B, C in row-major order, each entry a canonical 32-byte field element.
const matrixMagic = "LEDMAT01"

func FilePath(dir string, k int) string {
	return filepath.Join(dir, fmt.Sprintf("matrices_k%d.bin", k))
}

// Save creates a new file; it never overwrites an existing dataset.
// It validates shapes, not AB=C. The generator computes C before calling it.
func Save(path string, a, b, c Matrix) (err error) {
	k := len(a)
	if k == 0 {
		return fmt.Errorf("matrix dimension must be positive")
	}
	for _, m := range []Matrix{a, b, c} {
		if err := Check(m, k); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".matrices-*.partial")
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	w := bufio.NewWriterSize(f, 1<<20)
	if _, err = w.WriteString(matrixMagic); err != nil {
		return err
	}
	if err = binary.Write(w, binary.BigEndian, uint64(k)); err != nil {
		return err
	}
	for _, m := range []Matrix{a, b, c} {
		for _, row := range m {
			for _, value := range row {
				bytes := value.Bytes()
				if _, err = w.Write(bytes[:]); err != nil {
					return err
				}
			}
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// Publish a complete file without replacing another generator's output.
	return os.Link(f.Name(), path)
}

// Load checks the format, requested dimension, exact size and canonical
// field representation. It deliberately does not recompute AB: the LAMP/Freivalds proof
// checks the multiplication relation. Do not change files while loading them.
func Load(path string, k int) (a, b, c Matrix, err error) {
	if k < 1 || k > 1<<28 {
		return nil, nil, nil, fmt.Errorf("invalid matrix dimension")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, nil, err
	}
	expected := int64(16) + 3*int64(k)*int64(k)*fr.Bytes
	if info.Size() != expected {
		return nil, nil, nil, fmt.Errorf("matrix file size %d, want %d for k=%d", info.Size(), expected, k)
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var header [16]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, nil, err
	}
	if string(header[:8]) != matrixMagic || binary.BigEndian.Uint64(header[8:]) != uint64(k) {
		return nil, nil, nil, fmt.Errorf("matrix file format or dimension mismatch")
	}
	a, b, c = New(k), New(k), New(k)
	var bytes [fr.Bytes]byte
	for _, m := range []Matrix{a, b, c} {
		for i := range m {
			for j := range m[i] {
				if _, err := io.ReadFull(r, bytes[:]); err != nil {
					return nil, nil, nil, err
				}
				if err := m[i][j].SetBytesCanonical(bytes[:]); err != nil {
					return nil, nil, nil, fmt.Errorf("noncanonical matrix entry: %w", err)
				}
			}
		}
	}
	return a, b, c, nil
}
