package matrix

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Matrix stores a square matrix in row-major order over the BN254 scalar field.
type Matrix = [][]fr.Element

// New returns a zero k-by-k matrix. The rows have separate storage.
func New(k int) Matrix {
	if k <= 0 {
		panic("lamp: matrix dimension must be positive")
	}
	m := make(Matrix, k)
	for i := range m {
		m[i] = make([]fr.Element, k)
	}
	return m
}

// Random samples each entry independently using crypto/rand through fr.
func Random(k int) (Matrix, error) {
	if k <= 0 {
		return nil, fmt.Errorf("lamp: matrix dimension must be positive, got %d", k)
	}
	m := New(k)
	for i := range m {
		for j := range m[i] {
			if _, err := m[i][j].SetRandom(); err != nil {
				return nil, fmt.Errorf("lamp: sample matrix entry (%d,%d): %w", i, j, err)
			}
		}
	}
	return m, nil
}

// Multiply returns a*b using up to GOMAXPROCS workers.
func Multiply(a, b Matrix) Matrix {
	return MultiplyWithWorkers(a, b, runtime.GOMAXPROCS(0))
}

// MultiplyWithWorkers transposes B for contiguous inner-product reads and
// assigns disjoint output rows to workers. Inputs are never modified.
// Work remains O(K^3); the transpose requires K^2 additional field elements.
func MultiplyWithWorkers(a, b Matrix, workers int) Matrix {
	k := Dimension(a, "left matrix")
	if Dimension(b, "right matrix") != k {
		panic("lamp: matrix multiplication dimensions differ")
	}
	if workers < 1 {
		panic("lamp: matrix workers must be positive")
	}
	if workers > k {
		workers = k
	}
	bt := New(k)
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			bt[j][i] = b[i][j]
		}
	}
	c := New(k)
	rows := func(first, last int) {
		for i := first; i < last; i++ {
			for j := 0; j < k; j++ {
				c[i][j] = InnerProduct(a[i], bt[j])
			}
		}
	}
	if workers == 1 {
		rows(0, k)
		return c
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		first, last := w*k/workers, (w+1)*k/workers
		wg.Add(1)
		go func() { defer wg.Done(); rows(first, last) }()
	}
	wg.Wait()
	return c
}

// InnerProduct returns sum_i a[i]*b[i]. Equal-length empty vectors give zero.
func InnerProduct(a, b []fr.Element) fr.Element {
	if len(a) != len(b) {
		panic("lamp: inner-product vector lengths differ")
	}
	var sum, product fr.Element
	for i := range a {
		product.Mul(&a[i], &b[i])
		sum.Add(&sum, &product)
	}
	return sum
}

// LeftMultiply returns the row vector v*m without modifying its inputs.
func LeftMultiply(v []fr.Element, m Matrix) []fr.Element {
	k := Dimension(m, "matrix")
	if len(v) != k {
		panic("lamp: left-multiplication vector length differs from matrix dimension")
	}
	return VecMatMul(v, m, k)
}

// Dimension checks that m is nonempty and square, and returns its size.
func Dimension(m Matrix, name string) int {
	k := len(m)
	if k == 0 {
		panic(fmt.Sprintf("lamp: %s must have positive dimension", name))
	}
	for i, row := range m {
		if len(row) != k {
			panic(fmt.Sprintf("lamp: %s row %d has length %d, want %d", name, i, len(row), k))
		}
	}
	return k
}

// Check reports whether m is a k-by-k matrix without panicking.
func Check(m Matrix, k int) error {
	if len(m) != k {
		return fmt.Errorf("expected %d matrix rows", k)
	}
	for _, row := range m {
		if len(row) != k {
			return fmt.Errorf("expected %d matrix columns", k)
		}
	}
	return nil
}
