package matrix

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"testing"
)

func TestMatrixMultiplication(t *testing.T) {
	a := Matrix{testVector(1, 2), testVector(3, 4)}
	b := Matrix{testVector(5, 6), testVector(7, 8)}
	c := Multiply(a, b)
	assertVector(t, c[0], testVector(19, 22))
	assertVector(t, c[1], testVector(43, 50))

	v := testVector(2, 3)
	assertVector(t, LeftMultiply(v, a), testVector(11, 16))
	assertVector(t, LeftMultiply(v, c), LeftMultiply(LeftMultiply(v, a), b))
	assertVector(t, a[0], testVector(1, 2))
	assertVector(t, b[1], testVector(7, 8))
}

func TestMatrixWorkers(t *testing.T) {
	for _, k := range []int{1, 7, 16} {
		a, err := Random(k)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Random(k)
		if err != nil {
			t.Fatal(err)
		}
		want := New(k)
		for i := 0; i < k; i++ {
			for j := 0; j < k; j++ {
				for l := 0; l < k; l++ {
					var term fr.Element
					term.Mul(&a[i][l], &b[l][j])
					want[i][j].Add(&want[i][j], &term)
				}
			}
		}
		for _, workers := range []int{1, 2, 3, k + 1} {
			got := MultiplyWithWorkers(a, b, workers)
			for i := range got {
				assertVector(t, got[i], want[i])
			}
		}
	}
}

func testVector(values ...uint64) []fr.Element {
	out := make([]fr.Element, len(values))
	for i, value := range values {
		out[i].SetUint64(value)
	}
	return out
}

func assertVector(t *testing.T, got, want []fr.Element) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("vector lengths differ: got %d, want %d", len(got), len(want))
	}
	for i := range got {
		if !got[i].Equal(&want[i]) {
			t.Fatalf("vector entry %d differs: got %s, want %s", i, got[i].String(), want[i].String())
		}
	}
}

// Independent cubic reference checks worker partitioning and transposition,
// including an odd size and worker counts that do not divide K.
