package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestGenerateIndicesWithReplacement(t *testing.T) {
	var seed fr.Element
	seed.SetUint64(7)

	indices, err := GenerateIndices(seed, 4, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(indices) != 9 {
		t.Fatalf("got %d indices, want 9", len(indices))
	}
	seen := make(map[int]bool)
	for _, idx := range indices {
		if idx < 0 || idx >= 4 {
			t.Fatalf("index %d is outside [0, 4)", idx)
		}
		seen[idx] = true
	}
	if len(seen) == len(indices) {
		t.Fatal("sampling more indices than the domain must contain duplicates")
	}
}
