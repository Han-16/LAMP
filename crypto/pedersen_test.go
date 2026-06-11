package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestBatchPedersenCommitABCBlindedMatchesConcatenatedCommitment(t *testing.T) {
	const (
		columnCount = 5
		blockLen    = 4
	)

	a := randomPedersenABCColumns(columnCount, blockLen)
	b := randomPedersenABCColumns(columnCount, blockLen)
	c := randomPedersenABCColumns(columnCount, blockLen)
	ck := SetupCommitKey(3 * blockLen)

	commits, blindings := BatchPedersenCommitABCBlinded(a, b, c, ck)
	if len(commits) != columnCount {
		t.Fatalf("unexpected commitment count: got %d want %d", len(commits), columnCount)
	}
	if len(blindings) != columnCount {
		t.Fatalf("unexpected blinding count: got %d want %d", len(blindings), columnCount)
	}

	for i := 0; i < columnCount; i++ {
		combined := make([]fr.Element, 0, 3*blockLen)
		combined = append(combined, a[i]...)
		combined = append(combined, b[i]...)
		combined = append(combined, c[i]...)

		expected := PedersenCommitBlinded(combined, blindings[i], ck)
		if !commits[i].Equal(&expected) {
			t.Fatalf("commitment mismatch at column %d", i)
		}
	}
}

func randomPedersenABCColumns(columnCount, blockLen int) [][]fr.Element {
	out := make([][]fr.Element, columnCount)
	for i := range out {
		out[i] = make([]fr.Element, blockLen)
		for j := range out[i] {
			out[i][j].SetRandom()
		}
	}
	return out
}
