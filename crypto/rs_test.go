package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestEncodeRowsToColumnsMatchesTransposedEncodeRows(t *testing.T) {
	const (
		k = 4
		n = 8
	)

	encoder := NewEncoder(k, n)
	rows := make([][]fr.Element, k)
	for i := range rows {
		rows[i] = make([]fr.Element, k)
		for j := range rows[i] {
			rows[i][j].SetRandom()
		}
	}

	_, encodedRows, err := encoder.EncodeRows(rows)
	if err != nil {
		t.Fatalf("EncodeRows failed: %v", err)
	}
	encodedCols, err := encoder.EncodeRowsToColumns(rows)
	if err != nil {
		t.Fatalf("EncodeRowsToColumns failed: %v", err)
	}

	if len(encodedCols) != n {
		t.Fatalf("unexpected column count: got %d want %d", len(encodedCols), n)
	}
	for col := 0; col < n; col++ {
		if len(encodedCols[col]) != k {
			t.Fatalf("unexpected column length at %d: got %d want %d", col, len(encodedCols[col]), k)
		}
		for row := 0; row < k; row++ {
			if !encodedCols[col][row].Equal(&encodedRows[row][col]) {
				t.Fatalf("mismatch at col=%d row=%d", col, row)
			}
		}
	}
}
