package main

import (
	"testing"

	"example.com/lamp/crypto"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestStructuredBProximityFoldMatchesEncoding(t *testing.T) {
	const K, N = 4, 8

	matB := make([][]fr.Element, K)
	for i := range matB {
		matB[i] = make([]fr.Element, K)
		for j := range matB[i] {
			matB[i][j].SetUint64(uint64(i*K + j + 1))
		}
	}

	var challengeB fr.Element
	challengeB.SetUint64(7)
	challengeBPowers := matrix.Powers(challengeB, K)
	vecBTest := matrix.VecMatMul(challengeBPowers, matB, K)

	encoder := crypto.NewEncoder(K, N)
	colsEncB, err := encoder.EncodeRowsToColumns(matB)
	if err != nil {
		t.Fatal(err)
	}
	_, encBTest, err := encoder.Encode(vecBTest)
	if err != nil {
		t.Fatal(err)
	}

	for column := 0; column < N; column++ {
		var foldedColumn fr.Element
		for row := 0; row < K; row++ {
			var term fr.Element
			term.Mul(&challengeBPowers[row], &colsEncB[column][row])
			foldedColumn.Add(&foldedColumn, &term)
		}
		if !foldedColumn.Equal(&encBTest[column]) {
			t.Fatalf("folded B column %d does not match its RS codeword", column)
		}
	}
}
