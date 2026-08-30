package main

import (
	"testing"

	"example.com/lamp/circuit"
	"example.com/lamp/crypto"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestBProximityFoldMatchesRectangularEncoding(t *testing.T) {
	const rows, cols, n = 3, 4, 8
	matB := make([][]fr.Element, rows)
	for i := range matB {
		matB[i] = make([]fr.Element, cols)
		for j := range matB[i] {
			matB[i][j].SetUint64(uint64(i*cols + j + 1))
		}
	}

	var challengeB fr.Element
	challengeB.SetUint64(7)
	bPowers := matrix.Powers(challengeB, rows)
	vecBTest := matrix.VecMatMulRect(bPowers, matB, rows, cols)

	encoder := crypto.NewEncoder(cols, n)
	_, encodedRows, err := encoder.EncodeRows(matB)
	if err != nil {
		t.Fatal(err)
	}
	encodedColumns := matrix.Transpose(encodedRows, rows, n)
	_, encBTest, err := encoder.Encode(vecBTest)
	if err != nil {
		t.Fatal(err)
	}

	for column := 0; column < n; column++ {
		if folded := foldNative(bPowers, encodedColumns[column]); !folded.Equal(&encBTest[column]) {
			t.Fatalf("folded B column %d does not match its RS codeword", column)
		}
	}

	var one fr.Element
	one.SetOne()
	encodedColumns[0][0].Add(&encodedColumns[0][0], &one)
	if folded := foldNative(bPowers, encodedColumns[0]); folded.Equal(&encBTest[0]) {
		t.Fatal("corrupted B column unexpectedly matched its RS codeword")
	}
}

func TestBProximityRSBatchesCoverEveryClaimOnce(t *testing.T) {
	_, specs := buildGPT2MediumTensorShapes(2)
	p := &preparedLayer{seqLen: 2, rho: "1/2", claims: make([]claimWitness, len(specs))}
	for i := range specs {
		p.claims[i].spec = specs[i]
	}

	p.addBProximityRSBatches()
	if len(p.rsBatches) != 4 {
		t.Fatalf("got %d B proximity batches, want 4 output-domain batches", len(p.rsBatches))
	}
	seen := make([]int, len(p.claims))
	for _, batch := range p.rsBatches {
		for _, term := range batch.terms {
			if term.side != circuit.LAMPGPT2RSSideBTest {
				t.Fatalf("unexpected RS side %d in B proximity batch", term.side)
			}
			seen[term.claimIndex]++
		}
	}
	for i, count := range seen {
		if count != 1 {
			t.Fatalf("claim %d appears in %d B proximity batches", i, count)
		}
	}
}

func foldNative(lhs, rhs []fr.Element) fr.Element {
	var out fr.Element
	for i := range lhs {
		var term fr.Element
		term.Mul(&lhs[i], &rhs[i])
		out.Add(&out, &term)
	}
	return out
}
