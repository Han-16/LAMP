package main

import (
	"math"
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

func TestCommitAndProveTimingSplit(t *testing.T) {
	r := runExperiment(2, "1/2", 2, false, "generate", t.TempDir())
	if r.MatrixCommitTime <= 0 || r.VectorComputeTime <= 0 || r.VectorCommitTime <= 0 {
		t.Fatal("missing commitment phase timing")
	}
	if r.CPLinkProofSize != 64 || r.QueryCommitmentsSize != 128 {
		t.Fatalf("expected two compressed links and four query commitments: link=%d query=%d", r.CPLinkProofSize, r.QueryCommitmentsSize)
	}
	if r.TotalProofSize != r.Groth16ProofSize+r.MerkleProofSize+r.CPLinkProofSize+r.QueryCommitmentsSize {
		t.Fatal("proof payload total omits or double counts a component")
	}
	if !r.SetupMemory.Measured || !r.CommitMemory.Measured || !r.ProveMemory.Measured || r.SetupMemory.HeapBytes == 0 {
		t.Fatal("stage memory was not sampled")
	}
	if r.MatrixWorkers < 1 {
		t.Fatal("generated input must record worker count")
	}
	checks := [][2]float64{
		{r.MatrixCommitTime, r.EncodingTime + r.PedersenCommitTime + r.MerkleCommitTime},
		{r.SetupTime, r.ProtocolSetupTime + r.CircuitSetupTime + r.CPLinkSetupTime},
		{r.CommitTime, r.MatrixCommitTime + r.VectorCommitTime},
		{r.TotalCommitTime, r.MatrixCommitTime + r.VectorComputeTime + r.VectorCommitTime},
		{r.TotalProveTime, r.CircuitProveTime + r.MerkleProveTime + r.CPLinkProveTime},
		{r.CommitAndProveTime, r.TotalCommitTime + r.TotalProveTime},
	}
	for _, c := range checks {
		if math.Abs(c[0]-c[1]) > 1e-9 {
			t.Fatalf("invalid timing sum: got %g, want %g", c[0], c[1])
		}
	}
}
