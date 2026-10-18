package main

import (
	"encoding/csv"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"example.com/lamp/benchmark"
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

func TestRepeatedExperiments(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	dir := t.TempDir()
	path := filepath.Join(dir, "repeated.csv")
	writer, err := benchmark.InitLAMPCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, logk := range []int{2, 3} {
		if err := runRepeatedExperiments(logk, "1/2", 2, false, "generate", dir, 3, writer); err != nil {
			t.Fatal(err)
		}
	}
	averagePath := filepath.Join(dir, "repeated_average.csv")
	if _, err := os.Stat(averagePath); !os.IsNotExist(err) {
		t.Fatal("average appeared before all configurations completed")
	}
	if err := writer.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	read := func(path string) [][]string {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		rows, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	for _, name := range []string{"repeated.csv", "repeated_info.csv", "repeated_memory.csv"} {
		rows := read(filepath.Join(dir, name))
		if len(rows) != 7 {
			t.Fatalf("%s: got %d repetitions, want 6", name, len(rows)-1)
		}
		columns := make(map[string]int)
		for i, key := range rows[0] {
			columns[key] = i
		}
		for i, row := range rows[1:] {
			if row[columns["repeat"]] != strconv.Itoa(i%3+1) || row[columns["logk"]] != strconv.Itoa(2+i/3) {
				t.Fatal("incorrect repetition order")
			}
			if name == "repeated_info.csv" && row[columns["matrix_compute_time"]] != rows[1+(i/3)*3][columns["matrix_compute_time"]] {
				t.Fatal("input computation was repeated instead of shared")
			}
		}
	}
	averages := read(averagePath)
	if len(averages) != 3 {
		t.Fatalf("got %d averages, want two sizes", len(averages)-1)
	}
	for _, row := range averages[1:] {
		for i, name := range averages[0] {
			if name == "runs" && row[i] != "3" {
				t.Fatal("average must contain three measurements")
			}
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
