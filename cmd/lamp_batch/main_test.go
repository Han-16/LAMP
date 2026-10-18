package main

import (
	"math"
	"testing"

	"example.com/lamp/matrix"
)

func TestBatchedBProximityEndToEnd(t *testing.T) {
	dir := t.TempDir()
	input, err := matrix.Prepare(4, "generate", dir)
	if err != nil {
		t.Fatal(err)
	}
	path := matrix.FilePath(dir, 4)
	if err := matrix.Save(path, input.A, input.B, input.C); err != nil {
		t.Fatal(err)
	}
	result := runExperiment(2, "1/2", 2, 5, false, "auto", dir)
	if result.Batch != 5 || result.MatrixSource != "file" || result.MatrixPath != path || result.MatrixComputeTime != 0 {
		t.Fatal("batch must reuse one saved product without matrix multiplication")
	}
	if result.MatrixWorkers != 0 {
		t.Fatal("file input must not record multiplication workers")
	}
	if result.CPLinkProofSize != 64 || result.QueryCommitmentsSize != 128 {
		t.Fatal("proof points must use compressed sizes")
	}
	if result.TotalProofSize != result.Groth16ProofSize+result.MerkleProofSize+result.CPLinkProofSize+result.QueryCommitmentsSize {
		t.Fatal("wrong proof payload total")
	}
	if !result.SetupMemory.Measured || !result.CommitMemory.Measured || !result.ProveMemory.Measured {
		t.Fatal("stage memory missing")
	}
	if result.Constraints == 0 || result.TotalProofSize == 0 {
		t.Fatal("batch B proximity proof produced an empty result")
	}
	if result.EncodingTime <= 0 || result.CommitTime <= 0 {
		t.Fatal("encoding and commit timings must both be positive")
	}
	if math.Abs(result.TotalCommitTime-(result.MatrixCommitTime+result.VectorComputeTime+result.VectorCommitTime)) > 1e-9 {
		t.Fatal("total commit time must sum ABC, vector computation and vector commitments")
	}
	if result.VectorComputeTime <= 0 || result.VectorCommitTime <= 0 || result.MatrixCommitTime <= 0 {
		t.Fatal("missing commitment phase timing")
	}
	if math.Abs(result.TotalProveTime-(result.CircuitProveTime+result.MerkleProveTime+result.CPLinkProveTime)) > 1e-9 {
		t.Fatal("total prove time includes work outside proof generation")
	}
	if math.Abs(result.CommitAndProveTime-(result.TotalCommitTime+result.TotalProveTime)) > 1e-9 {
		t.Fatal("commit and prove time must sum both phases")
	}
	if result.PeakMemoryBytes == 0 {
		t.Fatal("peak memory must be recorded")
	}
}
