package main

import (
	"math"
	"testing"
)

func TestBatchedBProximityEndToEnd(t *testing.T) {
	result := runExperiment(2, "1/2", 2, 2, false)
	if result.Constraints == 0 || result.TotalProofSize == 0 {
		t.Fatal("batch B proximity proof produced an empty result")
	}
	if result.EncodingTime <= 0 || result.CommitTime <= 0 {
		t.Fatal("encoding and commit timings must both be positive")
	}
	if math.Abs(result.TotalCommitTime-(result.EncodingTime+result.CommitTime)) > 1e-9 {
		t.Fatal("total commit time does not equal encoding time plus commit time")
	}
	if result.PeakMemoryBytes == 0 {
		t.Fatal("peak memory must be recorded")
	}
}
