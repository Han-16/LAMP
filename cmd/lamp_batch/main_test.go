package main

import "testing"

func TestBatchedBProximityEndToEnd(t *testing.T) {
	result := runExperiment(2, "1/2", 2, 2, false)
	if result.Constraints == 0 || result.TotalProofSize == 0 {
		t.Fatal("batch B proximity proof produced an empty result")
	}
}
