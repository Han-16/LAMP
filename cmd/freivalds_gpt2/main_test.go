package main

import (
	"testing"

	"example.com/lamp/matrix"
)

func TestRepeatedInputsKeepFreshWitnesses(t *testing.T) {
	// Exercise the real layer proving path with a small graph.
	a := &tensor{id: 0, name: "A", rows: 2, cols: 2, data: matrix.GenerateRandomMatrix(2, 2)}
	b := &tensor{id: 1, name: "B", rows: 2, cols: 2, data: matrix.GenerateRandomMatrix(2, 2)}
	c := &tensor{id: 2, name: "C", rows: 2, cols: 2, data: matrix.MatMulRect(a.data, b.data, 2, 2, 2)}
	graph := graphSpec{input: a, output: c, tensors: []*tensor{a, b, c}, claims: []claimSpec{{id: 0, A: a, B: b, C: c}}}
	input := layerInput{graph: graph, computeTime: .123}
	original := a.data[0][0]
	for repeat := 0; repeat < 2; repeat++ {
		result := runExperimentWithInput(0, false, input)
		if result.ProofSize <= 0 || result.Constraints <= 0 || result.MatrixComputeTime != .123 || result.MatrixSource != "generate" {
			t.Fatalf("invalid repeated result: %+v", result)
		}
		if !result.SetupMemory.Measured || !result.ProveMemory.Measured {
			t.Fatal("stage RSS was not sampled")
		}
		assignment := buildCircuit(graph, true)
		assignment.Tensors[0].Values[0][0] = 0
		if !a.data[0][0].Equal(&original) {
			t.Fatal("repetition mutated shared tensors")
		}
	}
}
