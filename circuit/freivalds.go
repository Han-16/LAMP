package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type FreivaldsCircuit struct {
	A [][]frontend.Variable
	B [][]frontend.Variable
	C [][]frontend.Variable
	K int
}

func (c *FreivaldsCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, _ := mimc.NewMiMC(api)
	var committedValues []frontend.Variable
	for i := 0; i < len(c.A); i++ {
		for j := 0; j < len(c.A[0]); j++ {
			committedValues = append(committedValues, c.A[i][j], c.B[i][j], c.C[i][j])
		}
	}
	cm, err := committer.Commit(committedValues...)
	if err != nil {
		return err
	}
	h.Reset()
	h.Write(cm)
	r := h.Sum()

	R := make([]frontend.Variable, c.K)
	R[0] = 1
	for i := 1; i < c.K; i++ {
		R[i] = api.Mul(R[i-1], r)
	}

	// 1. x = R * A 계산
	x := make([]frontend.Variable, c.K)
	for j := 0; j < c.K; j++ {
		x[j] = frontend.Variable(0)
		for i := 0; i < c.K; i++ {
			x[j] = api.Add(x[j], api.Mul(R[i], c.A[i][j]))
		}
	}

	for j := 0; j < c.K; j++ {
		y := frontend.Variable(0)
		z := frontend.Variable(0)

		for i := 0; i < c.K; i++ {
			y = api.Add(y, api.Mul(x[i], c.B[i][j]))
			z = api.Add(z, api.Mul(R[i], c.C[i][j]))
		}

		// 원소가 동일한지 검증
		api.AssertIsEqual(y, z)
	}

	return nil
}
