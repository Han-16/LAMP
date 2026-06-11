package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type FreivaldsBatchCircuit struct {
	A [][][]frontend.Variable
	B [][][]frontend.Variable
	C [][][]frontend.Variable
	K int
}

func (c *FreivaldsBatchCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	batch := len(c.A)
	committedValues := make([]frontend.Variable, 0, 3*batch*c.K*c.K)
	for b := 0; b < batch; b++ {
		for i := 0; i < c.K; i++ {
			for j := 0; j < c.K; j++ {
				committedValues = append(committedValues, c.A[b][i][j], c.B[b][i][j], c.C[b][i][j])
			}
		}
	}

	cm, err := committer.Commit(committedValues...)
	if err != nil {
		return err
	}
	h.Reset()
	h.Write(cm)
	r := h.Sum()

	R := Powers(api, r, c.K)
	for b := 0; b < batch; b++ {
		x := make([]frontend.Variable, c.K)
		for col := 0; col < c.K; col++ {
			xExpr := frontend.Variable(0)
			for row := 0; row < c.K; row++ {
				xExpr = api.Add(xExpr, api.Mul(R[row], c.A[b][row][col]))
			}

			xWire, err := materialize(api, xExpr)
			if err != nil {
				return err
			}
			api.AssertIsEqual(xWire, xExpr)
			x[col] = xWire
		}

		for col := 0; col < c.K; col++ {
			y := frontend.Variable(0)
			z := frontend.Variable(0)

			for i := 0; i < c.K; i++ {
				y = api.Add(y, api.Mul(x[i], c.B[b][i][col]))
				z = api.Add(z, api.Mul(R[i], c.C[b][i][col]))
			}

			api.AssertIsEqual(y, z)
		}
	}

	return nil
}
