package circuit

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

func init() {
	solver.RegisterHint(materializeHint)
}

type FreivaldsCircuit struct {
	A [][]frontend.Variable
	B [][]frontend.Variable
	C [][]frontend.Variable
	K int
}

func (c *FreivaldsCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	committedValues := make([]frontend.Variable, 0, 3*c.K*c.K)
	for i := 0; i < c.K; i++ {
		for j := 0; j < c.K; j++ {
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

	R := Powers(api, r, c.K)

	x := make([]frontend.Variable, c.K)
	for col := 0; col < c.K; col++ {
		xExpr := frontend.Variable(0)
		for row := 0; row < c.K; row++ {
			xExpr = api.Add(xExpr, api.Mul(R[row], c.A[row][col]))
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
			y = api.Add(y, api.Mul(x[i], c.B[i][col]))
			z = api.Add(z, api.Mul(R[i], c.C[i][col]))
		}

		api.AssertIsEqual(y, z)
	}

	return nil
}

func materialize(api frontend.API, value frontend.Variable) (frontend.Variable, error) {
	out, err := api.Compiler().NewHint(materializeHint, 1, value)
	if err != nil {
		return nil, err
	}
	return out[0], nil
}

func materializeHint(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != 1 {
		return fmt.Errorf("materialize hint expects 1 input and 1 output")
	}
	outputs[0].Set(inputs[0])
	if field != nil {
		outputs[0].Mod(outputs[0], field)
	}
	return nil
}
