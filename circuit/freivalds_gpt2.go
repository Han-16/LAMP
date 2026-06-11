package circuit

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
)

type FreivaldsGPT2Circuit struct {
	Input  []frontend.Variable `gnark:",public"`
	Output []frontend.Variable `gnark:",public"`

	Tensors         []FreivaldsGPT2Tensor
	Claims          []FreivaldsGPT2Claim
	SliceChecks     []FreivaldsGPT2SliceCheck
	TransposeChecks []FreivaldsGPT2TransposeCheck
	SumChecks       []FreivaldsGPT2SumCheck

	InputTensor  int
	OutputTensor int
}

type FreivaldsGPT2Tensor struct {
	Rows   int
	Cols   int
	Values [][]frontend.Variable
}

type FreivaldsGPT2Claim struct {
	ID      int
	A, B, C int
}

type FreivaldsGPT2TransposeCheck struct {
	Left, Right int
}

type FreivaldsGPT2SliceCheck struct {
	Left, Right    int
	RightColOffset int
}

type FreivaldsGPT2SumCheck struct {
	Output int
	Terms  []int
}

func (c *FreivaldsGPT2Circuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	committedValues := make([]frontend.Variable, 0)
	for i := range c.Tensors {
		committedValues = append(committedValues, FlattenRows(c.Tensors[i].Values)...)
	}

	cm, err := committer.Commit(committedValues...)
	if err != nil {
		return err
	}
	h.Reset()
	h.Write(cm)
	globalChallenge := h.Sum()

	if err := c.definePublicIO(api); err != nil {
		return err
	}

	for i := range c.Claims {
		if err := c.defineClaim(api, &h, globalChallenge, &c.Claims[i]); err != nil {
			return err
		}
	}

	for i := range c.SliceChecks {
		if err := c.defineSlice(api, &c.SliceChecks[i]); err != nil {
			return err
		}
	}

	for i := range c.TransposeChecks {
		if err := c.defineTranspose(api, &c.TransposeChecks[i]); err != nil {
			return err
		}
	}

	for i := range c.SumChecks {
		if err := c.defineSum(api, &c.SumChecks[i]); err != nil {
			return err
		}
	}

	return nil
}

func (c *FreivaldsGPT2Circuit) definePublicIO(api frontend.API) error {
	if c.InputTensor < 0 || c.InputTensor >= len(c.Tensors) {
		return fmt.Errorf("invalid Freivalds GPT-2 public input tensor index %d", c.InputTensor)
	}
	if c.OutputTensor < 0 || c.OutputTensor >= len(c.Tensors) {
		return fmt.Errorf("invalid Freivalds GPT-2 public output tensor index %d", c.OutputTensor)
	}

	input := c.Tensors[c.InputTensor]
	output := c.Tensors[c.OutputTensor]
	if len(c.Input) != input.Rows*input.Cols {
		return fmt.Errorf("invalid Freivalds GPT-2 public input length %d, expected %d", len(c.Input), input.Rows*input.Cols)
	}
	if len(c.Output) != output.Rows*output.Cols {
		return fmt.Errorf("invalid Freivalds GPT-2 public output length %d, expected %d", len(c.Output), output.Rows*output.Cols)
	}

	for row := 0; row < input.Rows; row++ {
		for col := 0; col < input.Cols; col++ {
			api.AssertIsEqual(input.Values[row][col], c.Input[row*input.Cols+col])
		}
	}
	for row := 0; row < output.Rows; row++ {
		for col := 0; col < output.Cols; col++ {
			api.AssertIsEqual(output.Values[row][col], c.Output[row*output.Cols+col])
		}
	}

	return nil
}

func (c *FreivaldsGPT2Circuit) defineClaim(api frontend.API, h hash.FieldHasher, globalChallenge frontend.Variable, claim *FreivaldsGPT2Claim) error {
	A := c.Tensors[claim.A]
	B := c.Tensors[claim.B]
	C := c.Tensors[claim.C]
	if A.Cols != B.Rows || A.Rows != C.Rows || B.Cols != C.Cols {
		return fmt.Errorf("invalid Freivalds GPT-2 claim %d: A=%dx%d B=%dx%d C=%dx%d", claim.ID, A.Rows, A.Cols, B.Rows, B.Cols, C.Rows, C.Cols)
	}

	h.Reset()
	h.Write(globalChallenge, claim.ID)
	challenge := h.Sum()
	challengePowers := Powers(api, challenge, A.Rows)

	foldedA := make([]frontend.Variable, A.Cols)
	for col := 0; col < A.Cols; col++ {
		value := frontend.Variable(0)
		for row := 0; row < A.Rows; row++ {
			value = api.Add(value, api.Mul(challengePowers[row], A.Values[row][col]))
		}

		wire, err := materialize(api, value)
		if err != nil {
			return err
		}
		api.AssertIsEqual(wire, value)
		foldedA[col] = wire
	}

	for col := 0; col < C.Cols; col++ {
		lhs := frontend.Variable(0)
		rhs := frontend.Variable(0)

		for i := 0; i < A.Cols; i++ {
			lhs = api.Add(lhs, api.Mul(foldedA[i], B.Values[i][col]))
		}
		for row := 0; row < C.Rows; row++ {
			rhs = api.Add(rhs, api.Mul(challengePowers[row], C.Values[row][col]))
		}

		api.AssertIsEqual(lhs, rhs)
	}

	return nil
}

func (c *FreivaldsGPT2Circuit) defineSlice(api frontend.API, check *FreivaldsGPT2SliceCheck) error {
	left := c.Tensors[check.Left]
	right := c.Tensors[check.Right]
	if left.Rows != right.Rows || check.RightColOffset < 0 || check.RightColOffset+left.Cols > right.Cols {
		return fmt.Errorf("invalid Freivalds GPT-2 slice check: left=%dx%d right=%dx%d offset=%d", left.Rows, left.Cols, right.Rows, right.Cols, check.RightColOffset)
	}
	for row := 0; row < left.Rows; row++ {
		for col := 0; col < left.Cols; col++ {
			api.AssertIsEqual(left.Values[row][col], right.Values[row][check.RightColOffset+col])
		}
	}
	return nil
}

func (c *FreivaldsGPT2Circuit) defineTranspose(api frontend.API, check *FreivaldsGPT2TransposeCheck) error {
	left := c.Tensors[check.Left]
	right := c.Tensors[check.Right]
	if left.Rows != right.Cols || left.Cols != right.Rows {
		return fmt.Errorf("invalid Freivalds GPT-2 transpose check: left=%dx%d right=%dx%d", left.Rows, left.Cols, right.Rows, right.Cols)
	}
	for row := 0; row < left.Rows; row++ {
		for col := 0; col < left.Cols; col++ {
			api.AssertIsEqual(left.Values[row][col], right.Values[col][row])
		}
	}
	return nil
}

func (c *FreivaldsGPT2Circuit) defineSum(api frontend.API, check *FreivaldsGPT2SumCheck) error {
	output := c.Tensors[check.Output]
	for _, termID := range check.Terms {
		term := c.Tensors[termID]
		if term.Rows != output.Rows || term.Cols != output.Cols {
			return fmt.Errorf("invalid Freivalds GPT-2 sum check: output=%dx%d term=%dx%d", output.Rows, output.Cols, term.Rows, term.Cols)
		}
	}
	for row := 0; row < output.Rows; row++ {
		for col := 0; col < output.Cols; col++ {
			sum := frontend.Variable(0)
			for _, termID := range check.Terms {
				sum = api.Add(sum, c.Tensors[termID].Values[row][col])
			}
			api.AssertIsEqual(output.Values[row][col], sum)
		}
	}
	return nil
}
