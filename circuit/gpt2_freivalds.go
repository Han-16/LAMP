package circuit

import (
	"github.com/Han-16/meow/gpt2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type GPT2FreivaldsCircuit struct {
	Spec gpt2.LayerSpec

	Input  []frontend.Variable `gnark:",public"`
	Output []frontend.Variable `gnark:",public"`

	WQKV []frontend.Variable
	QKV  []frontend.Variable

	Attention GPT2FreivaldsAttentionBlock
	MLP       GPT2FreivaldsMLPBlock
}

type GPT2FreivaldsAttentionBlock struct {
	Heads   []GPT2FreivaldsAttentionHeadBlock
	Context []frontend.Variable
	WOut    []frontend.Variable
	Output  []frontend.Variable
}

type GPT2FreivaldsAttentionHeadBlock struct {
	Q       []frontend.Variable
	K       []frontend.Variable
	V       []frontend.Variable
	KT      []frontend.Variable
	Score   []frontend.Variable
	Context []frontend.Variable
}

type GPT2FreivaldsMLPBlock struct {
	WUp    []frontend.Variable
	Hidden []frontend.Variable
	WDown  []frontend.Variable
}

func (c *GPT2FreivaldsCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	cm, err := committer.Commit(c.committedValues()...)
	if err != nil {
		return err
	}

	c.enforceAttentionWiring(api)

	claimIndex := 0
	enforce := func(claim gpt2.MatmulClaim, A, B, C []frontend.Variable) {
		h.Reset()
		h.Write(cm, claimIndex+1)
		r := h.Sum()
		checkGPT2FreivaldsMatmul(api, claim, A, B, C, r)
		claimIndex++
	}

	enforce(c.Spec.Attention.QKV, c.Input, c.WQKV, c.QKV)
	for head := range c.Attention.Heads {
		headSpec := c.Spec.Attention.Heads[head]
		headCircuit := c.Attention.Heads[head]
		enforce(headSpec.Score, headCircuit.Q, headCircuit.KT, headCircuit.Score)
		enforce(headSpec.Value, headCircuit.Score, headCircuit.V, headCircuit.Context)
	}
	enforce(c.Spec.Attention.Projection, c.Attention.Context, c.Attention.WOut, c.Attention.Output)
	enforce(c.Spec.MLP.Up, c.Attention.Output, c.MLP.WUp, c.MLP.Hidden)
	enforce(c.Spec.MLP.Down, c.MLP.Hidden, c.MLP.WDown, c.Output)

	return nil
}

func (c *GPT2FreivaldsCircuit) committedValues() []frontend.Variable {
	total := len(c.WQKV) + len(c.QKV)
	total += len(c.Attention.Context) + len(c.Attention.WOut) + len(c.Attention.Output)
	total += len(c.MLP.WUp) + len(c.MLP.Hidden) + len(c.MLP.WDown)
	for head := range c.Attention.Heads {
		h := c.Attention.Heads[head]
		total += len(h.Q) + len(h.K) + len(h.V) + len(h.KT) + len(h.Score) + len(h.Context)
	}

	out := make([]frontend.Variable, 0, total)
	out = append(out, c.WQKV...)
	out = append(out, c.QKV...)
	for head := range c.Attention.Heads {
		h := c.Attention.Heads[head]
		out = append(out, h.Q...)
		out = append(out, h.K...)
		out = append(out, h.V...)
		out = append(out, h.KT...)
		out = append(out, h.Score...)
		out = append(out, h.Context...)
	}
	out = append(out, c.Attention.Context...)
	out = append(out, c.Attention.WOut...)
	out = append(out, c.Attention.Output...)
	out = append(out, c.MLP.WUp...)
	out = append(out, c.MLP.Hidden...)
	out = append(out, c.MLP.WDown...)
	return out
}

func (c *GPT2FreivaldsCircuit) enforceAttentionWiring(api frontend.API) {
	S := c.Spec.SeqLen
	D := c.Spec.Model.Embd
	Dh := c.Spec.HeadDim

	for head := range c.Attention.Heads {
		h := c.Attention.Heads[head]
		for row := 0; row < S; row++ {
			for col := 0; col < Dh; col++ {
				api.AssertIsEqual(h.Q[row*Dh+col], c.QKV[row*3*D+head*Dh+col])
				api.AssertIsEqual(h.K[row*Dh+col], c.QKV[row*3*D+D+head*Dh+col])
				api.AssertIsEqual(h.V[row*Dh+col], c.QKV[row*3*D+2*D+head*Dh+col])
				api.AssertIsEqual(h.KT[col*S+row], h.K[row*Dh+col])
				api.AssertIsEqual(c.Attention.Context[row*D+head*Dh+col], h.Context[row*Dh+col])
			}
		}
	}
}

func checkGPT2FreivaldsMatmul(api frontend.API, claim gpt2.MatmulClaim, A, B, C []frontend.Variable, r frontend.Variable) {
	powers := Powers(api, r, claim.Rows)

	x := make([]frontend.Variable, claim.Inner)
	for col := 0; col < claim.Inner; col++ {
		xExpr := frontend.Variable(0)
		for row := 0; row < claim.Rows; row++ {
			xExpr = api.Add(xExpr, api.Mul(powers[row], A[row*claim.Inner+col]))
		}

		xWire, err := materialize(api, xExpr)
		if err != nil {
			panic(err)
		}
		api.AssertIsEqual(xWire, xExpr)
		x[col] = xWire
	}

	for col := 0; col < claim.Cols; col++ {
		y := frontend.Variable(0)
		z := frontend.Variable(0)
		for i := 0; i < claim.Inner; i++ {
			y = api.Add(y, api.Mul(x[i], B[i*claim.Cols+col]))
		}
		for row := 0; row < claim.Rows; row++ {
			z = api.Add(z, api.Mul(powers[row], C[row*claim.Cols+col]))
		}
		api.AssertIsEqual(y, z)
	}
}
