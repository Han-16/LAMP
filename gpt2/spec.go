package gpt2

import (
	"fmt"

	"github.com/Han-16/meow/matrix"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type ModelSpec struct {
	Name  string
	Embd  int
	Heads int
	MLP   int
}

func Model(name string) (ModelSpec, error) {
	switch name {
	case "small":
		return ModelSpec{Name: "small", Embd: 768, Heads: 12, MLP: 3072}, nil
	case "medium":
		return ModelSpec{Name: "medium", Embd: 1024, Heads: 16, MLP: 4096}, nil
	default:
		return ModelSpec{}, fmt.Errorf("unknown GPT-2 model %q", name)
	}
}

func (m ModelSpec) HeadDim() int {
	return m.Embd / m.Heads
}

type TensorShape struct {
	Name string
	Rows int
	Cols int
}

type MatmulClaim struct {
	Name  string
	Rows  int
	Inner int
	Cols  int
}

type AttentionHeadSpec struct {
	Index int
	Score MatmulClaim
	Value MatmulClaim
}

type AttentionSpec struct {
	QKV        MatmulClaim
	Heads      []AttentionHeadSpec
	Projection MatmulClaim
}

type MLPSpec struct {
	Up   MatmulClaim
	Down MatmulClaim
}

type LayerSpec struct {
	Model   ModelSpec
	SeqLen  int
	HeadDim int

	Attention AttentionSpec
	MLP       MLPSpec
}

func NewLayerSpec(model ModelSpec, seqLen int) LayerSpec {
	if seqLen <= 0 {
		panic("GPT-2 sequence length must be positive")
	}
	if model.Heads <= 0 || model.Embd%model.Heads != 0 {
		panic("GPT-2 embedding dimension must be divisible by head count")
	}

	D := model.Embd
	H := model.Heads
	Dh := model.HeadDim()
	M := model.MLP
	S := seqLen

	heads := make([]AttentionHeadSpec, H)
	for head := 0; head < H; head++ {
		heads[head] = AttentionHeadSpec{
			Index: head,
			Score: MatmulClaim{
				Name:  fmt.Sprintf("attention.head.%02d.score", head),
				Rows:  S,
				Inner: Dh,
				Cols:  S,
			},
			Value: MatmulClaim{
				Name:  fmt.Sprintf("attention.head.%02d.value", head),
				Rows:  S,
				Inner: S,
				Cols:  Dh,
			},
		}
	}

	return LayerSpec{
		Model:   model,
		SeqLen:  S,
		HeadDim: Dh,
		Attention: AttentionSpec{
			QKV: MatmulClaim{
				Name:  "attention.qkv",
				Rows:  S,
				Inner: D,
				Cols:  3 * D,
			},
			Heads: heads,
			Projection: MatmulClaim{
				Name:  "attention.projection",
				Rows:  S,
				Inner: D,
				Cols:  D,
			},
		},
		MLP: MLPSpec{
			Up: MatmulClaim{
				Name:  "mlp.up",
				Rows:  S,
				Inner: D,
				Cols:  M,
			},
			Down: MatmulClaim{
				Name:  "mlp.down",
				Rows:  S,
				Inner: M,
				Cols:  D,
			},
		},
	}
}

func (s LayerSpec) ClaimCount() int {
	return 1 + 2*len(s.Attention.Heads) + 3
}

type AttentionHeadData struct {
	Q       [][]fr.Element
	K       [][]fr.Element
	V       [][]fr.Element
	KT      [][]fr.Element
	Score   [][]fr.Element
	Context [][]fr.Element
}

type AttentionData struct {
	WQKV    [][]fr.Element
	QKV     [][]fr.Element
	Heads   []AttentionHeadData
	Context [][]fr.Element
	WOut    [][]fr.Element
	Output  [][]fr.Element
}

type MLPData struct {
	WUp    [][]fr.Element
	Hidden [][]fr.Element
	WDown  [][]fr.Element
	Output [][]fr.Element
}

type LayerData struct {
	Spec      LayerSpec
	Input     [][]fr.Element
	Attention AttentionData
	MLP       MLPData
	Output    [][]fr.Element
}

func GenerateLayerData(spec LayerSpec) LayerData {
	S := spec.SeqLen
	D := spec.Model.Embd
	Dh := spec.HeadDim
	M := spec.Model.MLP

	input := matrix.GenerateRandomMatrix(S, D)
	wQKV := matrix.GenerateRandomMatrix(D, 3*D)
	qkv := matrix.MatMulRect(input, wQKV, S, D, 3*D)

	heads := make([]AttentionHeadData, len(spec.Attention.Heads))
	headContexts := make([][][]fr.Element, len(spec.Attention.Heads))
	for head := range heads {
		q := sliceColumns(qkv, head*Dh, Dh)
		k := sliceColumns(qkv, D+head*Dh, Dh)
		v := sliceColumns(qkv, 2*D+head*Dh, Dh)
		kt := matrix.Transpose(k, S, Dh)
		score := matrix.MatMulRect(q, kt, S, Dh, S)
		context := matrix.MatMulRect(score, v, S, S, Dh)
		heads[head] = AttentionHeadData{
			Q:       q,
			K:       k,
			V:       v,
			KT:      kt,
			Score:   score,
			Context: context,
		}
		headContexts[head] = context
	}

	attentionContext := concatHeadContexts(headContexts, S, Dh)
	wOut := matrix.GenerateRandomMatrix(D, D)
	attentionOutput := matrix.MatMulRect(attentionContext, wOut, S, D, D)

	wUp := matrix.GenerateRandomMatrix(D, M)
	hidden := matrix.MatMulRect(attentionOutput, wUp, S, D, M)
	wDown := matrix.GenerateRandomMatrix(M, D)
	output := matrix.MatMulRect(hidden, wDown, S, M, D)

	return LayerData{
		Spec:  spec,
		Input: input,
		Attention: AttentionData{
			WQKV:    wQKV,
			QKV:     qkv,
			Heads:   heads,
			Context: attentionContext,
			WOut:    wOut,
			Output:  attentionOutput,
		},
		MLP: MLPData{
			WUp:    wUp,
			Hidden: hidden,
			WDown:  wDown,
			Output: output,
		},
		Output: output,
	}
}

func sliceColumns(values [][]fr.Element, start, width int) [][]fr.Element {
	out := make([][]fr.Element, len(values))
	for row := range values {
		out[row] = make([]fr.Element, width)
		copy(out[row], values[row][start:start+width])
	}
	return out
}

func concatHeadContexts(heads [][][]fr.Element, rows, headDim int) [][]fr.Element {
	out := make([][]fr.Element, rows)
	for row := 0; row < rows; row++ {
		out[row] = make([]fr.Element, len(heads)*headDim)
		for head := range heads {
			copy(out[row][head*headDim:(head+1)*headDim], heads[head][row])
		}
	}
	return out
}
