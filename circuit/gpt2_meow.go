package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

type GPT2MeowCircuit struct {
	Input      []frontend.Variable `gnark:",public"`
	Output     []frontend.Variable `gnark:",public"`
	GroupRoots []frontend.Variable `gnark:",public"`

	Groups    []GPT2MeowGroup
	Attention GPT2MeowAttentionBlock
	MLP       GPT2MeowMLPBlock
}

const (
	GPT2MeowGroupMatrix = iota
	GPT2MeowGroupScalar
)

type GPT2MeowGroup struct {
	Kind  int
	Width int
}

type GPT2MeowAttentionBlock struct {
	QKV        GPT2MeowMatmulClaim
	Heads      []GPT2MeowAttentionHeadBlock
	Projection GPT2MeowMatmulClaim
}

type GPT2MeowAttentionHeadBlock struct {
	Score GPT2MeowMatmulClaim
	Value GPT2MeowMatmulClaim
}

type GPT2MeowMLPBlock struct {
	Up   GPT2MeowMatmulClaim
	Down GPT2MeowMatmulClaim
}

type GPT2MeowMatmulClaim struct {
	Rows, Inner, Cols int
	KX, KY            int
	NX, NY            int
	DepthX, DepthY    int

	DomainInner  []fr.Element
	WeightsInner []fr.Element
	DomainX      []fr.Element
	WeightsX     []fr.Element

	DomainCols  []fr.Element
	WeightsCols []fr.Element
	DomainY     []fr.Element
	WeightsY    []fr.Element

	RowsGroup   int
	InnerGroup  int
	ScalarGroup int

	CmABC      frontend.Variable   `gnark:",public"`
	CmXYZ      frontend.Variable   `gnark:",public"`
	ChallengeR frontend.Variable   `gnark:",public"`
	IndicesX   []frontend.Variable `gnark:",public"`
	IndicesY   []frontend.Variable `gnark:",public"`
	RSPointX   frontend.Variable   `gnark:",public"`
	RSPointYZ  frontend.Variable   `gnark:",public"`

	ColsEncA [][]frontend.Variable // [L][Rows]
	ColsEncB [][]frontend.Variable // [L][Inner]
	ColsEncC [][]frontend.Variable // [L][Rows]

	VecX  []frontend.Variable // [KX], first Inner entries are used by B
	VecYZ []frontend.Variable // [KY]
	EncX  []frontend.Variable // [NX]
	EncYZ []frontend.Variable // [NY]

	TargetEncX  []frontend.Variable // [L]
	TargetEncYZ []frontend.Variable // [L]
}

func (c *GPT2MeowCircuit) Define(api frontend.API) error {
	if err := c.commitGroupedWitnesses(api); err != nil {
		return err
	}

	if err := c.proveAttentionQKVProjection(api); err != nil {
		return err
	}

	for head := range c.Attention.Heads {
		if err := c.proveSelfAttentionHead(api, head); err != nil {
			return err
		}
	}

	if err := c.proveAttentionOutputProjection(api); err != nil {
		return err
	}

	if err := c.proveMLP(api); err != nil {
		return err
	}

	enforcePublicOutputProjection(api, c.Output, &c.MLP.Down)
	return nil
}

func (c *GPT2MeowCircuit) commitGroupedWitnesses(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	claims := c.claimsInGPT2Order()

	for group := range c.Groups {
		var values []frontend.Variable
		for _, m := range claims {
			if m.RowsGroup == group {
				values = append(values, FlattenRows(m.ColsEncA)...)
			}
			if m.InnerGroup == group {
				values = append(values, FlattenRows(m.ColsEncB)...)
			}
			if m.RowsGroup == group {
				values = append(values, FlattenRows(m.ColsEncC)...)
			}
			if m.ScalarGroup == group {
				values = append(values, m.TargetEncX...)
				values = append(values, m.TargetEncYZ...)
			}
		}
		if len(values) == 0 {
			continue
		}
		if _, err := committer.Commit(values...); err != nil {
			return err
		}
	}
	return nil
}

func (c *GPT2MeowCircuit) claimsInGPT2Order() []*GPT2MeowMatmulClaim {
	claims := []*GPT2MeowMatmulClaim{&c.Attention.QKV}
	for head := range c.Attention.Heads {
		claims = append(claims, &c.Attention.Heads[head].Score, &c.Attention.Heads[head].Value)
	}
	claims = append(claims, &c.Attention.Projection, &c.MLP.Up, &c.MLP.Down)
	return claims
}

func (c *GPT2MeowCircuit) proveAttentionQKVProjection(api frontend.API) error {
	if err := enforceMeowMatmul(api, c.GroupRoots, &c.Attention.QKV); err != nil {
		return err
	}
	enforcePublicInputProjection(api, c.Input, &c.Attention.QKV)
	return nil
}

func (c *GPT2MeowCircuit) proveSelfAttentionHead(api frontend.API, head int) error {
	if err := enforceMeowMatmul(api, c.GroupRoots, &c.Attention.Heads[head].Score); err != nil {
		return err
	}

	softmaxIsOmittedForMatmulOnlyExperiment(api)

	if err := enforceMeowMatmul(api, c.GroupRoots, &c.Attention.Heads[head].Value); err != nil {
		return err
	}
	return nil
}

func (c *GPT2MeowCircuit) proveAttentionOutputProjection(api frontend.API) error {
	return enforceMeowMatmul(api, c.GroupRoots, &c.Attention.Projection)
}

func (c *GPT2MeowCircuit) proveMLP(api frontend.API) error {
	if err := enforceMeowMatmul(api, c.GroupRoots, &c.MLP.Up); err != nil {
		return err
	}
	return enforceMeowMatmul(api, c.GroupRoots, &c.MLP.Down)
}

func softmaxIsOmittedForMatmulOnlyExperiment(api frontend.API) {
	_ = api
}

func enforceMeowMatmul(api frontend.API, groupRoots []frontend.Variable, m *GPT2MeowMatmulClaim) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	Lx := len(m.IndicesX)
	Ly := len(m.IndicesY)
	challengeRPowers := Powers(api, m.ChallengeR, m.Rows)

	tX := logderivlookup.New(api)
	for j := 0; j < m.NX; j++ {
		tX.Insert(m.EncX[j])
	}
	tYZ := logderivlookup.New(api)
	for j := 0; j < m.NY; j++ {
		tYZ.Insert(m.EncYZ[j])
	}

	for i := 0; i < Lx; i++ {
		exprEncX := tX.Lookup(m.IndicesX[i])[0]
		api.AssertIsEqual(exprEncX, m.TargetEncX[i])

		foldA := Fold(api, challengeRPowers, m.ColsEncA[i])
		api.AssertIsEqual(foldA, m.TargetEncX[i])
	}

	for i := 0; i < Ly; i++ {
		exprEncYZ := tYZ.Lookup(m.IndicesY[i])[0]
		api.AssertIsEqual(exprEncYZ, m.TargetEncYZ[i])

		foldB := Fold(api, m.VecX[:m.Inner], m.ColsEncB[i])
		foldC := Fold(api, challengeRPowers, m.ColsEncC[i])
		api.AssertIsEqual(foldB, m.TargetEncYZ[i])
		api.AssertIsEqual(foldC, m.TargetEncYZ[i])
	}

	h.Reset()
	h.Write(groupRoots[m.RowsGroup], groupRoots[m.InnerGroup], groupRoots[m.RowsGroup])
	api.AssertIsEqual(m.CmABC, h.Sum())

	h.Reset()
	h.Write(groupRoots[m.ScalarGroup], groupRoots[m.ScalarGroup])
	api.AssertIsEqual(m.CmXYZ, h.Sum())

	VerifyRSEncoding(api, m.KX, m.NX, m.DomainInner, m.WeightsInner, m.DomainX, m.WeightsX, m.VecX, m.EncX, m.RSPointX)
	VerifyRSEncoding(api, m.KY, m.NY, m.DomainCols, m.WeightsCols, m.DomainY, m.WeightsY, m.VecYZ, m.EncYZ, m.RSPointYZ)

	return nil
}

func enforcePublicInputProjection(api frontend.API, publicInput []frontend.Variable, qkv *GPT2MeowMatmulClaim) {
	powers := Powers(api, qkv.ChallengeR, qkv.Rows)
	for col := 0; col < qkv.Inner; col++ {
		fold := frontend.Variable(0)
		for row := 0; row < qkv.Rows; row++ {
			fold = api.Add(fold, api.Mul(powers[row], publicInput[row*qkv.Inner+col]))
		}
		api.AssertIsEqual(fold, qkv.VecX[col])
	}
}

func enforcePublicOutputProjection(api frontend.API, publicOutput []frontend.Variable, final *GPT2MeowMatmulClaim) {
	powers := Powers(api, final.ChallengeR, final.Rows)
	for col := 0; col < final.Cols; col++ {
		fold := frontend.Variable(0)
		for row := 0; row < final.Rows; row++ {
			fold = api.Add(fold, api.Mul(powers[row], publicOutput[row*final.Cols+col]))
		}
		api.AssertIsEqual(fold, final.VecYZ[col])
	}
}
