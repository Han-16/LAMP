package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

type MeowGPT2Circuit struct {
	Input  []frontend.Variable `gnark:",public"`
	Output []frontend.Variable `gnark:",public"`

	ColumnGroups []MeowGPT2ColumnGroup
	Scalars      []frontend.Variable

	GroupRoots [5]frontend.Variable `gnark:",public"` // length S, D, Dh, M, scalar
	TensorCm   frontend.Variable    `gnark:",public"`
	GlobalCm   frontend.Variable    `gnark:",public"`

	Claims          []MeowGPT2RectClaim
	EqualityChecks  []MeowGPT2EntryEqualityCheck
	TransposeChecks []MeowGPT2TransposeCheck
	SumChecks       []MeowGPT2SumCheck
}

type MeowGPT2ColumnGroup struct {
	BlockLen int
	Blocks   [][]frontend.Variable
}

type MeowGPT2RectClaim struct {
	ID                int
	Rows, Inner, Cols int
	NIn, NOut         int

	DomainKIn  []fr.Element
	WeightsKIn []fr.Element
	DomainNIn  []fr.Element
	WeightsNIn []fr.Element

	DomainKOut  []fr.Element
	WeightsKOut []fr.Element
	DomainNOut  []fr.Element
	WeightsNOut []fr.Element

	IndicesIn  []frontend.Variable `gnark:",public"`
	IndicesOut []frontend.Variable `gnark:",public"`
	RSPointX   frontend.Variable   `gnark:",public"`
	RSPointYZ  frontend.Variable   `gnark:",public"`

	AGroup, BGroup, CGroup int
	ABlocks, BBlocks       []int
	CBlocks                []int
	TargetXScalars         []int
	TargetYZScalars        []int
	BindPublicInput        bool
	BindPublicOutput       bool

	VecX  []frontend.Variable
	VecYZ []frontend.Variable
	EncX  []frontend.Variable
	EncYZ []frontend.Variable
}

type MeowGPT2TransposeCheck struct {
	LeftGroup, RightGroup int
	LeftBlocks            []int
	RightBlocks           []int
	RowIndices            []frontend.Variable `gnark:",public"`
	ColIndices            []frontend.Variable `gnark:",public"`
}

type MeowGPT2EntryEqualityCheck struct {
	LeftGroup, RightGroup int
	LeftBlocks            []int
	RightBlocks           []int
	LeftIndices           []frontend.Variable `gnark:",public"`
	RightIndices          []frontend.Variable `gnark:",public"`
}

type MeowGPT2SumCheck struct {
	OutputGroup int
	OutputBlock int
	TermGroup   int
	TermBlocks  []int
}

func (c *MeowGPT2Circuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := range c.ColumnGroups {
		if len(c.ColumnGroups[i].Blocks) == 0 {
			continue
		}
		if _, err := committer.Commit(FlattenRows(c.ColumnGroups[i].Blocks)...); err != nil {
			return err
		}
	}
	if len(c.Scalars) > 0 {
		if _, err := committer.Commit(c.Scalars...); err != nil {
			return err
		}
	}

	h.Reset()
	h.Write(c.GroupRoots[0], c.GroupRoots[1], c.GroupRoots[2], c.GroupRoots[3])
	api.AssertIsEqual(c.TensorCm, h.Sum())

	h.Reset()
	h.Write(c.GroupRoots[0], c.GroupRoots[1], c.GroupRoots[2], c.GroupRoots[3], c.GroupRoots[4])
	api.AssertIsEqual(c.GlobalCm, h.Sum())

	for i := range c.Claims {
		if err := c.defineClaim(api, &h, &c.Claims[i]); err != nil {
			return err
		}
	}

	for i := range c.EqualityChecks {
		c.defineEquality(api, &c.EqualityChecks[i])
	}

	for i := range c.TransposeChecks {
		c.defineTranspose(api, &c.TransposeChecks[i])
	}

	for i := range c.SumChecks {
		c.defineSum(api, &c.SumChecks[i])
	}

	return nil
}

func (c *MeowGPT2Circuit) defineClaim(api frontend.API, h hash.FieldHasher, claim *MeowGPT2RectClaim) error {
	h.Reset()
	h.Write(c.TensorCm, claim.ID)
	challengeR := h.Sum()
	challengeRPowers := Powers(api, challengeR, claim.Rows)

	tX := logderivlookup.New(api)
	tYZ := logderivlookup.New(api)
	for j := 0; j < claim.NIn; j++ {
		tX.Insert(claim.EncX[j])
	}
	for j := 0; j < claim.NOut; j++ {
		tYZ.Insert(claim.EncYZ[j])
	}

	for i := 0; i < len(claim.IndicesIn); i++ {
		target := c.Scalars[claim.TargetXScalars[i]]
		exprEncX := tX.Lookup(claim.IndicesIn[i])[0]
		api.AssertIsEqual(exprEncX, target)

		aBlock := c.ColumnGroups[claim.AGroup].Blocks[claim.ABlocks[i]]
		foldA := Fold(api, challengeRPowers, aBlock)
		api.AssertIsEqual(foldA, target)
	}

	for i := 0; i < len(claim.IndicesOut); i++ {
		target := c.Scalars[claim.TargetYZScalars[i]]
		exprEncYZ := tYZ.Lookup(claim.IndicesOut[i])[0]
		api.AssertIsEqual(exprEncYZ, target)

		bBlock := c.ColumnGroups[claim.BGroup].Blocks[claim.BBlocks[i]]
		cBlock := c.ColumnGroups[claim.CGroup].Blocks[claim.CBlocks[i]]
		foldB := Fold(api, claim.VecX, bBlock)
		foldC := Fold(api, challengeRPowers, cBlock)

		api.AssertIsEqual(foldB, target)
		api.AssertIsEqual(foldC, target)
	}

	VerifyRSEncoding(api, claim.Inner, claim.NIn, claim.DomainKIn, claim.WeightsKIn, claim.DomainNIn, claim.WeightsNIn, claim.VecX, claim.EncX, claim.RSPointX)
	VerifyRSEncoding(api, claim.Cols, claim.NOut, claim.DomainKOut, claim.WeightsKOut, claim.DomainNOut, claim.WeightsNOut, claim.VecYZ, claim.EncYZ, claim.RSPointYZ)

	if claim.BindPublicInput {
		c.definePublicInputProjection(api, claim, challengeRPowers)
	}
	if claim.BindPublicOutput {
		c.definePublicOutputProjection(api, claim, challengeRPowers)
	}

	return nil
}

func (c *MeowGPT2Circuit) definePublicInputProjection(api frontend.API, claim *MeowGPT2RectClaim, challengeRPowers []frontend.Variable) {
	for col := 0; col < claim.Inner; col++ {
		fold := frontend.Variable(0)
		for row := 0; row < claim.Rows; row++ {
			fold = api.Add(fold, api.Mul(challengeRPowers[row], c.Input[row*claim.Inner+col]))
		}
		api.AssertIsEqual(fold, claim.VecX[col])
	}
}

func (c *MeowGPT2Circuit) definePublicOutputProjection(api frontend.API, claim *MeowGPT2RectClaim, challengeRPowers []frontend.Variable) {
	for col := 0; col < claim.Cols; col++ {
		fold := frontend.Variable(0)
		for row := 0; row < claim.Rows; row++ {
			fold = api.Add(fold, api.Mul(challengeRPowers[row], c.Output[row*claim.Cols+col]))
		}
		api.AssertIsEqual(fold, claim.VecYZ[col])
	}
}

func (c *MeowGPT2Circuit) defineEquality(api frontend.API, check *MeowGPT2EntryEqualityCheck) {
	for i := 0; i < len(check.LeftBlocks); i++ {
		left := c.ColumnGroups[check.LeftGroup].Blocks[check.LeftBlocks[i]]
		right := c.ColumnGroups[check.RightGroup].Blocks[check.RightBlocks[i]]

		leftVal := LookupVector(api, left, check.LeftIndices[i])
		rightVal := LookupVector(api, right, check.RightIndices[i])
		api.AssertIsEqual(leftVal, rightVal)
	}
}

func (c *MeowGPT2Circuit) defineTranspose(api frontend.API, check *MeowGPT2TransposeCheck) {
	for i := 0; i < len(check.LeftBlocks); i++ {
		left := c.ColumnGroups[check.LeftGroup].Blocks[check.LeftBlocks[i]]
		right := c.ColumnGroups[check.RightGroup].Blocks[check.RightBlocks[i]]

		leftVal := LookupVector(api, left, check.RowIndices[i])
		rightVal := LookupVector(api, right, check.ColIndices[i])
		api.AssertIsEqual(leftVal, rightVal)
	}
}

func (c *MeowGPT2Circuit) defineSum(api frontend.API, check *MeowGPT2SumCheck) {
	output := c.ColumnGroups[check.OutputGroup].Blocks[check.OutputBlock]
	for row := 0; row < len(output); row++ {
		sum := frontend.Variable(0)
		for _, blockIndex := range check.TermBlocks {
			term := c.ColumnGroups[check.TermGroup].Blocks[blockIndex]
			sum = api.Add(sum, term[row])
		}
		api.AssertIsEqual(output[row], sum)
	}
}

func LookupVector(api frontend.API, values []frontend.Variable, index frontend.Variable) frontend.Variable {
	table := logderivlookup.New(api)
	for i := range values {
		table.Insert(values[i])
	}
	return table.Lookup(index)[0]
}
