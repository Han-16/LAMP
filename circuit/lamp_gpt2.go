package circuit

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

const (
	LAMPGPT2RSSideX = iota
	LAMPGPT2RSSideYZ
)

const lampGPT2RSBatchChallengeTag = 73001

type LAMPGPT2Circuit struct {
	Input  []frontend.Variable `gnark:",public"`
	Output []frontend.Variable `gnark:",public"`

	ColumnGroups []LAMPGPT2ColumnGroup
	Scalars      []frontend.Variable

	GroupRoots [5]frontend.Variable `gnark:",public"` // length S, D, Dh, M, scalar
	TensorCm   frontend.Variable    `gnark:",public"`
	GlobalCm   frontend.Variable    `gnark:",public"`

	Claims          []LAMPGPT2RectClaim
	RSBatches       []LAMPGPT2RSBatch
	EqualityChecks  []LAMPGPT2EntryEqualityCheck
	TransposeChecks []LAMPGPT2TransposeCheck
	SumChecks       []LAMPGPT2SumCheck
}

type LAMPGPT2ColumnGroup struct {
	BlockLen int
	Blocks   [][]frontend.Variable
}

type LAMPGPT2RectClaim struct {
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
	SkipRSX                bool
	SkipRSYZ               bool

	VecX  []frontend.Variable
	VecYZ []frontend.Variable
	EncX  []frontend.Variable
	EncYZ []frontend.Variable
}

type LAMPGPT2RSBatchTerm struct {
	ClaimIndex int
	Side       int
}

type LAMPGPT2RSBatch struct {
	ID   int
	K, N int

	DomainK  []fr.Element
	WeightsK []fr.Element
	DomainN  []fr.Element
	WeightsN []fr.Element

	Terms   []LAMPGPT2RSBatchTerm
	RSPoint frontend.Variable `gnark:",public"`
}

type LAMPGPT2TransposeCheck struct {
	LeftGroup, RightGroup int
	LeftBlocks            []int
	RightBlocks           []int
	RowIndices            []frontend.Variable `gnark:",public"`
	ColIndices            []frontend.Variable `gnark:",public"`
}

type LAMPGPT2EntryEqualityCheck struct {
	LeftGroup, RightGroup int
	LeftBlocks            []int
	RightBlocks           []int
	LeftIndices           []frontend.Variable `gnark:",public"`
	RightIndices          []frontend.Variable `gnark:",public"`
}

type LAMPGPT2SumCheck struct {
	OutputGroup int
	OutputBlock int
	TermGroup   int
	TermBlocks  []int
}

func (c *LAMPGPT2Circuit) Define(api frontend.API) error {
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

	for i := range c.RSBatches {
		if err := c.defineRSBatch(api, &h, &c.RSBatches[i]); err != nil {
			return err
		}
	}

	lookupTables := newLAMPGPT2LookupTables(api, c)
	for i := range c.EqualityChecks {
		c.defineEquality(api, lookupTables, &c.EqualityChecks[i])
	}

	for i := range c.TransposeChecks {
		c.defineTranspose(api, lookupTables, &c.TransposeChecks[i])
	}

	for i := range c.SumChecks {
		c.defineSum(api, &c.SumChecks[i])
	}

	return nil
}

func (c *LAMPGPT2Circuit) defineClaim(api frontend.API, h hash.FieldHasher, claim *LAMPGPT2RectClaim) error {
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

	if claim.SkipRSX {
		api.AssertIsEqual(claim.RSPointX, 0)
	} else {
		VerifyRSEncoding(api, claim.Inner, claim.NIn, claim.DomainKIn, claim.WeightsKIn, claim.DomainNIn, claim.WeightsNIn, claim.VecX, claim.EncX, claim.RSPointX)
	}
	if claim.SkipRSYZ {
		api.AssertIsEqual(claim.RSPointYZ, 0)
	} else {
		VerifyRSEncoding(api, claim.Cols, claim.NOut, claim.DomainKOut, claim.WeightsKOut, claim.DomainNOut, claim.WeightsNOut, claim.VecYZ, claim.EncYZ, claim.RSPointYZ)
	}

	if claim.BindPublicInput {
		c.definePublicInputProjection(api, claim, challengeRPowers)
	}
	if claim.BindPublicOutput {
		c.definePublicOutputProjection(api, claim, challengeRPowers)
	}

	return nil
}

func (c *LAMPGPT2Circuit) definePublicInputProjection(api frontend.API, claim *LAMPGPT2RectClaim, challengeRPowers []frontend.Variable) {
	for col := 0; col < claim.Inner; col++ {
		fold := frontend.Variable(0)
		for row := 0; row < claim.Rows; row++ {
			fold = api.Add(fold, api.Mul(challengeRPowers[row], c.Input[row*claim.Inner+col]))
		}
		api.AssertIsEqual(fold, claim.VecX[col])
	}
}

func (c *LAMPGPT2Circuit) definePublicOutputProjection(api frontend.API, claim *LAMPGPT2RectClaim, challengeRPowers []frontend.Variable) {
	for col := 0; col < claim.Cols; col++ {
		fold := frontend.Variable(0)
		for row := 0; row < claim.Rows; row++ {
			fold = api.Add(fold, api.Mul(challengeRPowers[row], c.Output[row*claim.Cols+col]))
		}
		api.AssertIsEqual(fold, claim.VecYZ[col])
	}
}

func (c *LAMPGPT2Circuit) defineRSBatch(api frontend.API, h hash.FieldHasher, batch *LAMPGPT2RSBatch) error {
	if len(batch.Terms) == 0 {
		return fmt.Errorf("empty LAMP GPT-2 RS batch %d", batch.ID)
	}

	h.Reset()
	h.Write(c.GlobalCm, lampGPT2RSBatchChallengeTag, batch.ID)
	beta := h.Sum()
	betaPowers := Powers(api, beta, len(batch.Terms))

	combinedVec := make([]frontend.Variable, batch.K)
	combinedEnc := make([]frontend.Variable, batch.N)
	for i := range combinedVec {
		combinedVec[i] = frontend.Variable(0)
	}
	for i := range combinedEnc {
		combinedEnc[i] = frontend.Variable(0)
	}

	for i, term := range batch.Terms {
		vec, enc, err := c.rsBatchTermValues(term, batch.K, batch.N)
		if err != nil {
			return fmt.Errorf("invalid term %d in LAMP GPT-2 RS batch %d: %w", i, batch.ID, err)
		}

		coeff := betaPowers[i]
		for j := 0; j < batch.K; j++ {
			combinedVec[j] = api.Add(combinedVec[j], api.Mul(coeff, vec[j]))
		}
		for j := 0; j < batch.N; j++ {
			combinedEnc[j] = api.Add(combinedEnc[j], api.Mul(coeff, enc[j]))
		}
	}

	VerifyRSEncoding(api, batch.K, batch.N, batch.DomainK, batch.WeightsK, batch.DomainN, batch.WeightsN, combinedVec, combinedEnc, batch.RSPoint)
	return nil
}

func (c *LAMPGPT2Circuit) rsBatchTermValues(term LAMPGPT2RSBatchTerm, k, n int) ([]frontend.Variable, []frontend.Variable, error) {
	if term.ClaimIndex < 0 || term.ClaimIndex >= len(c.Claims) {
		return nil, nil, fmt.Errorf("claim index %d out of range", term.ClaimIndex)
	}

	claim := c.Claims[term.ClaimIndex]
	switch term.Side {
	case LAMPGPT2RSSideX:
		if claim.Inner != k || claim.NIn != n {
			return nil, nil, fmt.Errorf("X side domain mismatch for claim %d: got k=%d n=%d expected k=%d n=%d", term.ClaimIndex, claim.Inner, claim.NIn, k, n)
		}
		return claim.VecX, claim.EncX, nil
	case LAMPGPT2RSSideYZ:
		if claim.Cols != k || claim.NOut != n {
			return nil, nil, fmt.Errorf("YZ side domain mismatch for claim %d: got k=%d n=%d expected k=%d n=%d", term.ClaimIndex, claim.Cols, claim.NOut, k, n)
		}
		return claim.VecYZ, claim.EncYZ, nil
	default:
		return nil, nil, fmt.Errorf("unknown RS side %d", term.Side)
	}
}

func (c *LAMPGPT2Circuit) defineEquality(api frontend.API, lookups *lampGPT2LookupTables, check *LAMPGPT2EntryEqualityCheck) {
	for i := 0; i < len(check.LeftBlocks); i++ {
		leftVal := lookups.Lookup(check.LeftGroup, check.LeftBlocks[i], check.LeftIndices[i])
		rightVal := lookups.Lookup(check.RightGroup, check.RightBlocks[i], check.RightIndices[i])
		api.AssertIsEqual(leftVal, rightVal)
	}
}

func (c *LAMPGPT2Circuit) defineTranspose(api frontend.API, lookups *lampGPT2LookupTables, check *LAMPGPT2TransposeCheck) {
	for i := 0; i < len(check.LeftBlocks); i++ {
		leftVal := lookups.Lookup(check.LeftGroup, check.LeftBlocks[i], check.RowIndices[i])
		rightVal := lookups.Lookup(check.RightGroup, check.RightBlocks[i], check.ColIndices[i])
		api.AssertIsEqual(leftVal, rightVal)
	}
}

func (c *LAMPGPT2Circuit) defineSum(api frontend.API, check *LAMPGPT2SumCheck) {
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

type lampGPT2LookupKey struct {
	group int
	block int
}

type lampGPT2LookupTables struct {
	api    frontend.API
	c      *LAMPGPT2Circuit
	tables map[lampGPT2LookupKey]logderivlookup.Table
}

func newLAMPGPT2LookupTables(api frontend.API, c *LAMPGPT2Circuit) *lampGPT2LookupTables {
	return &lampGPT2LookupTables{
		api:    api,
		c:      c,
		tables: make(map[lampGPT2LookupKey]logderivlookup.Table),
	}
}

func (l *lampGPT2LookupTables) Lookup(group, block int, index frontend.Variable) frontend.Variable {
	key := lampGPT2LookupKey{group: group, block: block}
	table, ok := l.tables[key]
	if !ok {
		table = logderivlookup.New(l.api)
		values := l.c.ColumnGroups[group].Blocks[block]
		for i := range values {
			table.Insert(values[i])
		}
		l.tables[key] = table
	}
	return table.Lookup(index)[0]
}
