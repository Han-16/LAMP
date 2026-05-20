package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

type RectMeowCircuit struct {
	M, KIn, KOut      int
	NIn, NOut         int
	DepthIn, DepthOut int

	DomainKIn  []fr.Element
	WeightsKIn []fr.Element
	DomainNIn  []fr.Element
	WeightsNIn []fr.Element

	DomainKOut  []fr.Element
	WeightsKOut []fr.Element
	DomainNOut  []fr.Element
	WeightsNOut []fr.Element

	Roots      [5]frontend.Variable `gnark:",public"` // [A, B, C, X, YZ]
	CmABC      frontend.Variable    `gnark:",public"`
	CmXYZ      frontend.Variable    `gnark:",public"`
	ChallengeR frontend.Variable    `gnark:",public"`
	IndicesIn  []frontend.Variable  `gnark:",public"`
	IndicesOut []frontend.Variable  `gnark:",public"`
	RSPointX   frontend.Variable    `gnark:",public"`
	RSPointYZ  frontend.Variable    `gnark:",public"`

	ColsEncA [][]frontend.Variable // [L][M]
	ColsEncB [][]frontend.Variable // [L][KIn]
	ColsEncC [][]frontend.Variable // [L][M]

	VecX  []frontend.Variable // [KIn]
	VecYZ []frontend.Variable // [KOut]
	EncX  []frontend.Variable // [NIn]
	EncYZ []frontend.Variable // [NOut]

	TargetEncX  []frontend.Variable // [L]
	TargetEncYZ []frontend.Variable // [L]
}

func (c *RectMeowCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	challengeRPowers := Powers(api, c.ChallengeR, c.M)

	tX := logderivlookup.New(api)
	tYZ := logderivlookup.New(api)
	for j := 0; j < c.NIn; j++ {
		tX.Insert(c.EncX[j])
	}
	for j := 0; j < c.NOut; j++ {
		tYZ.Insert(c.EncYZ[j])
	}

	if _, err := committer.Commit(FlattenRows(c.ColsEncA)...); err != nil {
		return err
	}
	if _, err := committer.Commit(FlattenRows(c.ColsEncB)...); err != nil {
		return err
	}
	if _, err := committer.Commit(FlattenRows(c.ColsEncC)...); err != nil {
		return err
	}
	if _, err := committer.Commit(AppendVariables(c.TargetEncX, c.TargetEncYZ)...); err != nil {
		return err
	}

	for i := 0; i < len(c.IndicesIn); i++ {
		exprEncX := tX.Lookup(c.IndicesIn[i])[0]
		api.AssertIsEqual(exprEncX, c.TargetEncX[i])

		foldA := Fold(api, challengeRPowers, c.ColsEncA[i])
		api.AssertIsEqual(foldA, c.TargetEncX[i])
	}

	for i := 0; i < len(c.IndicesOut); i++ {
		exprEncYZ := tYZ.Lookup(c.IndicesOut[i])[0]
		api.AssertIsEqual(exprEncYZ, c.TargetEncYZ[i])

		foldB := Fold(api, c.VecX, c.ColsEncB[i])
		foldC := Fold(api, challengeRPowers, c.ColsEncC[i])

		api.AssertIsEqual(foldB, c.TargetEncYZ[i])
		api.AssertIsEqual(foldC, c.TargetEncYZ[i])
	}

	h.Reset()
	h.Write(c.Roots[0], c.Roots[1], c.Roots[2])
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.Roots[3], c.Roots[4])
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	VerifyRSEncoding(api, c.KIn, c.NIn, c.DomainKIn, c.WeightsKIn, c.DomainNIn, c.WeightsNIn, c.VecX, c.EncX, c.RSPointX)
	VerifyRSEncoding(api, c.KOut, c.NOut, c.DomainKOut, c.WeightsKOut, c.DomainNOut, c.WeightsNOut, c.VecYZ, c.EncYZ, c.RSPointYZ)

	return nil
}
