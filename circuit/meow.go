package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

type MeowCircuit struct {
	K, N, Depth int

	DomainK  []fr.Element
	WeightsK []fr.Element

	DomainN  []fr.Element
	WeightsN []fr.Element

	Roots      [5]frontend.Variable `gnark:",public"` // [0:3] for A, B, C & [3:5] for X, YZ
	CmABC      frontend.Variable    `gnark:",public"`
	CmXYZ      frontend.Variable    `gnark:",public"`
	ChallengeR frontend.Variable    `gnark:",public"`
	Indices    []frontend.Variable  `gnark:",public"`
	RSPointX   frontend.Variable    `gnark:",public"`
	RSPointYZ  frontend.Variable    `gnark:",public"`

	ColsEncA [][]frontend.Variable // [L][K]
	ColsEncB [][]frontend.Variable // [L][K]
	ColsEncC [][]frontend.Variable // [L][K]
	VecX     []frontend.Variable   // [K]
	VecYZ    []frontend.Variable   // [K]
	EncX     []frontend.Variable   // [N]
	EncYZ    []frontend.Variable   // [N]

	TargetEncX  []frontend.Variable // [L]
	TargetEncYZ []frontend.Variable // [L]
}

func (c *MeowCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	L := len(c.Indices)
	challengeRPowers := Powers(api, c.ChallengeR, c.K)

	tX := logderivlookup.New(api)
	tYZ := logderivlookup.New(api)

	// Insert X, YZ into lookup tables
	for j := 0; j < c.N; j++ {
		tX.Insert(c.EncX[j])
		tYZ.Insert(c.EncYZ[j])
	}

	// 1. Commit queried A/B/C columns and queried X/YZ scalar values as two grouped rounds.
	if _, err := committer.Commit(FlattenRows(c.ColsEncA, c.ColsEncB, c.ColsEncC)...); err != nil {
		return err
	}
	if _, err := committer.Commit(AppendVariables(c.TargetEncX, c.TargetEncYZ)...); err != nil {
		return err
	}

	for i := 0; i < L; i++ {
		exprEncX := tX.Lookup(c.Indices[i])[0]
		exprEncYZ := tYZ.Lookup(c.Indices[i])[0]

		api.AssertIsEqual(exprEncX, c.TargetEncX[i])
		api.AssertIsEqual(exprEncYZ, c.TargetEncYZ[i])

		foldA := Fold(api, challengeRPowers, c.ColsEncA[i]) // x = r * A
		foldB := Fold(api, c.VecX, c.ColsEncB[i])           // y = x * B
		foldC := Fold(api, challengeRPowers, c.ColsEncC[i]) // z = r * C

		api.AssertIsEqual(foldA, c.TargetEncX[i])
		api.AssertIsEqual(foldB, c.TargetEncYZ[i])
		api.AssertIsEqual(foldC, c.TargetEncYZ[i])
	}

	// 2. Verify Hashes
	h.Reset()
	h.Write(c.Roots[0], c.Roots[1], c.Roots[2])
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.Roots[3], c.Roots[4])
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	// 3. Verify Reed-Solomon encoding for X, YZ at transcript-derived out-of-domain points.
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX, c.EncX, c.RSPointX)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecYZ, c.EncYZ, c.RSPointYZ)

	return nil
}
