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
	ChallengeR []frontend.Variable  `gnark:",public"`
	Indices    []frontend.Variable  `gnark:",public"`

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

	tX := logderivlookup.New(api)
	tYZ := logderivlookup.New(api)

	// Insert X, YZ into lookup tables
	for j := 0; j < c.N; j++ {
		tX.Insert(c.EncX[j])
		tYZ.Insert(c.EncYZ[j])
	}

	// 1. Commit A, B, C & X, YZ sequentially
	for i := 0; i < L; i++ {
		committer.Commit(c.ColsEncA[i]...)
		committer.Commit(c.ColsEncB[i]...)
		committer.Commit(c.ColsEncC[i]...)

		exprEncX := tX.Lookup(c.Indices[i])[0]
		exprEncYZ := tYZ.Lookup(c.Indices[i])[0]

		api.AssertIsEqual(exprEncX, c.TargetEncX[i])
		api.AssertIsEqual(exprEncYZ, c.TargetEncYZ[i])

		committer.Commit(c.TargetEncX[i])
		committer.Commit(c.TargetEncYZ[i])

		foldA := Fold(api, c.ChallengeR, c.ColsEncA[i]) // x = r * A
		foldB := Fold(api, c.VecX, c.ColsEncB[i])       // y = x * B
		foldC := Fold(api, c.ChallengeR, c.ColsEncC[i]) // z = r * C

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

	// 3. Verify Reed-Solomon encoding for X, YZ
	var xFlatData, yzFlatData []frontend.Variable
	xFlatData = append(xFlatData, c.VecX...)
	xFlatData = append(xFlatData, c.EncX...)

	yzFlatData = append(yzFlatData, c.VecYZ...)
	yzFlatData = append(yzFlatData, c.EncYZ...)

	z_x, err := committer.Commit(xFlatData...)
	if err != nil {
		return err
	}
	z_yz, err := committer.Commit(yzFlatData...)
	if err != nil {
		return err
	}

	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX, c.EncX, z_x)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecYZ, c.EncYZ, z_yz)

	return nil
}
