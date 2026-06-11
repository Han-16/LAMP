package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

type LAMPCircuit struct {
	K, N, Depth int

	DomainK  []fr.Element
	WeightsK []fr.Element

	DomainN  []fr.Element
	WeightsN []fr.Element

	RootABC    frontend.Variable   `gnark:",public"`
	RootXYZ    frontend.Variable   `gnark:",public"`
	CmABC      frontend.Variable   `gnark:",public"`
	CmXYZ      frontend.Variable   `gnark:",public"`
	ChallengeR frontend.Variable   `gnark:",public"`
	Indices    []frontend.Variable `gnark:",public"`
	RSPointX   frontend.Variable   `gnark:",public"`
	RSPointYZ  frontend.Variable   `gnark:",public"`

	ColsEncABC [][]frontend.Variable // [L][3K]
	VecX       []frontend.Variable   // [K]
	VecYZ      []frontend.Variable   // [K]
	EncX       []frontend.Variable   // [N]
	EncYZ      []frontend.Variable   // [N]
	TargetXYZ  [][]frontend.Variable // [L][2]
}

func (c *LAMPCircuit) Define(api frontend.API) error {
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
	if _, err := committer.Commit(FlattenRows(c.ColsEncABC)...); err != nil {
		return err
	}
	if _, err := committer.Commit(FlattenRows(c.TargetXYZ)...); err != nil {
		return err
	}

	for i := 0; i < L; i++ {
		colsEncA := c.ColsEncABC[i][:c.K]
		colsEncB := c.ColsEncABC[i][c.K : 2*c.K]
		colsEncC := c.ColsEncABC[i][2*c.K : 3*c.K]
		targetEncX := c.TargetXYZ[i][0]
		targetEncYZ := c.TargetXYZ[i][1]

		exprEncX := tX.Lookup(c.Indices[i])[0]
		exprEncYZ := tYZ.Lookup(c.Indices[i])[0]

		api.AssertIsEqual(exprEncX, targetEncX)
		api.AssertIsEqual(exprEncYZ, targetEncYZ)

		foldA := Fold(api, challengeRPowers, colsEncA) // x = r * A
		foldB := Fold(api, c.VecX, colsEncB)           // y = x * B
		foldC := Fold(api, challengeRPowers, colsEncC) // z = r * C

		api.AssertIsEqual(foldA, targetEncX)
		api.AssertIsEqual(foldB, targetEncYZ)
		api.AssertIsEqual(foldC, targetEncYZ)
	}

	// 2. Verify Hashes
	h.Reset()
	h.Write(c.RootABC)
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.RootXYZ)
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	// 3. Verify Reed-Solomon encoding for X, YZ at transcript-derived out-of-domain points.
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX, c.EncX, c.RSPointX)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecYZ, c.EncYZ, c.RSPointYZ)

	return nil
}
