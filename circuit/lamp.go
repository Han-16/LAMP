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
	ChallengeB frontend.Variable   `gnark:",public"`
	Indices    []frontend.Variable `gnark:",public"`

	// For q = Indices[i], ColsEncABC[i] is
	// [colsEncA[q] || colsEncB[q] || colsEncC[q]].
	ColsEncABC [][]frontend.Variable // [L][3K]

	VecX     []frontend.Variable // [K]: (1, r, ..., r^(K-1)) * A
	VecYZ    []frontend.Variable // [K]: VecX * B
	VecBTest []frontend.Variable // [K]: (1, b, ..., b^(K-1)) * B

	EncX     []frontend.Variable // [N]: RS encoding of VecX
	EncYZ    []frontend.Variable // [N]: RS encoding of VecYZ
	EncBTest []frontend.Variable // [N]: RS encoding of VecBTest

	// For q = Indices[i], QueriedEncValues[i] is
	// [EncX[q], EncYZ[q], EncBTest[q]].
	QueriedEncValues [][]frontend.Variable // [L][3]
}

func (c *LAMPCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	L := len(c.Indices)
	challengeRPowers := Powers(api, c.ChallengeR, c.K)
	challengeBPowers := Powers(api, c.ChallengeB, c.K)

	tX := logderivlookup.New(api)
	tYZ := logderivlookup.New(api)
	tB := logderivlookup.New(api)

	// Insert X, YZ, and the independent B fold into lookup tables.
	for j := 0; j < c.N; j++ {
		tX.Insert(c.EncX[j])
		tYZ.Insert(c.EncYZ[j])
		tB.Insert(c.EncBTest[j])
	}

	// 1. Commit queried A/B/C columns and queried X/YZ/B-test scalar values as two grouped rounds.
	if _, err := committer.Commit(FlattenRows(c.ColsEncABC)...); err != nil {
		return err
	}
	if _, err := committer.Commit(FlattenRows(c.QueriedEncValues)...); err != nil {
		return err
	}
	// Bind all three RS messages and codewords before using one shared evaluation point.
	rsPoint, err := committer.Commit(AppendVariables(
		c.VecX,
		c.VecYZ,
		c.VecBTest,
		c.EncX,
		c.EncYZ,
		c.EncBTest,
	)...)
	if err != nil {
		return err
	}

	for i := 0; i < L; i++ {
		colsEncA := c.ColsEncABC[i][:c.K]
		colsEncB := c.ColsEncABC[i][c.K : 2*c.K]
		colsEncC := c.ColsEncABC[i][2*c.K : 3*c.K]
		targetEncX := c.QueriedEncValues[i][0]
		targetEncYZ := c.QueriedEncValues[i][1]
		targetEncB := c.QueriedEncValues[i][2]

		exprEncX := tX.Lookup(c.Indices[i])[0]
		exprEncYZ := tYZ.Lookup(c.Indices[i])[0]
		exprEncB := tB.Lookup(c.Indices[i])[0]

		api.AssertIsEqual(exprEncX, targetEncX)
		api.AssertIsEqual(exprEncYZ, targetEncYZ)
		api.AssertIsEqual(exprEncB, targetEncB)

		foldA := Fold(api, challengeRPowers, colsEncA) // x = r * A
		foldB := Fold(api, c.VecX, colsEncB)           // y = x * B
		foldC := Fold(api, challengeRPowers, colsEncC) // z = r * C
		foldBTest := Fold(api, challengeBPowers, colsEncB)

		api.AssertIsEqual(foldA, targetEncX)
		api.AssertIsEqual(foldB, targetEncYZ)
		api.AssertIsEqual(foldC, targetEncYZ)
		api.AssertIsEqual(foldBTest, targetEncB)
	}

	// 2. Verify Hashes
	h.Reset()
	h.Write(c.RootABC)
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.RootXYZ)
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	// 3. Verify Reed-Solomon encoding for X, YZ, and the independent B fold.
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX, c.EncX, rsPoint)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecYZ, c.EncYZ, rsPoint)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecBTest, c.EncBTest, rsPoint)

	return nil
}
