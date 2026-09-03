package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

type LAMPBATCHCircuit struct {
	K, N, Batch int

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
	Gamma      frontend.Variable   `gnark:",public"`
	Indices    []frontend.Variable `gnark:",public"`

	// For q = Indices[i], ColsEncABC[i] contains each batch item's
	// [colsEncA[q] || colsEncB[q] || colsEncC[q]] block.
	ColsEncABC [][]frontend.Variable // [L][3*Batch*K]

	// For q = Indices[i], QueriedEncValues[i] is
	// [EncX[0][q], ..., EncX[Batch-1][q], EncW[q], EncBTest[q]].
	QueriedEncValues [][]frontend.Variable // [L][Batch+2]

	VecX [][]frontend.Variable // [Batch][K]
	EncX [][]frontend.Variable // [Batch][N]

	VecW     []frontend.Variable // [K]
	EncW     []frontend.Variable // [N]
	VecBTest []frontend.Variable // [K]
	EncBTest []frontend.Variable // [N]
}

func (c *LAMPBATCHCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	L := len(c.Indices)
	challengeRPowers := Powers(api, c.ChallengeR, c.K)
	challengeBPowers := Powers(api, c.ChallengeB, c.K)
	gammaPowers := Powers(api, c.Gamma, c.Batch)

	tX := make([]logderivlookup.Table, c.Batch)
	for b := 0; b < c.Batch; b++ {
		tX[b] = logderivlookup.New(api)
		for j := 0; j < c.N; j++ {
			tX[b].Insert(c.EncX[b][j])
		}
	}

	tW := logderivlookup.New(api)
	tBTest := logderivlookup.New(api)
	for j := 0; j < c.N; j++ {
		tW.Insert(c.EncW[j])
		tBTest.Insert(c.EncBTest[j])
	}

	// Commit the queried ABC blocks and queried X/W/B-test symbols in two grouped rounds.
	if _, err := committer.Commit(FlattenRows(c.ColsEncABC)...); err != nil {
		return err
	}
	if _, err := committer.Commit(FlattenRows(c.QueriedEncValues)...); err != nil {
		return err
	}
	// Bind every batched RS message and codeword before using one shared evaluation point.
	rsPoint, err := committer.Commit(AppendVariables(
		FlattenRows(c.VecX),
		c.VecW,
		c.VecBTest,
		FlattenRows(c.EncX),
		c.EncW,
		c.EncBTest,
	)...)
	if err != nil {
		return err
	}

	for q := 0; q < L; q++ {
		block := c.ColsEncABC[q]
		target := c.QueriedEncValues[q]

		targetW := target[c.Batch]
		targetBTest := target[c.Batch+1]
		exprW := tW.Lookup(c.Indices[q])[0]
		exprBTest := tBTest.Lookup(c.Indices[q])[0]
		api.AssertIsEqual(exprW, targetW)
		api.AssertIsEqual(exprBTest, targetBTest)

		batchB := frontend.Variable(0)
		batchC := frontend.Variable(0)
		batchBTest := frontend.Variable(0)

		for b := 0; b < c.Batch; b++ {
			targetX := target[b]
			exprX := tX[b].Lookup(c.Indices[q])[0]
			api.AssertIsEqual(exprX, targetX)

			offset := b * 3 * c.K
			colsEncA := block[offset : offset+c.K]
			colsEncB := block[offset+c.K : offset+2*c.K]
			colsEncC := block[offset+2*c.K : offset+3*c.K]

			foldA := Fold(api, challengeRPowers, colsEncA)
			foldB := Fold(api, c.VecX[b], colsEncB)
			foldC := Fold(api, challengeRPowers, colsEncC)
			foldBTest := Fold(api, challengeBPowers, colsEncB)

			api.AssertIsEqual(foldA, targetX)

			coeff := gammaPowers[b]
			batchB = api.Add(batchB, api.Mul(coeff, foldB))
			batchC = api.Add(batchC, api.Mul(coeff, foldC))
			batchBTest = api.Add(batchBTest, api.Mul(coeff, foldBTest))
		}

		api.AssertIsEqual(batchB, targetW)
		api.AssertIsEqual(batchC, targetW)
		api.AssertIsEqual(batchBTest, targetBTest)
	}

	h.Reset()
	h.Write(c.RootABC)
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.RootXYZ)
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	for b := 0; b < c.Batch; b++ {
		VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX[b], c.EncX[b], rsPoint)
	}
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecW, c.EncW, rsPoint)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecBTest, c.EncBTest, rsPoint)

	return nil
}
