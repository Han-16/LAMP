package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
	Gamma      frontend.Variable   `gnark:",public"`
	Indices    []frontend.Variable `gnark:",public"`
	RSPointsX  []frontend.Variable `gnark:",public"`
	RSPointW   frontend.Variable   `gnark:",public"`

	ColsEncABC [][]frontend.Variable // [L][3*Batch*K]
	TargetXYZ  [][]frontend.Variable // [L][Batch+1]

	VecX [][]frontend.Variable // [Batch][K]
	EncX [][]frontend.Variable // [Batch][N]

	VecW []frontend.Variable // [K]
	EncW []frontend.Variable // [N]
}

func (c *LAMPBATCHCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	L := len(c.Indices)
	challengeRPowers := Powers(api, c.ChallengeR, c.K)
	gammaPowers := Powers(api, c.Gamma, c.Batch)

	tX := make([]logderivlookup.Table, c.Batch)
	for b := 0; b < c.Batch; b++ {
		tX[b] = logderivlookup.New(api)
		for j := 0; j < c.N; j++ {
			tX[b].Insert(c.EncX[b][j])
		}
	}

	tW := logderivlookup.New(api)
	for j := 0; j < c.N; j++ {
		tW.Insert(c.EncW[j])
	}

	// Commit the queried ABC blocks and queried X/W symbols in two grouped rounds.
	if _, err := committer.Commit(FlattenRows(c.ColsEncABC)...); err != nil {
		return err
	}
	if _, err := committer.Commit(FlattenRows(c.TargetXYZ)...); err != nil {
		return err
	}

	for q := 0; q < L; q++ {
		block := c.ColsEncABC[q]
		target := c.TargetXYZ[q]

		targetW := target[c.Batch]
		exprW := tW.Lookup(c.Indices[q])[0]
		api.AssertIsEqual(exprW, targetW)

		batchB := frontend.Variable(0)
		batchC := frontend.Variable(0)

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

			api.AssertIsEqual(foldA, targetX)

			coeff := gammaPowers[b]
			batchB = api.Add(batchB, api.Mul(coeff, foldB))
			batchC = api.Add(batchC, api.Mul(coeff, foldC))
		}

		api.AssertIsEqual(batchB, targetW)
		api.AssertIsEqual(batchC, targetW)
	}

	h.Reset()
	h.Write(c.RootABC)
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.RootXYZ)
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	for b := 0; b < c.Batch; b++ {
		VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX[b], c.EncX[b], c.RSPointsX[b])
	}
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecW, c.EncW, c.RSPointW)

	return nil
}
