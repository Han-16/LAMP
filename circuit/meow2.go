package circuit

import (
	"github.com/Han-16/meow/rs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Meow2Circuit struct {
	K, N, Depth int
	Roots       [6]frontend.Variable  `gnark:",public"`
	CmABC       frontend.Variable     `gnark:",public"`
	CmXYZ       frontend.Variable     `gnark:",public"`
	ChallengeR  []frontend.Variable   `gnark:",public"`
	Indices     []frontend.Variable   `gnark:",public"`
	ColsEncA    [][]frontend.Variable // [L][K]
	ColsEncB    [][]frontend.Variable // [L][K]
	ColsEncC    [][]frontend.Variable // [L][K]
	VecX        []frontend.Variable   // [K]
	VecY        []frontend.Variable   // [K]
	VecZ        []frontend.Variable   // [K]
	EncX        []frontend.Variable   // [N]
	EncY        []frontend.Variable   // [N]
	EncZ        []frontend.Variable   // [N]
	RandomA     []frontend.Variable   // [L]
	RandomB     []frontend.Variable   // [L]
	RandomC     []frontend.Variable   // [L]
}

func (c *Meow2Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	encoder := rs.NewEncoder(c.K, c.N)
	L := len(c.Indices)
	committer := api.(frontend.Committer)

	// 1. Commit ColsEncA, ColsEncB, ColsEncC
	var cmColsEncA, cmColsEncB, cmColsEncC []frontend.Variable
	for i := 0; i < L; i++ {
		var committedValuesA, committedValuesB, committedValuesC []frontend.Variable
		committedValuesA = append(committedValuesA, c.ColsEncA[i]...)
		committedValuesA = append(committedValuesA, c.RandomA[i])
		committedValuesB = append(committedValuesB, c.ColsEncB[i]...)
		committedValuesB = append(committedValuesB, c.RandomB[i])
		committedValuesC = append(committedValuesC, c.ColsEncC[i]...)
		committedValuesC = append(committedValuesC, c.RandomC[i])
		cmA, err := committer.Commit(committedValuesA...)
		if err != nil {
			return err
		}
		cmB, err := committer.Commit(committedValuesB...)
		if err != nil {
			return err
		}
		cmC, err := committer.Commit(committedValuesC...)
		if err != nil {
			return err
		}
		cmColsEncA = append(cmColsEncA, cmA)
		cmColsEncB = append(cmColsEncB, cmB)
		cmColsEncC = append(cmColsEncC, cmC)
	}
	// 2. Verify commitments
	// cm_ABC == Hash(cm_A, cm_B, cm_C)
	h.Reset()
	h.Write(c.Roots[0], c.Roots[1], c.Roots[2])
	api.AssertIsEqual(c.CmABC, h.Sum())

	// cm_XYZ == Hash(cm_x, cm_y, cm_z)
	h.Reset()
	h.Write(c.Roots[3], c.Roots[4], c.Roots[5])
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	// 3. Check encodings
	CheckEncode(api, encoder, c.VecX, c.EncX)
	CheckEncode(api, encoder, c.VecY, c.EncY)
	CheckEncode(api, encoder, c.VecZ, c.EncZ)

	// 4. Verify Folding & Proximity
	for i := 0; i < L; i++ {
		idx := c.Indices[i]

		foldA := Fold(api, c.ChallengeR, c.ColsEncA[i])
		foldB := Fold(api, c.VecX, c.ColsEncB[i])
		foldC := Fold(api, c.ChallengeR, c.ColsEncC[i])

		idxBits := api.ToBinary(idx, c.Depth)
		targetEncX := SelectTargetIndex(api, c.EncX, idxBits)
		targetEncY := SelectTargetIndex(api, c.EncY, idxBits)
		targetEncZ := SelectTargetIndex(api, c.EncZ, idxBits)

		api.AssertIsEqual(foldA, targetEncX)
		api.AssertIsEqual(foldB, targetEncY)
		api.AssertIsEqual(foldC, targetEncZ)
	}

	return nil
}
