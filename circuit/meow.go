package circuit

import (
	"github.com/Han-16/meow/rs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MeowCircuit struct {
	K, N          int
	Roots         [6]frontend.Variable `gnark:",public"`
	CmABC         frontend.Variable    `gnark:",public"`
	CmXYZ         frontend.Variable    `gnark:",public"`
	ChallengeR    []frontend.Variable  `gnark:",public"`
	Indices       []frontend.Variable  `gnark:",public"`
	ColsEncA      [][]frontend.Variable
	ColsEncB      [][]frontend.Variable
	ColsEncC      [][]frontend.Variable
	VecX          []frontend.Variable
	VecY          []frontend.Variable
	VecZ          []frontend.Variable
	MerkleProofsA [][]frontend.Variable
	MerkleProofsB [][]frontend.Variable
	MerkleProofsC [][]frontend.Variable
	MerkleProofsX [][]frontend.Variable
	MerkleProofsY [][]frontend.Variable
	MerkleProofsZ [][]frontend.Variable
}

func (c *MeowCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	encoder := rs.NewEncoder(c.K, c.N)
	L := len(c.Indices)
	depth := len(c.MerkleProofsA[0])

	// 1. Verify commitments
	h.Reset()
	h.Write(c.Roots[0], c.Roots[1], c.Roots[2])
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.Roots[3], c.Roots[4], c.Roots[5])
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	// 2. Encode vectors
	EncX, _ := encoder.EncodeInCircuit(c.VecX)
	EncY, _ := encoder.EncodeInCircuit(c.VecY)
	EncZ, _ := encoder.EncodeInCircuit(c.VecZ)

	// 3. Verify Folding & Proximity
	for i := 0; i < L; i++ {
		idx := c.Indices[i]

		foldA := Fold(api, c.ChallengeR, c.ColsEncA[i])
		foldB := Fold(api, c.VecX, c.ColsEncB[i])
		foldC := Fold(api, c.ChallengeR, c.ColsEncC[i])

		idxBits := api.ToBinary(idx, depth)
		targetEncX := SelectTargetIndex(api, EncX, idxBits)
		targetEncY := SelectTargetIndex(api, EncY, idxBits)
		targetEncZ := SelectTargetIndex(api, EncZ, idxBits)

		api.AssertIsEqual(foldA, targetEncX)
		api.AssertIsEqual(foldB, targetEncY)
		api.AssertIsEqual(foldC, targetEncZ)

		// // 4. Verify Merkle Proofs for A, B, C
		if err := VerifyColumnMerkleProof(api, h, c.ColsEncA[i], c.Roots[0], c.MerkleProofsA[i], idx); err != nil {
			return err
		}
		if err := VerifyColumnMerkleProof(api, h, c.ColsEncB[i], c.Roots[1], c.MerkleProofsB[i], idx); err != nil {
			return err
		}
		if err := VerifyColumnMerkleProof(api, h, c.ColsEncC[i], c.Roots[2], c.MerkleProofsC[i], idx); err != nil {
			return err
		}

		// 5. Verify Merkle Proofs for x, y, z
		if err := VerifyColumnMerkleProof(api, h, []frontend.Variable{targetEncX}, c.Roots[3], c.MerkleProofsX[i], idx); err != nil {
			return err
		}
		if err := VerifyColumnMerkleProof(api, h, []frontend.Variable{targetEncY}, c.Roots[4], c.MerkleProofsY[i], idx); err != nil {
			return err
		}
		if err := VerifyColumnMerkleProof(api, h, []frontend.Variable{targetEncZ}, c.Roots[5], c.MerkleProofsZ[i], idx); err != nil {
			return err
		}
	}
	return nil
}
