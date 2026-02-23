package circuit

import (
	"github.com/Han-16/meow/rs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type MeowCircuit struct {
	// Configurations
	K, N int

	// Public Inputs
	Roots      [6]frontend.Variable `gnark:",public"` // cm_A, cm_B, cm_C, cm_x, cm_y, cm_z
	CmABC      frontend.Variable    `gnark:",public"` // Commitment of cm_A, cm_B, cm_C
	CmXYZ      frontend.Variable    `gnark:",public"` // Commitment of cm_x, cm_y, cm_z
	ChallengeR []frontend.Variable  `gnark:",public"` // Random vector r (Length K) (It is drived from cm_A, cm_B, cm_C)
	Indices    []frontend.Variable  `gnark:",public"` // The index set I (It is drived from cm_x, cm_y, cm_z)

	// Private Inputs
	ColsEncA [][]frontend.Variable
	ColsEncB [][]frontend.Variable
	ColsEncC [][]frontend.Variable

	VecX []frontend.Variable
	VecY []frontend.Variable
	VecZ []frontend.Variable

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

	// 1. Verify commitments to A, B, C and x, y, z
	h.Reset()
	h.Write(c.Roots[0])
	h.Write(c.Roots[1])
	h.Write(c.Roots[2])
	expectedCmABC := h.Sum()
	api.AssertIsEqual(c.CmABC, expectedCmABC)

	h.Reset()
	h.Write(c.Roots[3])
	h.Write(c.Roots[4])
	h.Write(c.Roots[5])
	expectedCmXYZ := h.Sum()
	api.AssertIsEqual(c.CmXYZ, expectedCmXYZ)

	// 2. Encode vectors
	EncX, err := encoder.EncodeInCircuit(c.VecX)
	if err != nil {
		return err
	}
	EncY, err := encoder.EncodeInCircuit(c.VecY)
	if err != nil {
		return err
	}
	EncZ, err := encoder.EncodeInCircuit(c.VecZ)
	if err != nil {
		return err
	}

	// 3. Verify Folding, i.e., A * r = x, B * r = y, C * r = z
	for i := 0; i < L; i++ {
		idx := c.Indices[i]

		// 3.1 Folding
		var foldA, foldB, foldC frontend.Variable
		foldA = Fold(api, c.ChallengeR, c.ColsEncA[i])
		foldB = Fold(api, c.VecX, c.ColsEncB[i])
		foldC = Fold(api, c.ChallengeR, c.ColsEncC[i])

		// 3.2 check proximity
		// foldA[idx] == EncX[idx]
		// foldB[idx] == EncY[idx]
		// foldC[idx] == EncZ[idx]
		idxBits := api.ToBinary(idx, depth)

		targetEncX := DynamicSelect(api, EncX, idxBits)
		targetEncY := DynamicSelect(api, EncY, idxBits)
		targetEncZ := DynamicSelect(api, EncZ, idxBits)

		api.AssertIsEqual(foldA, targetEncX)
		api.AssertIsEqual(foldB, targetEncY)
		api.AssertIsEqual(foldC, targetEncZ)

		// 4. Verify Merkle Proofs for A, B, C
		VerifyColumnMerkleProof(api, h, c.Roots[0], c.ColsEncA[i], idx, c.MerkleProofsA[i])
		VerifyColumnMerkleProof(api, h, c.Roots[1], c.ColsEncB[i], idx, c.MerkleProofsB[i])
		VerifyColumnMerkleProof(api, h, c.Roots[2], c.ColsEncC[i], idx, c.MerkleProofsC[i])

		// 5. Verify Merkle Proofs for x, y, z
		VerifyColumnMerkleProof(api, h, c.Roots[3], []frontend.Variable{targetEncX}, idx, c.MerkleProofsX[i])
		VerifyColumnMerkleProof(api, h, c.Roots[4], []frontend.Variable{targetEncY}, idx, c.MerkleProofsY[i])
		VerifyColumnMerkleProof(api, h, c.Roots[5], []frontend.Variable{targetEncZ}, idx, c.MerkleProofsZ[i])
	}

	return nil
}
