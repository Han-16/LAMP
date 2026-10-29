package protocol

import (
	"strconv"

	"example.com/lamp/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
)

type Verifier struct {
	VK  groth16.VerifyingKey
	CK1 crypto.CommitKey
	CK2 []crypto.CommitKey
}

func NewVerifier(vk groth16.VerifyingKey, ck1 crypto.CommitKey, ck2 []crypto.CommitKey) *Verifier {
	return &Verifier{VK: vk, CK1: ck1, CK2: ck2}
}

func (v *Verifier) VerifyMembership(root fr.Element, commitment bn254.G1Affine, proof []crypto.Digest, idx int, depth int) bool {
	if depth < 0 || depth >= strconv.IntSize-1 {
		return false
	}
	leaf := crypto.MerkleLeafHash(commitment, idx, 1<<depth)
	return crypto.VerifyMerkleProof(root, leaf, proof, idx, depth)
}

func (v *Verifier) VerifyMembershipWithMeta(root fr.Element, commitment bn254.G1Affine, meta crypto.MerkleLeafMeta, proof []crypto.Digest, idx int, depth int) bool {
	leaf := crypto.HashPointWithMeta(commitment, meta)
	return crypto.VerifyMerkleProof(root, leaf, proof, idx, depth)
}

func (v *Verifier) VerifyMultiMembership(root fr.Element, commitments []bn254.G1Affine, indices []int, proof crypto.MerkleMultiProof, depth int) bool {
	if len(commitments) != len(indices) || depth < 0 || depth >= strconv.IntSize-1 {
		return false
	}
	leafHashes := make([]crypto.Digest, len(commitments))
	for i := range commitments {
		leafHashes[i] = crypto.MerkleLeafHash(commitments[i], indices[i], 1<<depth)
	}
	return crypto.VerifyMerkleMultiProof(root, leafHashes, indices, proof, depth)
}

func (v *Verifier) VerifyMultiMembershipWithMeta(root fr.Element, commitments []bn254.G1Affine, metas []crypto.MerkleLeafMeta, indices []int, proof crypto.MerkleMultiProof, depth int) bool {
	if len(commitments) != len(metas) {
		return false
	}
	leafHashes := make([]crypto.Digest, len(commitments))
	for i := range commitments {
		leafHashes[i] = crypto.HashPointWithMeta(commitments[i], metas[i])
	}
	return crypto.VerifyMerkleMultiProof(root, leafHashes, indices, proof, depth)
}

func (v *Verifier) VerifyGroth16(proof groth16.Proof, publicWitness witness.Witness) error {
	return groth16.Verify(proof, v.VK, publicWitness)
}
