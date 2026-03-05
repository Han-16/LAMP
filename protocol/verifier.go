package protocol

import (
	"github.com/Han-16/meow/crypto" // 통합된 crypto 패키지 사용
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
	return &Verifier{
		VK:  vk,
		CK1: ck1,
		CK2: ck2,
	}
}

// 1. 머클 트리 멤버십 검증
func (v *Verifier) VerifyMembership(root fr.Element, commitment bn254.G1Affine, proof []fr.Element, idx int, depth int) bool {
	currHash := crypto.HashPoint(commitment)
	currIdx := idx

	for level := 0; level < depth; level++ {
		sibling := proof[level]
		if currIdx%2 == 0 {
			currHash = crypto.HashElements(currHash, sibling)
		} else {
			currHash = crypto.HashElements(sibling, currHash)
		}
		currIdx /= 2
	}

	return currHash.Equal(&root)
}

// 2. Groth16 서킷 증명 검증
func (v *Verifier) VerifyGroth16(proof groth16.Proof, publicWitness witness.Witness) error {
	return groth16.Verify(proof, v.VK, publicWitness)
}

// 3. CP-LINK Batch 검증
func (v *Verifier) VerifyCPLinks(cmVec1 []bn254.G1Affine, cmVec2 []bn254.G1Affine, proofs []crypto.CPLinkProof) bool {
	for i := 0; i < len(proofs); i++ {
		isValid := crypto.VerifyCPLink(cmVec1[i], cmVec2[i], proofs[i], v.CK1, v.CK2[i])
		if !isValid {
			return false
		}
	}
	return true
}
