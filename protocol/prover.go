package protocol

import (
	"reflect"

	"github.com/Han-16/meow/crypto"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

type Prover struct {
	PK      groth16.ProvingKey
	CK1     crypto.CommitKey
	CK2     []crypto.CommitKey
	Encoder *crypto.Encoder
}

func NewProver(pk groth16.ProvingKey, ck1 crypto.CommitKey, encoder *crypto.Encoder) *Prover {
	var ck2 []crypto.CommitKey

	if pk != nil {
		val := reflect.ValueOf(pk)
		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}
		ckField := val.FieldByName("CommitmentKeys")
		if ckField.IsValid() {
			ckSlice := reflect.ValueOf(ckField.Interface())
			for i := 0; i < ckSlice.Len(); i++ {
				basisField := ckSlice.Index(i).FieldByName("Basis")
				bases := basisField.Interface().([]bn254.G1Affine)
				ck2 = append(ck2, crypto.CommitKey{G: bases})
			}
		}
	}

	return &Prover{
		PK:      pk,
		CK1:     ck1,
		CK2:     ck2,
		Encoder: encoder,
	}
}

// 1. 단일 벡터 Pedersen 커밋 (병렬 처리를 위해 분리)
func (p *Prover) CommitVector(vector []fr.Element) bn254.G1Affine {
	return crypto.PedersenCommit(vector, p.CK1)
}

// 2. 그룹 엘리먼트(커밋먼트) 배열로부터 머클 트리 생성 (시간 측정을 위해 분리)
func (p *Prover) BuildMerkleTree(leaves []bn254.G1Affine, depth int) ([][]fr.Element, fr.Element) {
	return crypto.BuildMerkleTreeFromGroupElements(leaves, depth)
}

// 3. Matrix & Merkle Tree 커밋먼트 일괄 생성 (기존 호환용)
func (p *Prover) CommitMatrix(matrix [][]fr.Element, depth int) ([][]fr.Element, fr.Element, []bn254.G1Affine) {
	return crypto.CommitMatrix(matrix, p.CK1, depth)
}

// 4. 멤버십 증명 경로 추출
func (p *Prover) GenerateMembershipProof(tree [][]fr.Element, idx, depth int) []fr.Element {
	return crypto.GetMerkleProof(tree, idx, depth)
}

// 5. Groth16 Prove 및 내부 Blinding Factor 추출
func (p *Prover) ProveCircuit(r1cs constraint.ConstraintSystem, assignment frontend.Circuit) (groth16.Proof, []bn254.G1Affine, []fr.Element, error) {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, nil, err
	}

	proof, err := groth16.Prove(r1cs, p.PK, witness)
	if err != nil {
		return nil, nil, nil, err
	}

	proofVal := reflect.ValueOf(proof).Elem()
	commitmentsField := proofVal.FieldByName("Commitments")
	var cmVec2 []bn254.G1Affine
	if commitmentsField.IsValid() {
		cmVec2 = commitmentsField.Interface().([]bn254.G1Affine)
	}

	blindings := groth16_bn254.HackBlindings

	return proof, cmVec2, blindings, nil
}

// 6. CP-LINK Schnorr Proof 일괄 생성
func (p *Prover) ProveCPLink(matrix [][]fr.Element, blindings []fr.Element, L int) []crypto.CPLinkProof {
	proofs := make([]crypto.CPLinkProof, L)
	for i := 0; i < L; i++ {
		proofs[i] = crypto.ProveCPLink(matrix[i], blindings[i], p.CK1, p.CK2[i])
	}
	return proofs
}

// 7. RS Encoding 수행
func (p *Prover) EncodeMatrix(matrix [][]fr.Element) ([][]fr.Element, [][]fr.Element, error) {
	if p.Encoder == nil {
		panic("Encoder is not initialized in Prover")
	}
	return p.Encoder.EncodeMatrix(matrix)
}
