package protocol

import (
	"reflect"

	"example.com/lamp/crypto"
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

				if len(bases) > 0 {
					G := bases[:len(bases)-1]
					H := bases[len(bases)-1]
					ck2 = append(ck2, crypto.CommitKey{G: G, H: H})
				}
			}
		}
	}

	return &Prover{PK: pk, CK1: ck1, CK2: ck2, Encoder: encoder}
}

func (p *Prover) CommitMatrixBlinded(matrix [][]fr.Element, depth int) ([][]fr.Element, fr.Element, []bn254.G1Affine, []fr.Element) {
	cm, blindings := crypto.BatchPedersenCommitBlinded(matrix, p.CK1)

	tree, root := crypto.BuildMerkleTreeFromGroupElements(cm, depth)

	return tree, root, cm, blindings
}

func (p *Prover) CommitMatrixBlindedWithKey(matrix [][]fr.Element, depth int, ck crypto.CommitKey) ([][]fr.Element, fr.Element, []bn254.G1Affine, []fr.Element) {
	cm, blindings := crypto.BatchPedersenCommitBlinded(matrix, ck)

	tree, root := crypto.BuildMerkleTreeFromGroupElements(cm, depth)

	return tree, root, cm, blindings
}

func (p *Prover) CommitScalarsBlinded(scalars []fr.Element, depth int, ckScalar crypto.CommitKey) ([][]fr.Element, fr.Element, []bn254.G1Affine, []fr.Element) {
	matrix := make([][]fr.Element, len(scalars))
	for i, s := range scalars {
		matrix[i] = []fr.Element{s}
	}

	cm, blindings := crypto.BatchPedersenCommitBlinded(matrix, ckScalar)

	tree, root := crypto.BuildMerkleTreeFromGroupElements(cm, depth)

	return tree, root, cm, blindings
}

func (p *Prover) GenerateMembershipProof(tree [][]fr.Element, idx, depth int) []fr.Element {
	return crypto.GetMerkleProof(tree, idx, depth)
}

func (p *Prover) ProveCircuit(r1cs constraint.ConstraintSystem, assignment frontend.Circuit) (groth16.Proof, []bn254.G1Affine, []fr.Element, error) {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, nil, err
	}
	proof, err := groth16.Prove(r1cs, p.PK, witness)
	if err != nil {
		return nil, nil, nil, err
	}

	cmVec2, blindings := ExtractGroth16CommitmentsAndBlindings(proof)
	return proof, cmVec2, blindings, nil
}

func ExtractGroth16CommitmentsAndBlindings(proof groth16.Proof) ([]bn254.G1Affine, []fr.Element) {
	proofVal := reflect.ValueOf(proof).Elem()
	commitmentsField := proofVal.FieldByName("Commitments")
	var cmVec2 []bn254.G1Affine
	if commitmentsField.IsValid() {
		cmVec2 = commitmentsField.Interface().([]bn254.G1Affine)
	}

	blindings := groth16_bn254.HackBlindings
	return cmVec2, blindings
}

func (p *Prover) EncodeMatrix(matrix [][]fr.Element) ([][]fr.Element, [][]fr.Element, error) {
	return p.Encoder.EncodeMatrix(matrix)
}
