package protocol

import (
	"testing"

	"github.com/Han-16/lamp/crypto"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type commitmentCircuit struct {
	Values [2]frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {
	_, err := api.(frontend.Committer).Commit(c.Values[:]...)
	return err
}

func TestBLS12381Groth16CommitmentExtraction(t *testing.T) {
	field := ecc.BLS12_381.ScalarField()
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &commitmentCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}

	assignment := &commitmentCircuit{Values: [2]frontend.Variable{3, 5}}
	prover := NewProver(pk, crypto.CommitKey{}, nil)
	proof, commitments, blindings, err := prover.ProveCircuit(cs, assignment)
	if err != nil {
		t.Fatal(err)
	}
	if len(prover.CK2) != 1 || len(commitments) != 1 || len(blindings) != 1 {
		t.Fatalf("unexpected commitment counts: keys=%d commitments=%d blindings=%d", len(prover.CK2), len(commitments), len(blindings))
	}

	expected := crypto.PedersenCommitBlinded(
		[]fr.Element{fr.NewElement(3), fr.NewElement(5)},
		blindings[0],
		prover.CK2[0],
	)
	if !expected.Equal(&commitments[0]) {
		t.Fatal("extracted BLS12-381 commitment and blinding do not match")
	}

	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		t.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		t.Fatal(err)
	}
}
