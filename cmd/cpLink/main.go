package main

import (
	"fmt"
	"reflect"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

const K = 1 << 2

func main() {
	field := ecc.BN254.ScalarField()
	fmt.Println("=== Native Commitment Hacking & Verification ===")

	// =========================================================================
	// 1. Compile & Setup
	// =========================================================================
	emptyCircuit := circuit.CpLink{
		CommittedValues: make([]frontend.Variable, K),
	}
	ccs, _ := frontend.Compile(field, r1cs.NewBuilder, &emptyCircuit)
	pk, vk, _ := groth16.Setup(ccs)

	// =========================================================================
	// 2. Extract ck2's "Basis" using Reflection
	// =========================================================================
	val := reflect.ValueOf(pk)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	ckField := val.FieldByName("CommitmentKeys")

	var nativeBasis []bn254.G1Affine
	if ckField.IsValid() {
		ckSlice := reflect.ValueOf(ckField.Interface())
		if ckSlice.Len() > 0 {
			nativeBasis = ckSlice.Index(0).FieldByName("Basis").Interface().([]bn254.G1Affine)
			fmt.Printf("✅ Extracted Native Basis from pk! (Length: %d)\n", len(nativeBasis))
		}
	}

	// =========================================================================
	// 3. Generate Random Vector (vectorA)
	// =========================================================================
	vectorA := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		vectorA[i].SetRandom()
	}

	// =========================================================================
	// 4. Generate ZK Proof & Extract Circuit's Commitment FIRST
	// =========================================================================
	fmt.Println("\n--- Step 1: Generating ZK Proof & Intercepting Blinding Factor ---")
	assignment := circuit.CpLink{
		CommittedValues: make([]frontend.Variable, K),
	}
	for i := 0; i < K; i++ {
		assignment.CommittedValues[i] = vectorA[i]
	}

	witnessFull, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	start := time.Now()

	proof, err := groth16.Prove(ccs, pk, witnessFull)
	if err != nil {
		fmt.Println("❌ Proof generation failed:", err)
		return
	}
	fmt.Printf("✅ Proof generated in %s\n", time.Since(start))

	proofVal := reflect.ValueOf(proof).Elem()
	commitmentsField := proofVal.FieldByName("Commitments")

	var proofCommitment bn254.G1Affine
	if commitmentsField.IsValid() {
		C2_array := commitmentsField.Interface().([]bn254.G1Affine)
		if len(C2_array) > 0 {
			proofCommitment = C2_array[0]
			fmt.Println("\n[Circuit Commitment] (Extracted from Proof):")
			fmt.Printf("    X: %s\n    Y: %s\n", proofCommitment.X.String(), proofCommitment.Y.String())
		}
	}

	// =========================================================================
	// 5. Compute Manual Commitment using the Hacked Blinding Factor
	// =========================================================================
	fmt.Println("\n--- Step 2: Computing Off-chain Commitment with Hacked Data ---")

	hackedBlinding := groth16_bn254.HackBlinding
	fmt.Printf("🔥🔥🔥 Successfully intercepted Blinding Factor from global var: %s\n", hackedBlinding.String())

	var manualCommitment bn254.G1Affine

	// Concat vectorA with the hacked blinding factor to mimic the circuit's input structure
	vectorA_padded := append(vectorA, hackedBlinding)

	// Perform multi-exponentiation to compute the commitment off-chain
	_, err = manualCommitment.MultiExp(nativeBasis, vectorA_padded, ecc.MultiExpConfig{})
	if err != nil {
		fmt.Printf("\n⚠️ MultiExp Error: %v\n", err)
	} else {
		fmt.Println("\n[Manual Commitment] (Computed Off-chain):")
		fmt.Printf("    X: %s\n    Y: %s\n", manualCommitment.X.String(), manualCommitment.Y.String())
	}

	// =========================================================================
	// 6. 🥁 The Moment of Truth: Compare them!
	// =========================================================================
	fmt.Println("\n=== The Ultimate Comparison Result ===")
	if manualCommitment.Equal(&proofCommitment) {
		fmt.Println("🔥🔥🔥 SUCCESS: The manual commitment perfectly matches the proof's commitment! 🔥🔥🔥")
		fmt.Println("    (블랙박스 내부 연산을 100% 동일하게 오프체인에서 재현하셨습니다!)")
	} else {
		fmt.Println("❌ FAILED: The commitments do not match.")
	}

	// 증명 검증
	witnessPublic, _ := witnessFull.Public()
	if err := groth16.Verify(proof, vk, witnessPublic); err == nil {
		fmt.Println("\n🎉 Groth16 Verification SUCCESSFUL!")
	}
}
