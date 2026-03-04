package main

import (
	"flag"
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

func main() {
	logKFlag := flag.Int("K", 10, "Log base 2 of K (e.g., 10 for K=1024)")
	LFlag := flag.Int("L", 10, "Number of columns L")
	flag.Parse()
	K := 1 << *logKFlag
	L := *LFlag

	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [CP Experiment]: K = 2^%d, L = %d\n", *logKFlag, L)

	// =========================================================================
	// 1. Compile & Setup
	// =========================================================================
	emptyCircuit := circuit.Cp{
		CommittedValues: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.CommittedValues[i] = make([]frontend.Variable, K)
	}
	r1cs, _ := frontend.Compile(field, r1cs.NewBuilder, &emptyCircuit)
	pk, vk, _ := groth16.Setup(r1cs)

	// =========================================================================
	// 2. Extract L sets of "Basis" from pk
	// =========================================================================
	val := reflect.ValueOf(pk)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	ckField := val.FieldByName("CommitmentKeys")

	var ck [][]bn254.G1Affine
	if ckField.IsValid() {
		ckSlice := reflect.ValueOf(ckField.Interface())
		for i := 0; i < ckSlice.Len(); i++ {
			basisField := ckSlice.Index(i).FieldByName("Basis")
			ck = append(ck, basisField.Interface().([]bn254.G1Affine))
		}
		fmt.Printf("✅ Extracted %d Native Bases from pk!\n", len(ck))
	}

	// =========================================================================
	// 3. Generate Random Matrix [L][K]
	// =========================================================================
	matrix := make([][]fr.Element, L)
	for i := 0; i < L; i++ {
		matrix[i] = make([]fr.Element, K)
		for j := 0; j < K; j++ {
			matrix[i][j].SetRandom()
		}
	}
	// =========================================================================
	// 4. Prove & Intercept Blinding Factors
	// =========================================================================
	fmt.Println("\n--- Step 1: Generating ZK Proof & Intercepting Blinding Factors ---")
	assignment := circuit.Cp{
		CommittedValues: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		assignment.CommittedValues[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignment.CommittedValues[i][j] = matrix[i][j]
		}
	}

	witnessFull, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	start := time.Now()
	proof, err := groth16.Prove(r1cs, pk, witnessFull)
	if err != nil {
		fmt.Println("❌ Proof generation failed:", err)
		return
	}
	fmt.Printf("✅ Proof generated in %s\n", time.Since(start))

	// 증명 결과물에서 L개의 커밋 추출
	proofVal := reflect.ValueOf(proof).Elem()
	commitmentsField := proofVal.FieldByName("Commitments")
	var proofCommitments []bn254.G1Affine
	if commitmentsField.IsValid() {
		proofCommitments = commitmentsField.Interface().([]bn254.G1Affine)
	}

	// =========================================================================
	// 5. Compute L Manual Commitments and Compare
	// =========================================================================
	fmt.Println("\n--- Step 2: Comparing L Commitments ---")

	hackedBlindings := groth16_bn254.HackBlindings

	allMatched := true

	for i := 0; i < L; i++ {
		// 1. 오프체인 커밋 계산 (matrix[i] + hackedBlindings[i])
		vectorPadded := append(matrix[i], hackedBlindings[i])
		var manualCommitment bn254.G1Affine
		_, err = manualCommitment.MultiExp(ck[i], vectorPadded, ecc.MultiExpConfig{})
		if err != nil {
			fmt.Printf("⚠️ MultiExp Error on [%d]: %v\n", i, err)
			allMatched = false
			continue
		}

		// 2. 증명 내부 커밋과 비교
		circuitCommitment := proofCommitments[i]

		if !manualCommitment.Equal(&circuitCommitment) {
			fmt.Printf("❌ Match FAILED at Commitment [%d]!\n", i)
			fmt.Printf("   Manual : %v\n", manualCommitment)
			fmt.Printf("   Circuit: %v\n", circuitCommitment)
			allMatched = false
		}
	}

	fmt.Println("\n=== The Ultimate Comparison Result ===")
	if allMatched {
		fmt.Println("🔥🔥🔥 ALL COMMITMENTS PERFECTLY MATCHED! 🔥🔥🔥")
	} else {
		fmt.Println("❌ SOME COMMITMENTS FAILED.")
	}

	// 증명 검증
	witnessPublic, _ := witnessFull.Public()
	if err := groth16.Verify(proof, vk, witnessPublic); err == nil {
		fmt.Println("\n🎉 Groth16 Verification SUCCESSFUL!")
	}
}
