package main

import (
	"flag"
	"fmt"
	"reflect"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/utils"
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

	fmt.Printf("🔥 [CP-LINK Experiment]: K = 2^%d, L = %d\n", *logKFlag, L)

	// =========================================================================
	// 1 & 2. Generate Matrix and Setup Off-chain CommitKey (ck1)
	// =========================================================================
	fmt.Println("\n--- Step 1: Matrix & ck1 Generation ---")
	matrix := make([][]fr.Element, L)
	for i := 0; i < L; i++ {
		matrix[i] = make([]fr.Element, K)
		for j := 0; j < K; j++ {
			matrix[i][j].SetRandom()
		}
	}

	// ck1 has size K (no blinding factor)
	ck1 := utils.SetupCommitKey(K)
	fmt.Printf("✅ ck1 generated with %d bases\n", K)

	// =========================================================================
	// 3. Compute Off-chain Commitments (cm_vec_1) using ck1
	// =========================================================================
	fmt.Println("\n--- Step 2: Generate cm_vec_1 (Off-chain) ---")
	cm_vec_1 := make([]bn254.G1Affine, L)
	for i := 0; i < L; i++ {
		cm_vec_1[i] = utils.PedersenCommit(matrix[i], ck1)
	}
	fmt.Printf("✅ cm_vec_1 generated: %d commitments\n", L)

	// =========================================================================
	// 4. Compile Circuit, Setup, and Prove
	// =========================================================================
	fmt.Println("\n--- Step 3: ZK Circuit Setup & Prove ---")
	emptyCircuit := circuit.Cp{
		CommittedValues: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.CommittedValues[i] = make([]frontend.Variable, K)
	}
	r1cs, _ := frontend.Compile(field, r1cs.NewBuilder, &emptyCircuit)
	pk, _, _ := groth16.Setup(r1cs)

	assignment := circuit.Cp{
		CommittedValues: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		assignment.CommittedValues[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignment.CommittedValues[i][j] = matrix[i][j]
		}
	}

	witnessFull, _ := frontend.NewWitness(&assignment, field)
	start := time.Now()
	proof, err := groth16.Prove(r1cs, pk, witnessFull)
	if err != nil {
		fmt.Println("❌ Proof generation failed:", err)
		return
	}
	fmt.Printf("✅ Proof generated in %s\n", time.Since(start))

	// =========================================================================
	// 5. Extract ck2 and cm_vec_2 from Circuit Proof
	// =========================================================================
	val := reflect.ValueOf(pk).Elem()
	ckField := val.FieldByName("CommitmentKeys")
	var rawCk2 [][]bn254.G1Affine
	if ckField.IsValid() {
		ckSlice := reflect.ValueOf(ckField.Interface())
		for i := 0; i < ckSlice.Len(); i++ {
			basisField := ckSlice.Index(i).FieldByName("Basis")
			rawCk2 = append(rawCk2, basisField.Interface().([]bn254.G1Affine))
		}
	}

	proofVal := reflect.ValueOf(proof).Elem()
	commitmentsField := proofVal.FieldByName("Commitments")
	var cm_vec_2 []bn254.G1Affine
	if commitmentsField.IsValid() {
		cm_vec_2 = commitmentsField.Interface().([]bn254.G1Affine)
	}

	// Extract the intercepted blinding factors
	hackedBlindings := groth16_bn254.HackBlindings
	fmt.Printf("✅ Extracted ck2 (size %d) and cm_vec_2 (size %d) from proof\n", len(rawCk2[0]), len(cm_vec_2))

	// =========================================================================
	// 6 & 7. Prove and Verify CP-LINK for each column
	// =========================================================================
	fmt.Println("\n--- Step 4: CP-LINK Equivalence Proofs ---")

	allMatched := true

	for i := 0; i < L; i++ {
		fmt.Printf("[Column %d]\n", i)

		// Create ck2 struct for the current column
		ck2 := utils.CommitKey{G: rawCk2[i]}

		// 6. Generate CP-LINK Proof
		startProve := time.Now()
		linkProof := utils.ProveCPLink(matrix[i], hackedBlindings[i], ck1, ck2)
		fmt.Printf("   📝 Proof generated in %s\n", time.Since(startProve))

		// 7. Verify CP-LINK Proof
		startVerify := time.Now()
		isValid := utils.VerifyCPLink(cm_vec_1[i], cm_vec_2[i], linkProof, ck1, ck2)
		fmt.Printf("   🔍 Verification took %s\n", time.Since(startVerify))

		if isValid {
			fmt.Println("   ✅ RESULT: Valid equivalence (cm_vec_1 matches cm_vec_2)")
		} else {
			fmt.Println("   ❌ RESULT: Invalid equivalence!")
			allMatched = false
		}
	}

	fmt.Println("\n=== The Ultimate CP-LINK Result ===")
	if allMatched {
		fmt.Println("🔥🔥🔥 ALL CP-LINK PROOFS VERIFIED SUCCESSFULLY! 🔥🔥🔥")
	} else {
		fmt.Println("❌ SOME PROOFS FAILED.")
	}
}
