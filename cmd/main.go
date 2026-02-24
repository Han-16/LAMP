package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/rs"
	"github.com/Han-16/meow/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// Command-line flags
	kLogPtr := flag.Int("k", 4, "Log2 of matrix size K (e.g., 10 means K=1024)")
	nLogPtr := flag.Int("n", 8, "Log2 of encoded size N (e.g., 11 means N=2048)")
	lPtr := flag.Int("l", 2, "Number of queries L (actual value)")
	circuitPtr := flag.String("circuit", "meow", "Circuit to run: 'meow' or 'freivalds'")

	compileOnlyPtr := flag.Bool("compileOnly", false, "If true, only compiles the circuit to check constraints")
	flag.Parse()

	// K, N <- 2^kLogPtr, 2^nLogPtr
	K := 1 << *kLogPtr
	N := 1 << *nLogPtr
	L := *lPtr
	circuitName := *circuitPtr
	compileOnly := *compileOnlyPtr

	Depth := *nLogPtr

	fmt.Printf("===================================================\n")
	fmt.Printf("1. Parameters: Circuit=%s, K=%d (2^%d), N=%d (2^%d), L=%d, Depth=%d, CompileOnly=%t\n",
		circuitName, K, *kLogPtr, N, *nLogPtr, L, Depth, compileOnly)
	fmt.Printf("===================================================\n")

	// --------------------------------------------------------------------------------
	// CompileOnly mode: Only compile the circuit and print the number of constraints, without generating matrices or proving.
	// --------------------------------------------------------------------------------
	if compileOnly {
		fmt.Println(">> [CompileOnly Mode] Skipping off-chain matrix generation and proving.")
		switch circuitName {
		case "freivalds":
			compileFreivaldsOnly(K)
		case "meow":
			compileMeowOnly(K, N, L, Depth)
		default:
			log.Fatalf("❌ Unknown circuit: %s. Please use '-circuit=meow' or '-circuit=freivalds'", circuitName)
		}
		return
	}

	// --------------------------------------------------------------------------------
	// Default mode: Full execution (matrix generation, proving, verification)
	// --------------------------------------------------------------------------------
	fmt.Println("2. Generating random matrices and computing C = A * B...")
	start := time.Now()
	A := make([][]fr.Element, K)
	B := make([][]fr.Element, K)
	for i := 0; i < K; i++ {
		A[i] = make([]fr.Element, K)
		B[i] = make([]fr.Element, K)
		for j := 0; j < K; j++ {
			_, _ = A[i][j].SetRandom()
			_, _ = B[i][j].SetRandom()
		}
	}

	C := utils.MatMul(A, B, K)
	fmt.Printf("   -> Matrix multiplication took %v\n", time.Since(start))
	fmt.Printf("---------------------------------------------------\n")

	switch circuitName {
	case "freivalds":
		runFreivalds(K, A, B, C)
	case "meow":
		runMeow(K, N, L, Depth, A, B, C)
	default:
		log.Fatalf("❌ Unknown circuit: %s. Please use '-circuit=meow' or '-circuit=freivalds'", circuitName)
	}
}

// ==============================================================================
// CompileOnly - Freivalds
// ==============================================================================
func compileFreivaldsOnly(K int) {
	fmt.Println("-> Compiling Freivalds Circuit...")
	start := time.Now()
	emptyCircuit := circuit.FreivaldsCircuit{
		K: K,
		A: make([][]frontend.Variable, K),
		B: make([][]frontend.Variable, K),
		C: make([][]frontend.Variable, K),
	}
	for i := 0; i < K; i++ {
		emptyCircuit.A[i] = make([]frontend.Variable, K)
		emptyCircuit.B[i] = make([]frontend.Variable, K)
		emptyCircuit.C[i] = make([]frontend.Variable, K)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Compilation failed: %v", err)
	}
	fmt.Printf("✅ Freivalds Circuit compiled successfully!\n")
	fmt.Printf("📊 Constraints: %d (took %v)\n", ccs.GetNbConstraints(), time.Since(start))
}

// ==============================================================================
// CompileOnly - Meow
// ==============================================================================
func compileMeowOnly(K, N, L, Depth int) {
	fmt.Println("-> Compiling Meow Circuit...")
	start := time.Now()
	emptyCircuit := circuit.MeowCircuit{
		K: K, N: N,
		ChallengeR: make([]frontend.Variable, K), Indices: make([]frontend.Variable, L),
		VecX: make([]frontend.Variable, K), VecY: make([]frontend.Variable, K), VecZ: make([]frontend.Variable, K),
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		MerkleProofsA: make([][]frontend.Variable, L), MerkleProofsB: make([][]frontend.Variable, L), MerkleProofsC: make([][]frontend.Variable, L),
		MerkleProofsX: make([][]frontend.Variable, L), MerkleProofsY: make([][]frontend.Variable, L), MerkleProofsZ: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
		emptyCircuit.MerkleProofsA[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsB[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsC[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsX[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsY[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsZ[i] = make([]frontend.Variable, Depth)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Compilation failed: %v", err)
	}
	fmt.Printf("✅ Meow Circuit compiled successfully!\n")
	fmt.Printf("📊 Constraints: %d (took %v)\n", ccs.GetNbConstraints(), time.Since(start))
}

// ==============================================================================
// Freivalds Circuit
// ==============================================================================
func runFreivalds(K int, A, B, C [][]fr.Element) {
	fmt.Println("3. [Freivalds] Preparing Assignment Witness...")
	start := time.Now()

	assignment := circuit.FreivaldsCircuit{
		K: K,
		A: make([][]frontend.Variable, K),
		B: make([][]frontend.Variable, K),
		C: make([][]frontend.Variable, K),
	}
	emptyCircuit := circuit.FreivaldsCircuit{
		K: K,
		A: make([][]frontend.Variable, K),
		B: make([][]frontend.Variable, K),
		C: make([][]frontend.Variable, K),
	}

	for i := 0; i < K; i++ {
		assignment.A[i] = make([]frontend.Variable, K)
		assignment.B[i] = make([]frontend.Variable, K)
		assignment.C[i] = make([]frontend.Variable, K)

		emptyCircuit.A[i] = make([]frontend.Variable, K)
		emptyCircuit.B[i] = make([]frontend.Variable, K)
		emptyCircuit.C[i] = make([]frontend.Variable, K)

		for j := 0; j < K; j++ {
			assignment.A[i][j] = A[i][j]
			assignment.B[i][j] = B[i][j]
			assignment.C[i][j] = C[i][j]
		}
	}
	fmt.Printf("   -> Assignment preparation took %v\n", time.Since(start))

	fmt.Println("4. [Freivalds] Compiling Circuit...")
	start = time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Compilation failed: %v", err)
	}
	fmt.Printf("   -> Circuit compiled! Constraints: %d (took %v)\n", ccs.GetNbConstraints(), time.Since(start))

	fmt.Println("5. [Freivalds] Setting up Groth16...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("❌ Setup failed: %v", err)
	}

	fmt.Println("6. [Freivalds] Generating Witness & Proving...")
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("❌ Witness generation failed: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ Public witness extraction failed: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("❌ Proving failed: %v", err)
	}

	fmt.Println("7. [Freivalds] Verifying...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("❌ Verification failed: %v", err)
	}
	fmt.Println("🎉 [Freivalds] Proof successfully generated and verified!")
}

// ==============================================================================
// Meow Circuit
// ==============================================================================
func runMeow(K, N, L, Depth int, A, B, C [][]fr.Element) {
	fmt.Println("3. [Meow] Encoding matrices K x K -> K x N...")
	start := time.Now()
	encoder := rs.NewEncoder(K, N)
	encA, _ := encoder.EncodeRowWise(A)
	encB, _ := encoder.EncodeRowWise(B)
	encC, _ := encoder.EncodeRowWise(C)
	fmt.Printf("   -> Encoding took %v\n", time.Since(start))

	fmt.Println("4. [Meow] Building Merkle Trees for A, B, C...")
	start = time.Now()
	leavesA, leavesB, leavesC := make([]fr.Element, N), make([]fr.Element, N), make([]fr.Element, N)
	for j := 0; j < N; j++ {
		colA, colB, colC := make([]fr.Element, K), make([]fr.Element, K), make([]fr.Element, K)
		for i := 0; i < K; i++ {
			colA[i], colB[i], colC[i] = encA[i][j], encB[i][j], encC[i][j]
		}
		leavesA[j] = utils.HashElements(colA...)
		leavesB[j] = utils.HashElements(colB...)
		leavesC[j] = utils.HashElements(colC...)
	}

	treeA, cm_A := utils.BuildMerkleTree(leavesA, Depth)
	treeB, cm_B := utils.BuildMerkleTree(leavesB, Depth)
	treeC, cm_C := utils.BuildMerkleTree(leavesC, Depth)
	fmt.Printf("   -> Merkle tree construction took %v\n", time.Since(start))

	fmt.Println("5. [Meow] Generating cmABC and ChallengeR...")
	start = time.Now()
	cmABC := utils.HashElements(cm_A, cm_B, cm_C)
	r := utils.HashElements(cmABC)
	challengeR := make([]fr.Element, K)
	challengeR[0].SetUint64(1)
	for i := 1; i < K; i++ {
		challengeR[i].Mul(&challengeR[i-1], &r)
	}
	fmt.Printf("   -> ChallengeR generation took %v\n", time.Since(start))

	fmt.Println("6. [Meow] Performing vector operations & encoding...")
	start = time.Now()
	x := utils.VecMatMul(challengeR, A, K)
	y := utils.VecMatMul(x, B, K)
	z := utils.VecMatMul(challengeR, C, K)

	encX, _ := encoder.Encode(x)
	encY, _ := encoder.Encode(y)
	encZ, _ := encoder.Encode(z)
	fmt.Printf("   -> Vector ops & encoding took %v\n", time.Since(start))

	fmt.Println("7. [Meow] Building Merkle Trees for vectors...")
	start = time.Now()
	leavesX, leavesY, leavesZ := make([]fr.Element, N), make([]fr.Element, N), make([]fr.Element, N)
	for i := 0; i < N; i++ {
		leavesX[i] = utils.HashElements(encX[i])
		leavesY[i] = utils.HashElements(encY[i])
		leavesZ[i] = utils.HashElements(encZ[i])
	}

	treeX, cm_x := utils.BuildMerkleTree(leavesX, Depth)
	treeY, cm_y := utils.BuildMerkleTree(leavesY, Depth)
	treeZ, cm_z := utils.BuildMerkleTree(leavesZ, Depth)
	fmt.Printf("   -> Merkle trees for vectors took %v\n", time.Since(start))

	fmt.Println("8. [Meow] Extracting indices using Fiat-Shamir heuristic...")
	start = time.Now()
	cmXYZ := utils.HashElements(cm_x, cm_y, cm_z)
	indices := make([]int, 0, L)
	used := make(map[int]bool)
	h := mimc.NewMiMC()
	cmBytes := cmXYZ.Bytes()
	hashBytes := cmBytes[:]

	for len(indices) < L {
		h.Reset()
		h.Write(hashBytes)
		hashBytes = h.Sum(nil)
		for i := 0; i < 32 && len(indices) < L; i += 8 {
			val := binary.BigEndian.Uint64(hashBytes[i : i+8])
			idx := int(val % uint64(N))
			if !used[idx] {
				used[idx] = true
				indices = append(indices, idx)
			}
		}
	}
	fmt.Printf("   -> Index extraction took %v\n", time.Since(start))

	fmt.Println("9. [Meow] Preparing Assignment Witness...")
	start = time.Now()
	assignment := circuit.MeowCircuit{
		K: K, N: N,
		CmABC: cmABC, CmXYZ: cmXYZ,
		Roots:         [6]frontend.Variable{cm_A, cm_B, cm_C, cm_x, cm_y, cm_z},
		ChallengeR:    make([]frontend.Variable, K),
		Indices:       make([]frontend.Variable, L),
		VecX:          make([]frontend.Variable, K),
		VecY:          make([]frontend.Variable, K),
		VecZ:          make([]frontend.Variable, K),
		ColsEncA:      make([][]frontend.Variable, L),
		ColsEncB:      make([][]frontend.Variable, L),
		ColsEncC:      make([][]frontend.Variable, L),
		MerkleProofsA: make([][]frontend.Variable, L), MerkleProofsB: make([][]frontend.Variable, L), MerkleProofsC: make([][]frontend.Variable, L),
		MerkleProofsX: make([][]frontend.Variable, L), MerkleProofsY: make([][]frontend.Variable, L), MerkleProofsZ: make([][]frontend.Variable, L),
	}

	for i := 0; i < K; i++ {
		assignment.ChallengeR[i] = challengeR[i]
		assignment.VecX[i], assignment.VecY[i], assignment.VecZ[i] = x[i], y[i], z[i]
	}

	toVarSlice := func(frArr []fr.Element) []frontend.Variable {
		vArr := make([]frontend.Variable, len(frArr))
		for k, v := range frArr {
			vArr[k] = v
		}
		return vArr
	}

	for i := 0; i < L; i++ {
		idx := indices[i]
		assignment.Indices[i] = idx

		assignment.ColsEncA[i] = make([]frontend.Variable, K)
		assignment.ColsEncB[i] = make([]frontend.Variable, K)
		assignment.ColsEncC[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignment.ColsEncA[i][j] = encA[j][idx]
			assignment.ColsEncB[i][j] = encB[j][idx]
			assignment.ColsEncC[i][j] = encC[j][idx]
		}

		assignment.MerkleProofsA[i] = toVarSlice(utils.GetMerkleProof(treeA, idx, Depth))
		assignment.MerkleProofsB[i] = toVarSlice(utils.GetMerkleProof(treeB, idx, Depth))
		assignment.MerkleProofsC[i] = toVarSlice(utils.GetMerkleProof(treeC, idx, Depth))
		assignment.MerkleProofsX[i] = toVarSlice(utils.GetMerkleProof(treeX, idx, Depth))
		assignment.MerkleProofsY[i] = toVarSlice(utils.GetMerkleProof(treeY, idx, Depth))
		assignment.MerkleProofsZ[i] = toVarSlice(utils.GetMerkleProof(treeZ, idx, Depth))
	}
	fmt.Printf("   -> Assignment preparation took %v\n", time.Since(start))

	fmt.Println("10. [Meow] Compiling Circuit...")
	start = time.Now()
	emptyCircuit := circuit.MeowCircuit{
		K: K, N: N,
		ChallengeR: make([]frontend.Variable, K), Indices: make([]frontend.Variable, L),
		VecX: make([]frontend.Variable, K), VecY: make([]frontend.Variable, K), VecZ: make([]frontend.Variable, K),
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		MerkleProofsA: make([][]frontend.Variable, L), MerkleProofsB: make([][]frontend.Variable, L), MerkleProofsC: make([][]frontend.Variable, L),
		MerkleProofsX: make([][]frontend.Variable, L), MerkleProofsY: make([][]frontend.Variable, L), MerkleProofsZ: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
		emptyCircuit.MerkleProofsA[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsB[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsC[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsX[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsY[i] = make([]frontend.Variable, Depth)
		emptyCircuit.MerkleProofsZ[i] = make([]frontend.Variable, Depth)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Compilation failed: %v", err)
	}
	fmt.Printf("   -> Circuit compiled! Constraints: %d (took %v)\n", ccs.GetNbConstraints(), time.Since(start))

	fmt.Println("11. [Meow] Generating Witness & Proving...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("❌ Setup failed: %v", err)
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatalf("❌ Witness generation failed: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ Public witness extraction failed: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatalf("❌ Proving failed: %v", err)
	}

	fmt.Println("12. [Meow] Verifying...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("❌ Verification failed: %v", err)
	}
	fmt.Println("🎉 [Meow] Proof successfully generated and verified!")
}
