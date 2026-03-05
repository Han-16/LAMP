package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/Han-16/meow/benchmark"
	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/crypto"
	"github.com/Han-16/meow/matrix"
	"github.com/Han-16/meow/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	logKFlag := flag.Int("K", 10, "Log base 2 of K (Matrix dimension KxK, e.g., 4 for K=16)")
	allFlag := flag.Bool("all", false, "Run benchmarks for K=4..10")
	flag.Parse()

	// 1. 안전한 벤치마크 디렉토리 및 CSV 파일 초기화
	outputDir := filepath.Join(".", "benchmark_results")
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	csvPath := filepath.Join(outputDir, "freivalds_benchmark_results.csv")
	file, writer := benchmark.InitFreivaldsCSV(csvPath)
	defer file.Close()

	if *allFlag {
		fmt.Println("🚀 [ALL MODE] Running benchmarks: K from 2^4 to 2^10")
		for logK := 4; logK <= 10; logK++ {
			res := runExperiment(logK)
			benchmark.AppendFreivaldsResultToCSV(writer, res)
			fmt.Println("----------------------------------------------------------------")
		}
	} else {
		res := runExperiment(*logKFlag)
		benchmark.AppendFreivaldsResultToCSV(writer, res)
	}

	fmt.Println("🎉 All Freivalds benchmarks finished!")
}

func runExperiment(logK int) benchmark.FreivaldsResult {
	K := 1 << logK
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [Freivalds] K = 2^%d (%d x %d Matrix)\n", logK, K, K)

	// =========================================================================
	// 1. Data Preparation & Compute C = A * B
	// =========================================================================
	fmt.Println("=== 1. Generating Matrices and Computing C = A * B ===")
	matA := matrix.GenerateRandomMatrix(K, K)
	matB := matrix.GenerateRandomMatrix(K, K)

	startCompute := time.Now()
	// Matrix 연산 패키지의 MatMul 활용 (O(K^3))
	matC := matrix.MatMul(matA, matB, K)
	computeTime := time.Since(startCompute).Seconds()
	fmt.Printf("   ✅ Compute Time: %.6f s\n", computeTime)

	// =========================================================================
	// 2. Circuit Setup (Compile & Groth16 Setup)
	// =========================================================================
	fmt.Println("=== 2. Circuit Compilation & Setup ===")
	startSetup := time.Now()

	emptyCircuit := &circuit.FreivaldsCircuit{
		A: make([][]frontend.Variable, K),
		B: make([][]frontend.Variable, K),
		C: make([][]frontend.Variable, K),
		K: K,
	}
	for i := 0; i < K; i++ {
		emptyCircuit.A[i] = make([]frontend.Variable, K)
		emptyCircuit.B[i] = make([]frontend.Variable, K)
		emptyCircuit.C[i] = make([]frontend.Variable, K)
	}

	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Circuit compilation failed: %v", err)
	}

	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("❌ Groth16 setup failed: %v", err)
	}
	setupTime := time.Since(startSetup).Seconds()
	numConstraints := r1csSystem.GetNbConstraints()
	fmt.Printf("   📊 Constraints: %d\n", numConstraints)

	// 🌟 Prover 및 Verifier 객체 초기화
	prover := protocol.NewProver(pk, crypto.CommitKey{}, nil)
	verifier := protocol.NewVerifier(vk, crypto.CommitKey{}, nil)

	// =========================================================================
	// 3. Witness Assignment & Proof Generation
	// =========================================================================
	fmt.Println("=== 3. Generating Proof ===")
	assignment := &circuit.FreivaldsCircuit{
		A: make([][]frontend.Variable, K),
		B: make([][]frontend.Variable, K),
		C: make([][]frontend.Variable, K),
		K: K,
	}
	for i := 0; i < K; i++ {
		assignment.A[i] = make([]frontend.Variable, K)
		assignment.B[i] = make([]frontend.Variable, K)
		assignment.C[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignment.A[i][j] = matA[i][j]
			assignment.B[i][j] = matB[i][j]
			assignment.C[i][j] = matC[i][j]
		}
	}

	startProve := time.Now()
	proof, _, _, err := prover.ProveCircuit(r1csSystem, assignment)
	if err != nil {
		log.Fatalf("❌ Proof generation failed: %v", err)
	}
	proveTime := time.Since(startProve).Seconds()
	fmt.Printf("   ✅ Prove Time: %.6f s\n", proveTime)

	// =========================================================================
	// 4. Verification
	// =========================================================================
	fmt.Println("=== 4. Verifying Proof ===")
	startVerify := time.Now()

	// Public Witness 추출
	witness, _ := frontend.NewWitness(assignment, field)
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ Public witness extraction failed: %v", err)
	}

	// Verifier 객체의 VerifyGroth16 활용
	err = verifier.VerifyGroth16(proof, publicWitness)
	if err != nil {
		log.Fatalf("❌ Verification FAILED: %v", err)
	}
	verifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %.6f s\n", verifyTime)

	return benchmark.FreivaldsResult{
		LogK:        logK,
		Compute:     computeTime,
		Constraints: numConstraints,
		SetupTime:   setupTime,
		ProveTime:   proveTime,
		VerifyTime:  verifyTime,
	}
}
