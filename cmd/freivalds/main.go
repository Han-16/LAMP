package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/Han-16/meow/benchmark"
	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/config"
	"github.com/Han-16/meow/crypto"
	"github.com/Han-16/meow/matrix"
	"github.com/Han-16/meow/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	logKFlag := flag.Int("K", config.GetInt("FREIVALDS_LOG_K", 10), "Log base 2 of K")
	allFlag := flag.Bool("all", config.GetBool("FREIVALDS_ALL", false), "Run benchmark range")
	fromFlag := flag.Int("from", config.GetInt("FREIVALDS_LOG_K_FROM", 5), "First logK when -all is enabled")
	toFlag := flag.Int("to", config.GetInt("FREIVALDS_LOG_K_TO", 15), "Last logK when -all is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("FREIVALDS_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("FREIVALDS_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("FREIVALDS_OUTPUT_DIR", filepath.Join("benchmark", "freivalds"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	csvPath := filepath.Join(outputDir, "freivalds_benchmark_results.csv")
	file, writer := benchmark.InitFreivaldsCSV(csvPath)
	defer file.Close()

	if *allFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid logK range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		if onlyCompile {
			fmt.Printf("🚀 [OnlyCompile MODE] Checking constraints for logK=%d..%d\n", *fromFlag, *toFlag)
		} else {
			fmt.Printf("🚀 [ALL MODE] Running Freivalds benchmarks for logK=%d..%d\n", *fromFlag, *toFlag)
		}

		for logK := *fromFlag; logK <= *toFlag; logK++ {
			res := runExperiment(logK, onlyCompile)
			benchmark.AppendFreivaldsResultToCSV(writer, res)
			fmt.Println("----------------------------------------------------------------")
		}
	} else {
		res := runExperiment(*logKFlag, onlyCompile)
		benchmark.AppendFreivaldsResultToCSV(writer, res)
	}

	fmt.Println("🎉 All Freivalds benchmarks finished!")
}

func runExperiment(logK int, onlyCompile bool) benchmark.FreivaldsResult {
	K := 1 << logK
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [Freivalds] logK=%d, K=%d (%d x %d Matrix)\n", logK, K, K, K)

	if onlyCompile {
		fmt.Println("=== 🔍 Compiling Circuit for Constraints ===")

		emptyCircuit := newFreivaldsCircuit(K)

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("❌ Circuit compilation failed: %v", err)
		}

		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("✅ Circuit compiled successfully! Total Constraints: %d\n", nbConstraints)

		return benchmark.FreivaldsResult{
			LogK:        logK,
			Constraints: nbConstraints,
		}
	}

	// =========================================================================
	// 1. Data Preparation & Compute C = A * B
	// =========================================================================
	fmt.Println("=== 1. Generating Matrices and Computing C = A * B ===")
	matA := matrix.GenerateRandomMatrix(K, K)
	matB := matrix.GenerateRandomMatrix(K, K)

	startCompute := time.Now()
	// Matrix 연산 패키지의 MatMul 활용 (O(K^3))
	matC := matrix.MatMul(matA, matB, K)
	matrixComputeTime := time.Since(startCompute).Seconds()
	fmt.Printf("   ✅ Matrix Compute Time: %.2f s\n", matrixComputeTime)

	// =========================================================================
	// 2. Circuit Setup (Compile & Groth16 Setup)
	// =========================================================================
	fmt.Println("=== 2. Circuit Compilation & Setup ===")
	startSetup := time.Now()

	emptyCircuit := newFreivaldsCircuit(K)

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

	prover := protocol.NewProver(pk, crypto.CommitKey{}, nil)
	verifier := protocol.NewVerifier(vk, crypto.CommitKey{}, nil)

	// =========================================================================
	// 3. Witness Assignment & Proof Generation
	// =========================================================================
	fmt.Println("=== 3. Generating Proof ===")
	assignment := newFreivaldsCircuit(K)
	for i := 0; i < K; i++ {
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
	fmt.Printf("   ✅ Prove Time: %.2f s\n", proveTime)

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

	err = verifier.VerifyGroth16(proof, publicWitness)
	if err != nil {
		log.Fatalf("❌ Verification FAILED: %v", err)
	}
	verifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %.2f s\n", verifyTime)

	return benchmark.FreivaldsResult{
		LogK:              logK,
		MatrixComputeTime: matrixComputeTime,
		Constraints:       numConstraints,
		SetupTime:         setupTime,
		ProveTime:         proveTime,
		VerifyTime:        verifyTime,
	}
}

func newFreivaldsCircuit(K int) *circuit.FreivaldsCircuit {
	c := &circuit.FreivaldsCircuit{
		A: make([][]frontend.Variable, K),
		B: make([][]frontend.Variable, K),
		C: make([][]frontend.Variable, K),
		K: K,
	}
	for i := 0; i < K; i++ {
		c.A[i] = make([]frontend.Variable, K)
		c.B[i] = make([]frontend.Variable, K)
		c.C[i] = make([]frontend.Variable, K)
	}
	return c
}
