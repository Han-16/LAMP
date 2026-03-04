package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// Command line flags
	logKFlag := flag.Int("K", 10, "Log base 2 of K (Matrix dimension, e.g., 10 for K=1024)")
	allFlag := flag.Bool("all", false, "Run benchmarks for K=2^8 to 2^15")

	flag.Parse()

	// 1. Init CSV for benchmark results
	file, writer := utils.InitFreivaldsCSV("../../benchmark/freivalds_benchmark_results.csv")
	defer file.Close()

	// 2. Run benchmarks
	if *allFlag {
		fmt.Println("🚀 [ALL MODE] Running benchmarks: K from 2^8 to 2^15")
		for logK := 8; logK <= 15; logK++ {
			res := runExperiment(logK)
			utils.AppendFreivaldsResultToCSV(writer, res)
			fmt.Println("----------------------------------------------------------------")
		}
	} else {
		res := runExperiment(*logKFlag)
		utils.AppendFreivaldsResultToCSV(writer, res)
	}

	fmt.Println("🎉 All benchmarks finished successfully!")
}

func runExperiment(logK int) utils.FreivaldsResult {
	K := 1 << logK

	fmt.Printf("🔥 Experiment: logK = %d (Matrix Dimension K = %d x %d)\n", logK, K, K)

	// ------------------------------------------------------------------------
	// 0. Matrix Generation & Multiplication (Offline)
	// ------------------------------------------------------------------------
	fmt.Printf("=== 0. Generate Matrices & Compute C = A * B (Offline) ===\n")
	startTime := time.Now()

	A := utils.GenerateRandomMatrix(K, K)
	B := utils.GenerateRandomMatrix(K, K)
	C := utils.MatMul(A, B, K)

	offlineTimeS := time.Since(startTime).Seconds()
	fmt.Printf("✅ Offline matrix multiplication completed in: %.6f s\n", offlineTimeS)

	// ------------------------------------------------------------------------
	// 1. Circuit Setup (Compile & Setup)
	// ------------------------------------------------------------------------
	fmt.Println("=== 1. Circuit Setup (Compile & Setup) ===")
	field := ecc.BN254.ScalarField()
	startTime = time.Now()

	emptyA := make([][]frontend.Variable, K)
	emptyB := make([][]frontend.Variable, K)
	emptyC := make([][]frontend.Variable, K)

	for i := 0; i < K; i++ {
		emptyA[i] = make([]frontend.Variable, K)
		emptyB[i] = make([]frontend.Variable, K)
		emptyC[i] = make([]frontend.Variable, K)
	}

	emptyCircuit := &circuit.FreivaldsCircuit{
		A: emptyA,
		B: emptyB,
		C: emptyC,
		K: K,
	}

	r1csCircuit, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("Circuit compilation failed: %v", err)
	}

	numConstraints := r1csCircuit.GetNbConstraints()
	fmt.Printf("📊 Circuit Constraints: %d\n", numConstraints)

	pk, vk, err := groth16.Setup(r1csCircuit)
	if err != nil {
		log.Fatalf("Groth16 setup failed: %v", err)
	}
	setupTimeS := time.Since(startTime).Seconds()
	fmt.Printf("✅ Setup completed in: %.6f s\n", setupTimeS)

	// ------------------------------------------------------------------------
	// 2. Prove & Verify
	// ------------------------------------------------------------------------
	fmt.Println("=== 2. Prove & Verify ===")
	assignA := make([][]frontend.Variable, K)
	assignB := make([][]frontend.Variable, K)
	assignC := make([][]frontend.Variable, K)

	for i := 0; i < K; i++ {
		assignA[i] = make([]frontend.Variable, K)
		assignB[i] = make([]frontend.Variable, K)
		assignC[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignA[i][j] = A[i][j]
			assignB[i][j] = B[i][j]
			assignC[i][j] = C[i][j]
		}
	}

	assignment := &circuit.FreivaldsCircuit{
		A: assignA,
		B: assignB,
		C: assignC,
		K: K,
	}

	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("Witness creation failed: %v", err)
	}

	proveStartTime := time.Now()
	proof, err := groth16.Prove(r1csCircuit, pk, witness)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	proveTimeS := time.Since(proveStartTime).Seconds()
	fmt.Printf("✅ Prove completed in: %.6f s\n", proveTimeS)

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Public witness extraction failed: %v", err)
	}

	verifyStartTime := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("Proof verification failed: %v", err)
	}
	verifyTimeS := time.Since(verifyStartTime).Seconds()
	fmt.Printf("✅ Verify completed in: %.6f s\n", verifyTimeS)

	return utils.FreivaldsResult{
		LogK:        logK,
		Compute:     offlineTimeS,
		Constraints: numConstraints,
		Setup:       setupTimeS,
		Prove:       proveTimeS,
		Verify:      verifyTimeS,
	}
}
