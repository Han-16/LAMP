package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"example.com/lamp/benchmark"
	"example.com/lamp/circuit"
	"example.com/lamp/config"
	"example.com/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type freivaldsBatchProduct struct {
	A, B, C [][]fr.Element
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	logKFlag := flag.Int("K", config.GetInt("FREIVALDS_BATCH_LOG_K", 7), "Log base 2 of K")
	batchFlag := flag.Int("batch", config.GetInt("FREIVALDS_BATCH_SIZE", 5), "Number of matrix multiplications in the batch")
	allFlag := flag.Bool("all", config.GetBool("FREIVALDS_BATCH_ALL", false), "Run benchmark range over logK")
	batchRangeFlag := flag.Bool("batch-range", config.GetBool("FREIVALDS_BATCH_RANGE", false), "Run benchmark range over batch sizes")
	fromFlag := flag.Int("from", config.GetInt("FREIVALDS_BATCH_LOG_K_FROM", 7), "First logK when -all is enabled")
	toFlag := flag.Int("to", config.GetInt("FREIVALDS_BATCH_LOG_K_TO", 13), "Last logK when -all is enabled")
	batchFromFlag := flag.Int("batch-from", config.GetInt("FREIVALDS_BATCH_FROM", 1), "First batch size when -batch-range is enabled")
	batchToFlag := flag.Int("batch-to", config.GetInt("FREIVALDS_BATCH_TO", 10), "Last batch size when -batch-range is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("FREIVALDS_BATCH_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("FREIVALDS_BATCH_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("FREIVALDS_BATCH_OUTPUT_DIR", filepath.Join("benchmark", "freivalds_batch"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	csvPath := filepath.Join(outputDir, "freivalds_batch_benchmark_results.csv")
	file, writer := benchmark.InitFreivaldsBatchCSV(csvPath)
	defer file.Close()

	runLogKFrom, runLogKTo := *logKFlag, *logKFlag
	if *allFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid logK range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		runLogKFrom, runLogKTo = *fromFlag, *toFlag
	}

	runBatchFrom, runBatchTo := *batchFlag, *batchFlag
	if *batchRangeFlag {
		if *batchFromFlag > *batchToFlag {
			log.Fatalf("invalid batch range: from=%d, to=%d", *batchFromFlag, *batchToFlag)
		}
		runBatchFrom, runBatchTo = *batchFromFlag, *batchToFlag
	}

	if *allFlag || *batchRangeFlag {
		if onlyCompile {
			fmt.Printf("🚀 [OnlyCompile MODE] Checking Freivalds batch constraints for logK=%d..%d, batch=%d..%d\n", runLogKFrom, runLogKTo, runBatchFrom, runBatchTo)
		} else {
			fmt.Printf("🚀 [RANGE MODE] Running Freivalds batch benchmarks for logK=%d..%d, batch=%d..%d\n", runLogKFrom, runLogKTo, runBatchFrom, runBatchTo)
		}
		for logK := runLogKFrom; logK <= runLogKTo; logK++ {
			for batch := runBatchFrom; batch <= runBatchTo; batch++ {
				res := runExperiment(logK, batch, onlyCompile)
				benchmark.AppendFreivaldsBatchResultToCSV(writer, res)
			}
		}
	} else {
		res := runExperiment(*logKFlag, *batchFlag, onlyCompile)
		benchmark.AppendFreivaldsBatchResultToCSV(writer, res)
	}

	fmt.Println("🎉 All Freivalds batch benchmarks finished!")
}

func runExperiment(logK int, batch int, onlyCompile bool) benchmark.FreivaldsBatchResult {
	if batch <= 0 {
		log.Fatalf("batch must be positive, got %d", batch)
	}

	K := 1 << logK
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [Freivalds Batch] logK=%d, K=%d (%d x %d Matrix), batch=%d\n", logK, K, K, K, batch)

	if onlyCompile {
		fmt.Println("=== 🔍 Compiling Freivalds Batch Circuit for Constraints ===")
		emptyCircuit := newFreivaldsBatchCircuit(K, batch)

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("❌ Circuit compilation failed: %v", err)
		}

		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("✅ Circuit compiled successfully! Total Constraints: %d\n", nbConstraints)

		return benchmark.FreivaldsBatchResult{
			LogK:        logK,
			Batch:       batch,
			Constraints: nbConstraints,
		}
	}

	fmt.Println("=== 1. Generating Matrices and Computing C_i = A_i * B_i ===")
	products := make([]freivaldsBatchProduct, batch)
	for i := range products {
		products[i].A = matrix.GenerateRandomMatrix(K, K)
		products[i].B = matrix.GenerateRandomMatrix(K, K)
	}

	startCompute := time.Now()
	for i := range products {
		products[i].C = matrix.MatMul(products[i].A, products[i].B, K)
	}
	matrixComputeTime := time.Since(startCompute).Seconds()
	fmt.Printf("   ✅ Matrix Compute Time: %.2f s\n", matrixComputeTime)

	fmt.Println("=== 2. Circuit Compilation & Setup ===")
	emptyCircuit := newFreivaldsBatchCircuit(K, batch)

	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Circuit compilation failed: %v", err)
	}

	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("❌ Groth16 setup failed: %v", err)
	}
	setupTime := time.Since(startSetup).Seconds()

	numConstraints := r1csSystem.GetNbConstraints()
	fmt.Printf("   📊 Constraints: %d\n", numConstraints)

	fmt.Println("=== 3. Generating Proof ===")
	assignment := newFreivaldsBatchCircuit(K, batch)
	for b := 0; b < batch; b++ {
		for i := 0; i < K; i++ {
			for j := 0; j < K; j++ {
				assignment.A[b][i][j] = products[b].A[i][j]
				assignment.B[b][i][j] = products[b].B[i][j]
				assignment.C[b][i][j] = products[b].C[i][j]
			}
		}
	}

	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ Witness generation failed: %v", err)
	}
	startProve := time.Now()
	proof, err := groth16.Prove(r1csSystem, pk, witness)
	if err != nil {
		log.Fatalf("❌ Proof generation failed: %v", err)
	}
	proveTime := time.Since(startProve).Seconds()
	fmt.Printf("   ✅ Prove Time: %s\n", benchmark.FormatDurationSeconds(proveTime))

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		log.Fatalf("❌ Proof serialization failed: %v", err)
	}
	proofSize := proofBuf.Len()
	fmt.Printf("   📦 Proof Size: %d B\n", proofSize)

	fmt.Println("=== 4. Verifying Proof ===")
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ Public witness extraction failed: %v", err)
	}

	startVerify := time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatalf("❌ Verification FAILED: %v", err)
	}
	verifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %s\n", benchmark.FormatDurationSeconds(verifyTime))

	return benchmark.FreivaldsBatchResult{
		LogK:              logK,
		Batch:             batch,
		MatrixComputeTime: matrixComputeTime,
		Constraints:       numConstraints,
		SetupTime:         setupTime,
		ProveTime:         proveTime,
		VerifyTime:        verifyTime,
		ProofSize:         proofSize,
	}
}

func newFreivaldsBatchCircuit(K, batch int) *circuit.FreivaldsBatchCircuit {
	c := &circuit.FreivaldsBatchCircuit{
		A: make([][][]frontend.Variable, batch),
		B: make([][][]frontend.Variable, batch),
		C: make([][][]frontend.Variable, batch),
		K: K,
	}
	for b := 0; b < batch; b++ {
		c.A[b] = make([][]frontend.Variable, K)
		c.B[b] = make([][]frontend.Variable, K)
		c.C[b] = make([][]frontend.Variable, K)
		for i := 0; i < K; i++ {
			c.A[b][i] = make([]frontend.Variable, K)
			c.B[b][i] = make([]frontend.Variable, K)
			c.C[b][i] = make([]frontend.Variable, K)
		}
	}
	return c
}
