package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"runtime"
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
	matrixSourceFlag := flag.String("matrix-source", config.GetString("LAMP_MATRIX_SOURCE", "auto"), "Matrix input: auto, file, or generate")
	matrixDirFlag := flag.String("matrix-dir", config.OutputDir("LAMP_MATRIX_DIR", "matrices"), "Directory containing matrices_k<K>.bin")
	repeatFlag := flag.Int("repeat", config.GetInt("FREIVALDS_BATCH_REPEAT", 1), "Measurements per configuration (minimum 1)")
	flag.Parse()
	if *repeatFlag < 1 {
		log.Fatalf("repeat must be positive, got %d", *repeatFlag)
	}

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("FREIVALDS_BATCH_OUTPUT_DIR", filepath.Join("benchmark", "freivalds_batch"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	csvPath := filepath.Join(outputDir, "freivalds_batch_benchmark_results.csv")
	writer, err := benchmark.InitFreivaldsBatchCSV(csvPath)
	if err != nil {
		log.Fatal(err)
	}
	defer writer.Close()

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
				if err := runRepeatedExperiments(logK, batch, onlyCompile, *matrixSourceFlag, *matrixDirFlag, *repeatFlag, writer); err != nil {
					log.Fatal(err)
				}
			}
		}
	} else {
		if err := runRepeatedExperiments(*logKFlag, *batchFlag, onlyCompile, *matrixSourceFlag, *matrixDirFlag, *repeatFlag, writer); err != nil {
			log.Fatal(err)
		}
	}

	if err := writer.SaveAverages(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("🎉 All Freivalds batch benchmarks finished!")
}

func prepareInput(logK int, onlyCompile bool, source, dir string) (matrix.Input, error) {
	if onlyCompile {
		return matrix.Input{}, nil
	}
	return matrix.Prepare(1<<logK, source, dir)
}

func runRepeatedExperiments(logK int, batch int, onlyCompile bool, source, dir string, repeats int, writer *benchmark.FreivaldsCSV) error {
	if repeats < 1 {
		return fmt.Errorf("repeat must be positive")
	}
	if batch < 1 {
		return fmt.Errorf("batch must be positive")
	}
	input, err := prepareInput(logK, onlyCompile, source, dir)
	if err != nil {
		return err
	}
	for repeat := 1; repeat <= repeats; repeat++ {
		runtime.GC()
		res := runExperimentWithInput(logK, batch, onlyCompile, input)
		res.Repeat = repeat
		if err := benchmark.AppendFreivaldsBatchResultToCSV(writer, res); err != nil {
			return err
		}
	}
	return nil
}

func runExperimentWithInput(logK int, batch int, onlyCompile bool, input matrix.Input) benchmark.FreivaldsBatchResult {
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
			LogK:         logK,
			Batch:        batch,
			Constraints:  nbConstraints,
			MatrixSource: "compile",
		}
	}

	fmt.Println("=== 1. Preparing One Matrix Product for the Full Batch ===")
	matrixComputeTime := input.Compute.Seconds()
	fmt.Printf("   Matrix input: %s (%s); load: %s; compute: %s\n", input.Source, input.Path,
		benchmark.FormatDurationSeconds(input.Load.Seconds()), benchmark.FormatDurationSeconds(matrixComputeTime))
	// Repeat one product; all downstream encoding and proof work still uses the full batch.
	products := make([]freivaldsBatchProduct, batch)
	for i := range products {
		products[i].A, products[i].B, products[i].C = input.A, input.B, input.C
	}

	fmt.Println("=== 2. Circuit Compilation & Setup ===")
	emptyCircuit := newFreivaldsBatchCircuit(K, batch)

	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Circuit compilation failed: %v", err)
	}

	setupSampler := benchmark.StartMemory()
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("❌ Groth16 setup failed: %v", err)
	}
	setupTime := time.Since(startSetup).Seconds()
	setupMemory := setupSampler.Stop()

	numConstraints := r1csSystem.GetNbConstraints()
	fmt.Printf("   📊 Constraints: %d\n", numConstraints)

	fmt.Println("=== 3. Generating Proof ===")
	proveSampler := benchmark.StartMemory()
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
	proveMemory := proveSampler.Stop()
	fmt.Printf("   ✅ Prove Time: %s\n", benchmark.FormatDurationSeconds(proveTime))

	proofBytes, err := proof.WriteTo(io.Discard)
	if err != nil {
		log.Fatalf("❌ Proof serialization failed: %v", err)
	}
	proofSize := int(proofBytes)
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
		MatrixSource:      input.Source,
		MatrixPath:        input.Path,
		MatrixLoadTime:    input.Load.Seconds(),
		MatrixWorkers:     input.Workers,
		SetupMemory:       setupMemory,
		ProveMemory:       proveMemory,
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
