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
	matrixSourceFlag := flag.String("matrix-source", config.GetString("LAMP_MATRIX_SOURCE", "auto"), "Matrix input: auto, file, or generate")
	matrixDirFlag := flag.String("matrix-dir", config.OutputDir("LAMP_MATRIX_DIR", "matrices"), "Directory containing matrices_k<K>.bin")
	repeatFlag := flag.Int("repeat", config.GetInt("FREIVALDS_REPEAT", 1), "Measurements per configuration (minimum 1)")
	flag.Parse()
	if *repeatFlag < 1 {
		log.Fatalf("repeat must be positive, got %d", *repeatFlag)
	}

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("FREIVALDS_OUTPUT_DIR", filepath.Join("benchmark", "freivalds"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	csvPath := filepath.Join(outputDir, "freivalds_benchmark_results.csv")
	writer, err := benchmark.InitFreivaldsCSV(csvPath)
	if err != nil {
		log.Fatal(err)
	}
	defer writer.Close()

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
			if err := runRepeatedExperiments(logK, onlyCompile, *matrixSourceFlag, *matrixDirFlag, *repeatFlag, writer); err != nil {
				log.Fatal(err)
			}
			fmt.Println("----------------------------------------------------------------")
		}
	} else {
		if err := runRepeatedExperiments(*logKFlag, onlyCompile, *matrixSourceFlag, *matrixDirFlag, *repeatFlag, writer); err != nil {
			log.Fatal(err)
		}
	}

	if err := writer.SaveAverages(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("🎉 All Freivalds benchmarks finished!")
}

func prepareInput(logK int, onlyCompile bool, source, dir string) (matrix.Input, error) {
	if onlyCompile {
		return matrix.Input{}, nil
	}
	return matrix.Prepare(1<<logK, source, dir)
}

func runRepeatedExperiments(logK int, onlyCompile bool, source, dir string, repeats int, writer *benchmark.FreivaldsCSV) error {
	if repeats < 1 {
		return fmt.Errorf("repeat must be positive")
	}
	input, err := prepareInput(logK, onlyCompile, source, dir)
	if err != nil {
		return err
	}
	for repeat := 1; repeat <= repeats; repeat++ {
		runtime.GC()
		res := runExperimentWithInput(logK, onlyCompile, input)
		res.Repeat = repeat
		if err := benchmark.AppendFreivaldsResultToCSV(writer, res); err != nil {
			return err
		}
	}
	return nil
}

func runExperimentWithInput(logK int, onlyCompile bool, input matrix.Input) benchmark.FreivaldsResult {
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
			LogK:         logK,
			Constraints:  nbConstraints,
			MatrixSource: "compile",
		}
	}

	// =========================================================================
	// 1. Data Preparation & Compute C = A * B
	// =========================================================================
	fmt.Println("=== 1. Preparing Matrices A, B, C ===")
	matrixComputeTime := input.Compute.Seconds()
	fmt.Printf("   Matrix input: %s (%s); load: %s; compute: %s\n", input.Source, input.Path,
		benchmark.FormatDurationSeconds(input.Load.Seconds()), benchmark.FormatDurationSeconds(matrixComputeTime))
	matA, matB, matC := input.A, input.B, input.C

	// =========================================================================
	// 2. Circuit Compilation & Groth16 Setup
	// =========================================================================
	fmt.Println("=== 2. Circuit Compilation & Setup ===")

	emptyCircuit := newFreivaldsCircuit(K)

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

	// =========================================================================
	// 3. Witness Assignment & Proof Generation
	// =========================================================================
	fmt.Println("=== 3. Generating Proof ===")
	proveSampler := benchmark.StartMemory()
	assignment := newFreivaldsCircuit(K)
	for i := 0; i < K; i++ {
		for j := 0; j < K; j++ {
			assignment.A[i][j] = matA[i][j]
			assignment.B[i][j] = matB[i][j]
			assignment.C[i][j] = matC[i][j]
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

	// =========================================================================
	// 4. Verification
	// =========================================================================
	fmt.Println("=== 4. Verifying Proof ===")

	// Public Witness 추출
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ Public witness extraction failed: %v", err)
	}

	startVerify := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("❌ Verification FAILED: %v", err)
	}
	verifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %s\n", benchmark.FormatDurationSeconds(verifyTime))

	return benchmark.FreivaldsResult{
		LogK:              logK,
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
