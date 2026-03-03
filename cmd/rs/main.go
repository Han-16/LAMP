package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/rs"
	"github.com/Han-16/meow/utils"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// Command line flags
	logKFlag := flag.Int("K", 10, "Log base 2 of K (e.g., 10 for K=1024)")
	rhoFlag := flag.String("rho", "1/2", "Code rate: '1/2' or '1/4'")
	allFlag := flag.Bool("all", false, "Run benchmarks for K=10..20 and rho=1/2, 1/4")

	flag.Parse()

	// 1. Init CSV for benchmark results
	file, writer := utils.InitCSV("benchmark_results.csv")
	defer file.Close()

	// 2. Run benchmarks
	if *allFlag {
		fmt.Println("🚀 [ALL MODE] Running benchmarks: K from 2^10 to 2^20, rho in {1/2, 1/4}")
		rhos := []string{"1/2", "1/4"}
		for logK := 10; logK <= 20; logK++ {
			for _, r := range rhos {
				res := runExperiment(logK, r)

				utils.AppendResultToCSV(writer, res)

				fmt.Println("----------------------------------------------------------------")
			}
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag)
		utils.AppendResultToCSV(writer, res)
	}

	fmt.Println("🎉 All benchmarks finished successfully!")
}

func runExperiment(logK int, rhoStr string) utils.BenchmarkResult {
	K := 1 << logK
	var N int

	switch rhoStr {
	case "1/2":
		N = K << 1
	case "1/4":
		N = K << 2
	default:
		log.Fatalf("❌ Invalid rho value: %s. Use '1/2' or '1/4'", rhoStr)
	}

	fmt.Printf("🔥 Experiment: K = 2^%d (%d), N = %d, rho = %s\n", logK, K, N, rhoStr)

	// ------------------------------------------------------------------------
	// 0. Precompute
	// ------------------------------------------------------------------------
	fmt.Printf("=== 0. Precompute Barycentric Weights ===\n")
	field := ecc.BN254.ScalarField()
	startTime := time.Now()

	domainN := fft.NewDomain(uint64(N))
	rootsN := rs.GetDomainRoots(domainN, N)
	weightsN := rs.PrecomputeBarycentricWeights(rootsN)

	precomputeTimeS := time.Since(startTime).Seconds()
	fmt.Printf("✅ Precomputation completed in: %.6f s\n", precomputeTimeS)

	// ------------------------------------------------------------------------
	// 1. Encoding
	// ------------------------------------------------------------------------
	fmt.Println("=== 1. Encoding Data with Reed-Solomon Code (Offline) ===")
	startTime = time.Now()
	encoder := rs.NewEncoder(K, N)

	x := make([]fr.Element, K)
	for j := 0; j < K; j++ {
		x[j].SetRandom()
	}

	coeffs, enc, err := encoder.Encode(x)
	if err != nil {
		log.Fatalf("Encoding failed: %v", err)
	}
	encodingTimeS := time.Since(startTime).Seconds()
	fmt.Printf("✅ Encoding completed in: %.6f s\n", encodingTimeS)

	// ------------------------------------------------------------------------
	// 2. Circuit Setup
	// ------------------------------------------------------------------------
	fmt.Println("=== 2. Circuit Setup (Compile & Setup) ===")
	startTime = time.Now()

	emptyCoeffs := make([]frontend.Variable, K)
	emptyEncoded := make([]frontend.Variable, N)

	emptyCircuit := &circuit.RSCircuit{
		K:              K,
		N:              N,
		DomainN:        rootsN,
		WeightsN:       weightsN,
		Message:        emptyCoeffs,
		CodewordValues: emptyEncoded,
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
	fmt.Printf("✅ Setup completed in: %.6f s\n", time.Since(startTime).Seconds())

	// ------------------------------------------------------------------------
	// 3. Prove & Verify
	// ------------------------------------------------------------------------
	fmt.Println("=== 3. Prove & Verify ===")
	assignCoeffs := make([]frontend.Variable, K)
	assignEncoded := make([]frontend.Variable, N)

	for j := 0; j < K; j++ {
		assignCoeffs[j] = coeffs[j]
	}
	for j := 0; j < N; j++ {
		assignEncoded[j] = enc[j]
	}

	assignment := &circuit.RSCircuit{
		K:              K,
		N:              N,
		DomainN:        rootsN,
		WeightsN:       weightsN,
		Message:        assignCoeffs,
		CodewordValues: assignEncoded,
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
	fmt.Printf("✅ Prove completed in: %.6f s\n", time.Since(proveStartTime).Seconds())

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("Public witness extraction failed: %v", err)
	}

	verifyStartTime := time.Now()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatalf("Proof verification failed: %v", err)
	} else {
		fmt.Printf("✅ Verify completed in: %.6f s\n", time.Since(verifyStartTime).Seconds())
	}

	return utils.BenchmarkResult{
		LogK:        logK,
		Rho:         rhoStr,
		Precompute:  precomputeTimeS,
		Encoding:    encodingTimeS,
		Constraints: numConstraints,
	}
}
