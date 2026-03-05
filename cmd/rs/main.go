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
	"github.com/Han-16/meow/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	logKFlag := flag.Int("K", 10, "Log base 2 of K")
	rhoFlag := flag.String("rho", "1/2", "Code rate")
	allFlag := flag.Bool("all", false, "Run benchmarks")
	flag.Parse()

	outputDir := filepath.Join(".", "benchmark_results")
	benchmark.EnsureDir(outputDir)
	csvPath := filepath.Join(outputDir, "reed_solomon_benchmark_results.csv")
	file, writer := benchmark.InitCSV(csvPath)
	defer file.Close()

	if *allFlag {
		rhos := []string{"1/2", "1/4"}
		for logK := 10; logK <= 20; logK++ {
			for _, r := range rhos {
				res := runExperiment(logK, r)
				benchmark.AppendResultToCSV(writer, res)
			}
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag)
		benchmark.AppendResultToCSV(writer, res)
	}
}

func runExperiment(logK int, rhoStr string) benchmark.ReedSolomonResult {
	K := 1 << logK
	N := K << 1
	if rhoStr == "1/4" {
		N = K << 2
	}

	fmt.Printf("🔥 [RS] K = 2^%d (%d), N = %d, rho = %s\n", logK, K, N, rhoStr)

	field := ecc.BN254.ScalarField()

	// Precompute
	startPre := time.Now()
	domainN := fft.NewDomain(uint64(N))
	rootsN := crypto.GetDomainRoots(domainN, N)
	weightsN := crypto.PrecomputeBarycentricWeights(rootsN)
	preTime := time.Since(startPre).Seconds()

	// Circuit Setup
	emptyCircuit := &circuit.RSCircuit{
		K: K, N: N, DomainN: rootsN, WeightsN: weightsN,
		Message: make([]frontend.Variable, K), CodewordValues: make([]frontend.Variable, N),
	}
	r1csCircuit, _ := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	pk, vk, _ := groth16.Setup(r1csCircuit)

	// 🌟 Prover / Verifier 초기화 (RS는 CommitKey 불필요)
	prover := protocol.NewProver(pk, crypto.CommitKey{}, crypto.NewEncoder(K, N))
	verifier := protocol.NewVerifier(vk, crypto.CommitKey{}, nil)

	// 1. Encoding (Prover 활용)
	startEnc := time.Now()
	x := make([]fr.Element, K)
	for j := 0; j < K; j++ {
		x[j].SetRandom()
	}

	coeffs, enc, err := prover.Encoder.Encode(x)
	if err != nil {
		log.Fatalf("Encoding failed: %v", err)
	}
	encTime := time.Since(startEnc).Seconds()

	// 2. Prove Circuit (Prover 활용)
	assignCoeffs := make([]frontend.Variable, K)
	assignEncoded := make([]frontend.Variable, N)
	for j := 0; j < K; j++ {
		assignCoeffs[j] = coeffs[j]
	}
	for j := 0; j < N; j++ {
		assignEncoded[j] = enc[j]
	}

	assignment := &circuit.RSCircuit{
		K: K, N: N, DomainN: rootsN, WeightsN: weightsN,
		Message: assignCoeffs, CodewordValues: assignEncoded,
	}

	startProve := time.Now()
	proof, _, _, err := prover.ProveCircuit(r1csCircuit, assignment)
	if err != nil {
		log.Fatalf("Proof failed: %v", err)
	}
	proveTime := time.Since(startProve).Seconds()

	// 3. Verify Circuit (Verifier 활용)
	startVerify := time.Now()
	witness, _ := frontend.NewWitness(assignment, field)
	publicWitness, _ := witness.Public()

	err = verifier.VerifyGroth16(proof, publicWitness)
	if err != nil {
		log.Fatalf("Verify failed: %v", err)
	}
	verifyTime := time.Since(startVerify).Seconds()

	return benchmark.ReedSolomonResult{
		LogK:        logK,
		Rho:         rhoStr,
		Precompute:  preTime,
		Encoding:    encTime,
		Constraints: r1csCircuit.GetNbConstraints(),
		Setup:       0, // Setup 측정 시간 원할 시 추가 가능
		Prove:       proveTime,
		Verify:      verifyTime,
	}
}
