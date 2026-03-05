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
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	logKFlag := flag.Int("K", 10, "Log base 2 of K")
	LFlag := flag.Int("L", 100, "Number of columns L")
	allFlag := flag.Bool("all", false, "Run benchmarks")
	flag.Parse()

	outputDir := filepath.Join(".", "benchmark_results")
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "cplink_benchmark_results.csv")
	file, writer := benchmark.InitCpLinkCSV(csvPath)
	defer file.Close()

	if *allFlag {
		for logK := 10; logK <= 15; logK++ {
			res := runExperiment(logK, *LFlag)
			benchmark.AppendCpLinkResultToCSV(writer, res)
		}
	} else {
		res := runExperiment(*logKFlag, *LFlag)
		benchmark.AppendCpLinkResultToCSV(writer, res)
	}
}

func runExperiment(logK int, L int) benchmark.CpLinkResult {
	K := 1 << logK
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [CP-LINK] K = 2^%d (%d), L = %d\n", logK, K, L)

	mat := matrix.GenerateRandomMatrix(L, K)

	// 서킷 초기화
	emptyCircuit := &circuit.Cp{CommittedValues: make([][]frontend.Variable, L)}
	for i := 0; i < L; i++ {
		emptyCircuit.CommittedValues[i] = make([]frontend.Variable, K)
	}
	r1csSystem, _ := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	pk, vk, _ := groth16.Setup(r1csSystem)

	// 🌟 Prover / Verifier 초기화
	ck1 := crypto.SetupCommitKey(K)
	prover := protocol.NewProver(pk, ck1, nil)
	verifier := protocol.NewVerifier(vk, ck1, prover.CK2)

	// =========================================================================
	// 1. Off-chain Commitment (외부 커밋먼트 + 난수 생성)
	// =========================================================================
	cm_vec_1 := make([]bn254.G1Affine, L)
	blindings1 := make([]fr.Element, L)
	for i := 0; i < L; i++ {
		blindings1[i].SetRandom()
		cm_vec_1[i] = crypto.PedersenCommitBlinded(mat[i], blindings1[i], ck1)
	}

	// =========================================================================
	// 2. Circuit Prove (내부 커밋먼트 및 난수 추출)
	// =========================================================================
	assignment := &circuit.Cp{CommittedValues: make([][]frontend.Variable, L)}
	for i := 0; i < L; i++ {
		assignment.CommittedValues[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignment.CommittedValues[i][j] = mat[i][j]
		}
	}
	_, cm_vec_2, blindings2, err := prover.ProveCircuit(r1csSystem, assignment)
	if err != nil {
		log.Fatalf("❌ Circuit proof failed: %v", err)
	}

	// =========================================================================
	// 3. CPLink Prove (이중 블라인딩 적용)
	// =========================================================================
	fmt.Println("=== 3. Proving CP-LINK ===")
	startCPLinkProve := time.Now()
	cpLinkProofs := make([]crypto.CPLinkProof, L)
	for i := 0; i < L; i++ {
		// 외부 난수(blindings1)와 내부 난수(blindings2)를 모두 사용
		cpLinkProofs[i] = crypto.ProveCPLink(mat[i], blindings1[i], blindings2[i], ck1, verifier.CK2[i])
	}
	cplinkProveTime := time.Since(startCPLinkProve).Seconds()

	// =========================================================================
	// 4. CPLink Verify
	// =========================================================================
	fmt.Println("=== 4. Verifying CP-LINK ===")
	startVerify := time.Now()
	for i := 0; i < L; i++ {
		isValid := crypto.VerifyCPLink(cm_vec_1[i], cm_vec_2[i], cpLinkProofs[i], ck1, verifier.CK2[i])
		if !isValid {
			log.Fatalf("❌ CP-LINK Verification FAILED at index %d!", i)
		}
	}
	verifyTime := time.Since(startVerify).Seconds()

	// Proof Size 계산: R1, R2, Z(길이 K), T1, T2 -> 총 K + 6 개의 Element
	// Byte 단위: (K + 6) * 32 * L
	proofSizeBytes := L * (K + 6) * 32

	return benchmark.CpLinkResult{
		LogK:            logK,
		NumCommitments:  L,
		CPLinkProveTime: cplinkProveTime,
		ProofSize:       proofSizeBytes,
		VerifyTime:      verifyTime,
	}
}
