package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"path/filepath"
	"sync"
	"time"

	"github.com/Han-16/meow/benchmark"
	"github.com/Han-16/meow/crypto"
	"github.com/Han-16/meow/matrix"
	"github.com/Han-16/meow/protocol"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func main() {
	logKFlag := flag.Int("K", 10, "Log base 2 of K (e.g., 10 for K=1024)")
	rhoFlag := flag.String("rho", "1/2", "Code rate: '1/2' or '1/4'")
	LFlag := flag.Int("L", 100, "Number of random indices to extract")
	allFlag := flag.Bool("all", false, "Run benchmarks for K=10..15 and rho=1/2, 1/4")
	flag.Parse()

	outputDir := filepath.Join(".", "benchmark_results")
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("Failed to create directory: %v", err)
	}

	csvPath := filepath.Join(outputDir, "membership_benchmark_results.csv")
	file, writer := benchmark.InitMembershipCSV(csvPath)
	defer file.Close()

	if *allFlag {
		fmt.Println("🚀 [ALL MODE] Running benchmarks: K from 2^10 to 2^15, rho in {1/2, 1/4}")
		rhos := []string{"1/2", "1/4"}
		for logK := 10; logK <= 15; logK++ {
			for _, r := range rhos {
				res := runExperiment(logK, r, *LFlag)
				benchmark.AppendMembershipResultToCSV(writer, res)
				fmt.Println("----------------------------------------------------------------")
			}
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag)
		benchmark.AppendMembershipResultToCSV(writer, res)
	}

	fmt.Println("🎉 All Membership benchmarks finished!")
}

func runExperiment(logK int, rhoStr string, L int) benchmark.MembershipResult {
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

	depth := int(math.Log2(float64(N)))

	fmt.Printf("🔥 [Membership] K = 2^%d (%d), rho = %s, N = %d, L = %d\n", logK, K, rhoStr, N, L)

	// 1. 초기 데이터 생성 및 인코딩
	matrixKxK := matrix.GenerateRandomMatrix(K, K)

	ck := crypto.SetupCommitKey(K)
	prover := protocol.NewProver(nil, ck, crypto.NewEncoder(K, N))
	verifier := protocol.NewVerifier(nil, ck, nil)

	_, matrixKxN, err := prover.EncodeMatrix(matrixKxK)
	if err != nil {
		log.Fatalf("❌ RS Encoding failed: %v", err)
	}
	columnsNxK := matrix.Transpose(matrixKxN, K, N)

	// =========================================================================
	// 2. 시간 분리 측정 1: Pedersen Commitments (병렬 처리)
	// =========================================================================
	fmt.Println("=== 1. Generating Pedersen Commitments ===")
	startPed := time.Now()
	commitments := make([]bn254.G1Affine, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			commitments[idx] = prover.CommitVector(columnsNxK[idx])
		}(i)
	}
	wg.Wait()
	pedTime := time.Since(startPed).Seconds()

	// =========================================================================
	// 3. 시간 분리 측정 2: Merkle Tree Build
	// =========================================================================
	fmt.Println("=== 2. Building Merkle Tree ===")
	startTree := time.Now()
	tree, cm := prover.BuildMerkleTree(commitments, depth)
	treeTime := time.Since(startTree).Seconds()

	indices, err := crypto.GenerateUniqueIndices(cm, N, L)
	if err != nil {
		log.Fatalf("❌ Failed to generate indices: %v", err)
	}

	// =========================================================================
	// 4. 시간 분리 측정 3: Proof Path Extraction (경로 추출)
	// =========================================================================
	fmt.Println("=== 3. Extracting Proof Paths ===")
	startPathExtract := time.Now()
	proofs := make([][]fr.Element, L)
	for i, idx := range indices {
		proofs[i] = prover.GenerateMembershipProof(tree, idx, depth)
	}
	pathExtractTime := time.Since(startPathExtract).Seconds()

	totalProveTime := pedTime + treeTime + pathExtractTime

	// =========================================================================
	// 5. 시간 분리 측정 4: Verification
	// =========================================================================
	fmt.Println("=== 4. Verifying Proofs ===")
	startVerify := time.Now()
	for i, idx := range indices {
		isValid := verifier.VerifyMembership(cm, commitments[idx], proofs[i], idx, depth)
		if !isValid {
			log.Fatalf("❌ Verification FAILED for index %d!", idx)
		}
	}
	verifyTime := time.Since(startVerify).Seconds()

	// fr.Element 1개 = 32 Bytes 기준으로 바이트 단위 변환
	proofSizeBytes := L * depth * 32

	return benchmark.MembershipResult{
		LogK:                logK,
		Rho:                 rhoStr,
		N:                   N,
		Height:              depth,
		NumQueries:          L,
		PedCommitTime:       pedTime,
		MerkleTreeBuildTime: treeTime,
		ProofSize:           proofSizeBytes,
		ProveTime:           totalProveTime,
		VerifyTime:          verifyTime,
	}
}
