package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"path/filepath"
	"time"

	"github.com/Han-16/meow/benchmark"
	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/crypto"
	"github.com/Han-16/meow/matrix"
	"github.com/Han-16/meow/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	logKFlag := flag.Int("K", 4, "Log base 2 of K")
	rhoFlag := flag.String("rho", "1/2", "Code rate")
	LFlag := flag.Int("L", 3, "Number of unique indices L")
	allFlag := flag.Bool("all", false, "Run benchmarks")
	flag.Parse()

	outputDir := filepath.Join(".", "benchmark_results")
	benchmark.EnsureDir(outputDir)
	csvPath := filepath.Join(outputDir, "meow_benchmark_results.csv")
	file, writer := benchmark.InitMeowCSV(csvPath)
	defer file.Close()

	if *allFlag {
		fmt.Println("🚀 [ALL MODE] Running Meow ZK benchmarks...")
		for logK := 4; logK <= 8; logK++ {
			res := runExperiment(logK, *rhoFlag, *LFlag)
			benchmark.AppendMeowResultToCSV(writer, res)
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag)
		benchmark.AppendMeowResultToCSV(writer, res)
	}
	fmt.Println("🎉 All Meow ZK benchmarks finished!")
}

func runExperiment(logK int, rhoStr string, L int) benchmark.MeowResult {
	K := 1 << logK
	N := K << 1
	if rhoStr == "1/4" {
		N = K << 2
	}
	depth := int(math.Log2(float64(N)))
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [Meow ZK Protocol] K=%d, N=%d, L=%d\n", K, N, L)

	startCompute := time.Now()
	matA := matrix.GenerateRandomMatrix(K, K)
	matB := matrix.GenerateRandomMatrix(K, K)
	matC := matrix.MatMul(matA, matB, K)
	computeTime := time.Since(startCompute).Seconds()

	startMatCommit := time.Now()
	ck1 := crypto.SetupCommitKey(K)      // 행렬용 키 (크기 K)
	ckScalar := crypto.SetupCommitKey(1) // 스칼라(X, Y, Z)용 키 (크기 1)
	encoder := crypto.NewEncoder(K, N)
	prover := protocol.NewProver(nil, ck1, encoder)

	_, encA, _ := prover.EncodeMatrix(matA)
	_, encB, _ := prover.EncodeMatrix(matB)
	_, encC, _ := prover.EncodeMatrix(matC)

	colsEncA := matrix.Transpose(encA, K, N)
	colsEncB := matrix.Transpose(encB, K, N)
	colsEncC := matrix.Transpose(encC, K, N)

	treeA, cmA, leavesA, blA := prover.CommitMatrixBlinded(colsEncA, depth)
	treeB, cmB, leavesB, blB := prover.CommitMatrixBlinded(colsEncB, depth)
	treeC, cmC, leavesC, blC := prover.CommitMatrixBlinded(colsEncC, depth)

	CmABC := crypto.HashElementsMiMC(cmA, cmB, cmC)
	ChallengeR := crypto.GenerateChallengeVector(CmABC, K)
	matCommitTime := time.Since(startMatCommit).Seconds()

	startVecCommit := time.Now()
	vecX := matrix.VecMatMul(ChallengeR, matA, K)
	vecY := matrix.VecMatMul(vecX, matB, K)
	vecZ := matrix.VecMatMul(ChallengeR, matC, K)

	_, encX, _ := encoder.Encode(vecX)
	_, encY, _ := encoder.Encode(vecY)
	_, encZ, _ := encoder.Encode(vecZ)

	treeX, cmX, leavesX, blX := prover.CommitScalarsBlinded(encX, depth, ckScalar)
	treeY, cmY, leavesY, blY := prover.CommitScalarsBlinded(encY, depth, ckScalar)
	treeZ, cmZ, leavesZ, blZ := prover.CommitScalarsBlinded(encZ, depth, ckScalar)

	CmXYZ := crypto.HashElementsMiMC(cmX, cmY, cmZ)
	indices, _ := crypto.GenerateUniqueIndices(CmXYZ, N, L)
	vecCommitTime := time.Since(startVecCommit).Seconds()

	fmt.Println("=== Circuit Setup & Prove ===")
	domainN := fft.NewDomain(uint64(N))
	rootsN := crypto.GetDomainRoots(domainN, N)
	weightsN := crypto.PrecomputeBarycentricWeights(rootsN)

	domainK := fft.NewDomain(uint64(K))
	rootsK := crypto.GetDomainRoots(domainK, K)
	weightsK := crypto.PrecomputeBarycentricWeights(rootsK)

	emptyCircuit := &circuit.MeowCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		ChallengeR: make([]frontend.Variable, K), Indices: make([]frontend.Variable, L),
		VecX: make([]frontend.Variable, K), VecY: make([]frontend.Variable, K), VecZ: make([]frontend.Variable, K),
		EncX: make([]frontend.Variable, N), EncY: make([]frontend.Variable, N), EncZ: make([]frontend.Variable, N),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
	}

	r1csSystem, _ := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	pk, vk, _ := groth16.Setup(r1csSystem)

	assignment := &circuit.MeowCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		Roots: [6]frontend.Variable{cmA, cmB, cmC, cmX, cmY, cmZ}, CmABC: CmABC, CmXYZ: CmXYZ,
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		ChallengeR: make([]frontend.Variable, K), Indices: make([]frontend.Variable, L),
		VecX: make([]frontend.Variable, K), VecY: make([]frontend.Variable, K), VecZ: make([]frontend.Variable, K),
		EncX: make([]frontend.Variable, N), EncY: make([]frontend.Variable, N), EncZ: make([]frontend.Variable, N),
	}

	for i := 0; i < K; i++ {
		assignment.ChallengeR[i] = ChallengeR[i]
		assignment.VecX[i] = vecX[i]
		assignment.VecY[i] = vecY[i]
		assignment.VecZ[i] = vecZ[i]
	}
	for i := 0; i < N; i++ {
		assignment.EncX[i] = encX[i]
		assignment.EncY[i] = encY[i]
		assignment.EncZ[i] = encZ[i]
	}

	for i, idx := range indices {
		assignment.Indices[i] = idx
		assignment.ColsEncA[i] = make([]frontend.Variable, K)
		assignment.ColsEncB[i] = make([]frontend.Variable, K)
		assignment.ColsEncC[i] = make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			assignment.ColsEncA[i][j] = colsEncA[idx][j]
			assignment.ColsEncB[i][j] = colsEncB[idx][j]
			assignment.ColsEncC[i][j] = colsEncC[idx][j]
		}
	}

	proverWithPK := protocol.NewProver(pk, ck1, encoder)
	verifier := protocol.NewVerifier(vk, ck1, proverWithPK.CK2)

	startCircuitProve := time.Now()
	circuitProof, cmVec2, blindingsIn, err := proverWithPK.ProveCircuit(r1csSystem, assignment)
	if err != nil {
		log.Fatalf("❌ Circuit proof failed: %v", err)
	}
	circuitProveTime := time.Since(startCircuitProve).Seconds()

	// =========================================================================
	// 5. 오프체인 증명 생성 (Gnark 정렬 법칙이 적용된 인덱싱)
	// =========================================================================
	fmt.Println("=== Generating Off-chain Proofs ===")
	startOffchainProve := time.Now()

	mpA := make([][]fr.Element, L)
	mpB := make([][]fr.Element, L)
	mpC := make([][]fr.Element, L)
	mpX := make([][]fr.Element, L)
	mpY := make([][]fr.Element, L)
	mpZ := make([][]fr.Element, L)

	cpA := make([]crypto.CPLinkProof, L)
	cpB := make([]crypto.CPLinkProof, L)
	cpC := make([]crypto.CPLinkProof, L)
	cpX := make([]crypto.CPLinkProof, L)
	cpY := make([]crypto.CPLinkProof, L)
	cpZ := make([]crypto.CPLinkProof, L)

	for i, idx := range indices {
		mpA[i] = proverWithPK.GenerateMembershipProof(treeA, idx, depth)
		mpB[i] = proverWithPK.GenerateMembershipProof(treeB, idx, depth)
		mpC[i] = proverWithPK.GenerateMembershipProof(treeC, idx, depth)
		mpX[i] = proverWithPK.GenerateMembershipProof(treeX, idx, depth)
		mpY[i] = proverWithPK.GenerateMembershipProof(treeY, idx, depth)
		mpZ[i] = proverWithPK.GenerateMembershipProof(treeZ, idx, depth)

		// 🌟 Gnark가 정렬해놓은 커밋 배열의 정확한 위치 (Magic Formula)
		idxA := i
		idxB := L + i
		idxC := 2*L + i

		// xFlat, yFlat, zFlat은 3L, 3L+1, 3L+2에 위치하므로, Target 스칼라값들은 3L+3부터 시작합니다.
		idxX := 3*L + 3 + 3*i
		idxY := 3*L + 3 + 3*i + 1
		idxZ := 3*L + 3 + 3*i + 2

		fmt.Println("Generating CPLink proofs for index", idx)
		cpA[i] = crypto.ProveCPLink(colsEncA[idx], blA[idx], blindingsIn[idxA], ck1, proverWithPK.CK2[idxA])
		fmt.Println("apA[i] generated")
		cpB[i] = crypto.ProveCPLink(colsEncB[idx], blB[idx], blindingsIn[idxB], ck1, proverWithPK.CK2[idxB])
		fmt.Println("cpB[i] generated")
		cpC[i] = crypto.ProveCPLink(colsEncC[idx], blC[idx], blindingsIn[idxC], ck1, proverWithPK.CK2[idxC])
		fmt.Println("cpC[i] generated")

		cpX[i] = crypto.ProveCPLink([]fr.Element{encX[idx]}, blX[idx], blindingsIn[idxX], ckScalar, proverWithPK.CK2[idxX])
		fmt.Println("cpX[i] generated")
		cpY[i] = crypto.ProveCPLink([]fr.Element{encY[idx]}, blY[idx], blindingsIn[idxY], ckScalar, proverWithPK.CK2[idxY])
		fmt.Println("cpY[i] generated")
		cpZ[i] = crypto.ProveCPLink([]fr.Element{encZ[idx]}, blZ[idx], blindingsIn[idxZ], ckScalar, proverWithPK.CK2[idxZ])
		fmt.Println("cpZ[i] generated")
	}
	offchainProveTime := time.Since(startOffchainProve).Seconds()

	// =========================================================================
	// 6. 전체 검증
	// =========================================================================
	fmt.Println("=== Verifying All Proofs ===")
	startVerify := time.Now()

	witness, _ := frontend.NewWitness(assignment, field)
	publicWitness, _ := witness.Public()
	if err := verifier.VerifyGroth16(circuitProof, publicWitness); err != nil {
		log.Fatalf("❌ Groth16 Verify failed: %v", err)
	}

	for i, idx := range indices {
		if !verifier.VerifyMembership(cmA, leavesA[idx], mpA[i], idx, depth) {
			log.Fatal("❌ Merkle A Failed")
		}
		if !verifier.VerifyMembership(cmB, leavesB[idx], mpB[i], idx, depth) {
			log.Fatal("❌ Merkle B Failed")
		}
		if !verifier.VerifyMembership(cmC, leavesC[idx], mpC[i], idx, depth) {
			log.Fatal("❌ Merkle C Failed")
		}
		if !verifier.VerifyMembership(cmX, leavesX[idx], mpX[i], idx, depth) {
			log.Fatal("❌ Merkle X Failed")
		}
		if !verifier.VerifyMembership(cmY, leavesY[idx], mpY[i], idx, depth) {
			log.Fatal("❌ Merkle Y Failed")
		}
		if !verifier.VerifyMembership(cmZ, leavesZ[idx], mpZ[i], idx, depth) {
			log.Fatal("❌ Merkle Z Failed")
		}

		// 🌟 검증할 때도 정확한 매핑 인덱스 사용
		idxA := i
		idxB := L + i
		idxC := 2*L + i
		idxX := 3*L + 3 + 3*i
		idxY := 3*L + 3 + 3*i + 1
		idxZ := 3*L + 3 + 3*i + 2

		if !crypto.VerifyCPLink(leavesA[idx], cmVec2[idxA], cpA[i], ck1, verifier.CK2[idxA]) {
			log.Fatal("❌ CPLink A Failed")
		}
		if !crypto.VerifyCPLink(leavesB[idx], cmVec2[idxB], cpB[i], ck1, verifier.CK2[idxB]) {
			log.Fatal("❌ CPLink B Failed")
		}
		if !crypto.VerifyCPLink(leavesC[idx], cmVec2[idxC], cpC[i], ck1, verifier.CK2[idxC]) {
			log.Fatal("❌ CPLink C Failed")
		}
		if !crypto.VerifyCPLink(leavesX[idx], cmVec2[idxX], cpX[i], ckScalar, verifier.CK2[idxX]) {
			log.Fatal("❌ CPLink X Failed")
		}
		if !crypto.VerifyCPLink(leavesY[idx], cmVec2[idxY], cpY[i], ckScalar, verifier.CK2[idxY]) {
			log.Fatal("❌ CPLink Y Failed")
		}
		if !crypto.VerifyCPLink(leavesZ[idx], cmVec2[idxZ], cpZ[i], ckScalar, verifier.CK2[idxZ]) {
			log.Fatal("❌ CPLink Z Failed")
		}
	}
	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Println("✅ ALL BLINDED ZK PROOFS VERIFIED SUCCESSFULLY!")

	totalProveTime := matCommitTime + vecCommitTime + circuitProveTime + offchainProveTime

	return benchmark.MeowResult{
		LogK:             logK,
		Rho:              rhoStr,
		N:                N,
		NumQueries:       L,
		ComputeTime:      computeTime,
		MatrixCommitTime: matCommitTime,
		VectorCommitTime: vecCommitTime,
		CircuitProveTime: circuitProveTime,
		CPLinkProveTime:  offchainProveTime,
		TotalProveTime:   totalProveTime,
		TotalVerifyTime:  totalVerifyTime,
	}
}
