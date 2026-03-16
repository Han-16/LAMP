package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math"
	"path/filepath"
	"sync"
	"time"

	"github.com/Han-16/meow/benchmark"
	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/crypto"
	"github.com/Han-16/meow/matrix"
	"github.com/Han-16/meow/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	logKFlag := flag.Int("K", 10, "Log base 2 of K")
	rhoFlag := flag.String("rho", "1/2", "Code rate")
	LFlag := flag.Int("L", 128, "Number of unique indices L")
	allFlag := flag.Bool("all", false, "Run benchmarks")
	onlyCompileFlag := flag.Bool("OnlyCompile", false, "Only compile the circuit to get constraints")
	flag.Parse()

	outputDir := filepath.Join("../../benchmark", "benchmark_results")
	benchmark.EnsureDir(outputDir)
	csvPath := filepath.Join(outputDir, "meow_benchmark_results.csv")
	file, writer := benchmark.InitMeowCSV(csvPath)
	defer file.Close()

	if *allFlag {
		if *onlyCompileFlag {
			fmt.Println("🚀 [OnlyCompile MODE] Checking constraints for K=5 to 15...")
		} else {
			fmt.Println("🚀 [ALL MODE] Running Meow ZK benchmarks...")
		}

		for logK := 7; logK <= 20; logK++ {
			res := runExperiment(logK, *rhoFlag, *LFlag, *onlyCompileFlag)
			benchmark.AppendMeowResultToCSV(writer, res)
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag, *onlyCompileFlag)
		benchmark.AppendMeowResultToCSV(writer, res)
	}
	fmt.Println("🎉 All Meow ZK tasks finished!")
}

func runExperiment(logK int, rhoStr string, L int, onlyCompile bool) benchmark.MeowResult {
	K := 1 << logK
	N := K << 1
	if rhoStr == "1/4" {
		N = K << 2
	}
	depth := int(math.Log2(float64(N)))
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [Meow ZK Protocol] K=%d, N=%d, L=%d\n", K, N, L)

	if onlyCompile {
		fmt.Println("=== 🔍 Compiling Circuit for Constraints ===")

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
			VecX: make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
			EncX: make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
			TargetEncX: make([]frontend.Variable, L), TargetEncYZ: make([]frontend.Variable, L),
		}
		for i := 0; i < L; i++ {
			emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
			emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
			emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
		}

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("❌ Compilation failed: %v", err)
		}

		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("✅ Circuit compiled successfully! Total Constraints: %d\n", nbConstraints)

		return benchmark.MeowResult{
			LogK:        logK,
			Rho:         rhoStr,
			N:           N,
			NumQueries:  L,
			Constraints: nbConstraints,
		}
	}

	// =========================================================================
	// 0. Setup Phase
	// =========================================================================
	ck1 := crypto.SetupCommitKey(K)
	ckScalar := crypto.SetupCommitKey(1)
	encoder := crypto.NewEncoder(K, N)
	prover := protocol.NewProver(nil, ck1, encoder)

	// =========================================================================
	// 1. Compute Matrices A, B, C
	// =========================================================================
	startCompute := time.Now()
	matA := matrix.GenerateRandomMatrix(K, K)
	matB := matrix.GenerateRandomMatrix(K, K)
	matC := matrix.MatMul(matA, matB, K)
	MatrixComputeTime := time.Since(startCompute).Seconds()

	// =========================================================================
	// 2. Encode & Commit Matrices A, B, C
	// =========================================================================
	startMatCommit := time.Now()

	var encA, encB, encC [][]fr.Element
	var colsEncA, colsEncB, colsEncC [][]fr.Element
	var treeA, treeB, treeC [][]fr.Element

	var cmA, cmB, cmC fr.Element

	var leavesA, leavesB, leavesC []bn254.G1Affine
	var blA, blB, blC []fr.Element

	var wg sync.WaitGroup
	wg.Add(3)

	// Matrix A
	go func() {
		defer wg.Done()
		_, encA, _ = prover.EncodeMatrix(matA)
		colsEncA = matrix.Transpose(encA, K, N)
		treeA, cmA, leavesA, blA = prover.CommitMatrixBlinded(colsEncA, depth)
	}()

	// Matrix B
	go func() {
		defer wg.Done()
		_, encB, _ = prover.EncodeMatrix(matB)
		colsEncB = matrix.Transpose(encB, K, N)
		treeB, cmB, leavesB, blB = prover.CommitMatrixBlinded(colsEncB, depth)
	}()

	// Matrix C
	go func() {
		defer wg.Done()
		_, encC, _ = prover.EncodeMatrix(matC)
		colsEncC = matrix.Transpose(encC, K, N)
		treeC, cmC, leavesC, blC = prover.CommitMatrixBlinded(colsEncC, depth)
	}()

	wg.Wait()

	CmABC := crypto.HashElementsMiMC(cmA, cmB, cmC)
	ChallengeR := crypto.GenerateChallengeVector(CmABC, K)
	matCommitTime := time.Since(startMatCommit).Seconds()

	// =========================================================================
	// 3. Compute vector x, yz = x*B & their commitments
	// =========================================================================
	startVecCommit := time.Now()
	vecX := matrix.VecMatMul(ChallengeR, matA, K)
	vecYZ := matrix.VecMatMul(vecX, matB, K)

	_, encX, _ := encoder.Encode(vecX)
	_, encYZ, _ := encoder.Encode(vecYZ)

	treeX, cmX, leavesX, blX := prover.CommitScalarsBlinded(encX, depth, ckScalar)
	treeYZ, cmYZ, leavesYZ, blYZ := prover.CommitScalarsBlinded(encYZ, depth, ckScalar)

	CmXYZ := crypto.HashElementsMiMC(cmX, cmYZ)
	indices, _ := crypto.GenerateUniqueIndices(CmXYZ, N, L)
	vecCommitTime := time.Since(startVecCommit).Seconds()

	// =========================================================================
	// 4. Circuit Compile & Setup
	// =========================================================================
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
		VecX: make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		EncX: make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		TargetEncX: make([]frontend.Variable, L), TargetEncYZ: make([]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
	}

	r1csSystem, _ := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	nbConstraints := r1csSystem.GetNbConstraints()

	pk, vk, _ := groth16.Setup(r1csSystem)

	// =========================================================================
	// 5. Generate Proof
	// =========================================================================
	assignment := &circuit.MeowCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		Roots: [5]frontend.Variable{cmA, cmB, cmC, cmX, cmYZ}, CmABC: CmABC, CmXYZ: CmXYZ,
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		ChallengeR: make([]frontend.Variable, K), Indices: make([]frontend.Variable, L),
		VecX: make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		EncX: make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		TargetEncX: make([]frontend.Variable, L), TargetEncYZ: make([]frontend.Variable, L),
	}

	for i := 0; i < K; i++ {
		assignment.ChallengeR[i] = ChallengeR[i]
		assignment.VecX[i] = vecX[i]
		assignment.VecYZ[i] = vecYZ[i]
	}
	for i := 0; i < N; i++ {
		assignment.EncX[i] = encX[i]
		assignment.EncYZ[i] = encYZ[i]
	}

	for i, idx := range indices {
		assignment.Indices[i] = idx
		assignment.TargetEncX[i] = encX[idx]
		assignment.TargetEncYZ[i] = encYZ[idx]

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
	// 6. Off-line Proof Generation for Merkle & CPLink
	// =========================================================================
	fmt.Println("=== Generating Off-line Proofs ===")
	startOfflineProve := time.Now()

	var idxK []int
	var idx1 []int
	for i, ck := range proverWithPK.CK2 {
		if len(ck.G) == K {
			idxK = append(idxK, i)
		} else if len(ck.G) == 1 {
			idx1 = append(idx1, i)
		}
	}

	if len(idxK) != 3*L || len(idx1) != 2*L {
		log.Fatalf("❌ Commitment length mismatch: expected K:%d, 1:%d, got K:%d, 1:%d", 3*L, 2*L, len(idxK), len(idx1))
	}

	mpA := make([][]fr.Element, L)
	mpB := make([][]fr.Element, L)
	mpC := make([][]fr.Element, L)
	mpX := make([][]fr.Element, L)
	mpYZ := make([][]fr.Element, L)

	cpA := make([]crypto.CPLinkProof, L)
	cpB := make([]crypto.CPLinkProof, L)
	cpC := make([]crypto.CPLinkProof, L)
	cpX := make([]crypto.CPLinkProof, L)
	cpYZ := make([]crypto.CPLinkProof, L)

	for i, idx := range indices {
		mpA[i] = proverWithPK.GenerateMembershipProof(treeA, idx, depth)
		mpB[i] = proverWithPK.GenerateMembershipProof(treeB, idx, depth)
		mpC[i] = proverWithPK.GenerateMembershipProof(treeC, idx, depth)
		mpX[i] = proverWithPK.GenerateMembershipProof(treeX, idx, depth)
		mpYZ[i] = proverWithPK.GenerateMembershipProof(treeYZ, idx, depth)

		idxA := idxK[3*i]
		idxB := idxK[3*i+1]
		idxC := idxK[3*i+2]
		idxX := idx1[2*i]
		idxYZ := idx1[2*i+1]

		cpA[i] = crypto.ProveCPLink(colsEncA[idx], blA[idx], blindingsIn[idxA], ck1, proverWithPK.CK2[idxA])
		cpB[i] = crypto.ProveCPLink(colsEncB[idx], blB[idx], blindingsIn[idxB], ck1, proverWithPK.CK2[idxB])
		cpC[i] = crypto.ProveCPLink(colsEncC[idx], blC[idx], blindingsIn[idxC], ck1, proverWithPK.CK2[idxC])

		cpX[i] = crypto.ProveCPLink([]fr.Element{encX[idx]}, blX[idx], blindingsIn[idxX], ckScalar, proverWithPK.CK2[idxX])
		cpYZ[i] = crypto.ProveCPLink([]fr.Element{encYZ[idx]}, blYZ[idx], blindingsIn[idxYZ], ckScalar, proverWithPK.CK2[idxYZ])
	}
	offlineProveTime := time.Since(startOfflineProve).Seconds()

	// =========================================================================
	// 7. Verify All Proofs
	// =========================================================================
	fmt.Println("=== Verifying All Proofs ===")
	startVerify := time.Now()

	witness_for_verify, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ Failed to create witness for verification: %v", err)
	}
	publicWitness, _ := witness_for_verify.Public()

	startCircuitVerify := time.Now()
	if err := verifier.VerifyGroth16(circuitProof, publicWitness); err != nil {
		log.Fatalf("❌ Groth16 Verify failed: %v", err)
	}
	circuitVerifyTime := time.Since(startCircuitVerify).Seconds()

	var merkleVerifyTime float64
	var cpLinkVerifyTime float64

	var c1A, c1B, c1C, c1X, c1YZ []bn254.G1Affine
	var c2A, c2B, c2C, c2X, c2YZ []bn254.G1Affine
	var ck2A, ck2B, ck2C, ck2X, ck2YZ []crypto.CommitKey

	for i, idx := range indices {
		startMerkle := time.Now()
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
		if !verifier.VerifyMembership(cmYZ, leavesYZ[idx], mpYZ[i], idx, depth) {
			log.Fatal("❌ Merkle YZ Failed")
		}
		merkleVerifyTime += time.Since(startMerkle).Seconds()

		idxA := idxK[3*i]
		idxB := idxK[3*i+1]
		idxC := idxK[3*i+2]
		idxX := idx1[2*i]
		idxYZ := idx1[2*i+1]

		c1A = append(c1A, leavesA[idx])
		c2A = append(c2A, cmVec2[idxA])
		ck2A = append(ck2A, verifier.CK2[idxA])
		c1B = append(c1B, leavesB[idx])
		c2B = append(c2B, cmVec2[idxB])
		ck2B = append(ck2B, verifier.CK2[idxB])
		c1C = append(c1C, leavesC[idx])
		c2C = append(c2C, cmVec2[idxC])
		ck2C = append(ck2C, verifier.CK2[idxC])
		c1X = append(c1X, leavesX[idx])
		c2X = append(c2X, cmVec2[idxX])
		ck2X = append(ck2X, verifier.CK2[idxX])
		c1YZ = append(c1YZ, leavesYZ[idx])
		c2YZ = append(c2YZ, cmVec2[idxYZ])
		ck2YZ = append(ck2YZ, verifier.CK2[idxYZ])
	}

	startCpLink := time.Now()
	if !crypto.VerifyCPLinksBatched(c1A, c2A, cpA, ck1, ck2A) {
		log.Fatal("❌ Batched CPLink A Failed")
	}
	if !crypto.VerifyCPLinksBatched(c1B, c2B, cpB, ck1, ck2B) {
		log.Fatal("❌ Batched CPLink B Failed")
	}
	if !crypto.VerifyCPLinksBatched(c1C, c2C, cpC, ck1, ck2C) {
		log.Fatal("❌ Batched CPLink C Failed")
	}
	if !crypto.VerifyCPLinksBatched(c1X, c2X, cpX, ckScalar, ck2X) {
		log.Fatal("❌ Batched CPLink X Failed")
	}
	if !crypto.VerifyCPLinksBatched(c1YZ, c2YZ, cpYZ, ckScalar, ck2YZ) {
		log.Fatal("❌ Batched CPLink YZ Failed")
	}
	cpLinkVerifyTime += time.Since(startCpLink).Seconds()

	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Println("✅ ALL BLINDED ZK PROOFS VERIFIED SUCCESSFULLY!")

	totalProveTime := matCommitTime + vecCommitTime + circuitProveTime + offlineProveTime

	var buf bytes.Buffer
	circuitProof.WriteTo(&buf)
	groth16ProofSize := buf.Len()

	merkleProofSize := L * 5 * depth * 32

	cpLinkProofSize := 0
	for i := 0; i < L; i++ {
		cpLinkProofSize += 128 + (len(cpA[i].Z) * 32)
		cpLinkProofSize += 128 + (len(cpB[i].Z) * 32)
		cpLinkProofSize += 128 + (len(cpC[i].Z) * 32)
		cpLinkProofSize += 128 + (len(cpX[i].Z) * 32)
		cpLinkProofSize += 128 + (len(cpYZ[i].Z) * 32)
	}

	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize

	fmt.Printf("📊 Proof Sizes -> Groth16: %d B, Merkle: %d B, CPLink: %d B | Total: %d B\n",
		groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.MeowResult{
		LogK:              logK,
		Rho:               rhoStr,
		N:                 N,
		NumQueries:        L,
		Constraints:       nbConstraints,
		MatrixComputeTime: MatrixComputeTime,
		MatrixCommitTime:  matCommitTime,
		VectorCommitTime:  vecCommitTime,
		CircuitProveTime:  circuitProveTime,
		CPLinkProveTime:   offlineProveTime,
		TotalProveTime:    totalProveTime,
		CircuitVerifyTime: circuitVerifyTime,
		MerkleVerifyTime:  merkleVerifyTime,
		CPLinkVerifyTime:  cpLinkVerifyTime,
		TotalVerifyTime:   totalVerifyTime,
		MerkleProofSize:   merkleProofSize,
		Groth16ProofSize:  groth16ProofSize,
		CPLinkProofSize:   cpLinkProofSize,
		TotalProofSize:    totalProofSize,
	}
}
