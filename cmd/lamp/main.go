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

	"example.com/lamp/benchmark"
	"example.com/lamp/circuit"
	"example.com/lamp/config"
	"example.com/lamp/crypto"
	"example.com/lamp/matrix"
	"example.com/lamp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	linkerQALink = "qa_link"
)

const (
	merkleMulti = "multi"

	challengeBLabel uint64 = 1
	rsPointBLabel   uint64 = 3
)

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	logKFlag := flag.Int("K", config.GetInt("LAMP_LOG_K", 10), "Log base 2 of K")
	rhoFlag := flag.String("rho", config.GetString("LAMP_RHO", "1/2"), "Code rate")
	LFlag := flag.Int("L", config.GetInt("LAMP_L", 128), "Number of unique indices L")
	allFlag := flag.Bool("all", config.GetBool("LAMP_ALL", false), "Run benchmark range")
	fromFlag := flag.Int("from", config.GetInt("LAMP_LOG_K_FROM", 7), "First logK when -all is enabled")
	toFlag := flag.Int("to", config.GetInt("LAMP_LOG_K_TO", 20), "Last logK when -all is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("LAMP_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("LAMP_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("LAMP_OUTPUT_DIR", filepath.Join("benchmark", "lamp"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "lamp_benchmark_results.csv")
	file, writer := benchmark.InitLAMPCSV(csvPath)
	defer file.Close()

	if *allFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid logK range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		if onlyCompile {
			fmt.Printf("🚀 [OnlyCompile MODE] Checking constraints for logK=%d..%d...\n", *fromFlag, *toFlag)
		} else {
			fmt.Printf("🚀 [ALL MODE] Running LAMP ZK benchmarks for logK=%d..%d...\n", *fromFlag, *toFlag)
		}

		for logK := *fromFlag; logK <= *toFlag; logK++ {
			res := runExperiment(logK, *rhoFlag, *LFlag, onlyCompile)
			benchmark.AppendLAMPResultToCSV(writer, res)
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag, onlyCompile)
		benchmark.AppendLAMPResultToCSV(writer, res)
	}
	fmt.Println("🎉 All LAMP ZK tasks finished!")
}

func runExperiment(logK int, rhoStr string, L int, onlyCompile bool) benchmark.LAMPResult {
	merkle := merkleMulti
	K := 1 << logK
	var N int
	switch rhoStr {
	case "1/2":
		N = K << 1
	case "1/4":
		N = K << 2
	case "1/8":
		N = K << 3
	default:
		log.Fatalf("unsupported rho %q; use 1/2, 1/4, or 1/8", rhoStr)
	}
	if L > N {
		log.Fatalf("L=%d exceeds codeword length N=%d", L, N)
	}
	depth := int(math.Log2(float64(N)))
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [LAMP ZK Protocol] logK=%d, K=%d, N=%d, L=%d, linker=%s, merkle=%s\n", logK, K, N, L, linkerQALink, merkle)

	if onlyCompile {
		fmt.Println("=== 🔍 Compiling Circuit for Constraints ===")

		domainN := fft.NewDomain(uint64(N))
		rootsN := crypto.GetDomainRoots(domainN, N)
		weightsN := crypto.PrecomputeBarycentricWeights(rootsN)

		domainK := fft.NewDomain(uint64(K))
		rootsK := crypto.GetDomainRoots(domainK, K)
		weightsK := crypto.PrecomputeBarycentricWeights(rootsK)

		emptyCircuit := &circuit.LAMPCircuit{
			K: K, N: N, Depth: depth,
			DomainK: rootsK, WeightsK: weightsK,
			DomainN: rootsN, WeightsN: weightsN,
			ColsEncABC: make([][]frontend.Variable, L),
			Indices:    make([]frontend.Variable, L),
			VecX:       make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
			VecBTest: make([]frontend.Variable, K),
			EncX:     make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
			EncBTest:         make([]frontend.Variable, N),
			QueriedEncValues: make([][]frontend.Variable, L),
		}
		for i := 0; i < L; i++ {
			emptyCircuit.ColsEncABC[i] = make([]frontend.Variable, 3*K)
			emptyCircuit.QueriedEncValues[i] = make([]frontend.Variable, 3)
		}

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("❌ Compilation failed: %v", err)
		}

		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("✅ Circuit compiled successfully! Total Constraints: %d\n", nbConstraints)

		return benchmark.LAMPResult{
			LogK:            logK,
			Rho:             rhoStr,
			Linker:          linkerQALink,
			Merkle:          merkle,
			N:               N,
			NumQueries:      L,
			Constraints:     nbConstraints,
			PeakMemoryBytes: benchmark.PeakRSSBytes(),
		}
	}

	// =========================================================================
	// 0. Setup Phase
	// =========================================================================
	var protocolSetupTime float64
	var circuitSetupTime float64
	var cpLinkSetupTime float64
	startProtocolSetup := time.Now()
	ckABC := crypto.SetupCommitKey(3 * K)
	ckXYZ := crypto.SetupCommitKey(3)
	encoder := crypto.NewEncoder(K, N)
	protocolSetupTime += time.Since(startProtocolSetup).Seconds()

	// =========================================================================
	// 1. Compute Matrices A, B, C
	// =========================================================================
	matA := matrix.GenerateRandomMatrix(K, K)
	matB := matrix.GenerateRandomMatrix(K, K)
	startCompute := time.Now()
	matC := matrix.MatMul(matA, matB, K)
	matrixComputeTime := time.Since(startCompute).Seconds()
	fmt.Printf("   ✅ Matrix Compute Time: %.2f s\n", matrixComputeTime)

	// =========================================================================
	// 2. Encode & Commit Matrices A, B, C
	// =========================================================================
	startMatCommit := time.Now()

	var colsEncA, colsEncB, colsEncC [][]fr.Element
	var errA, errB, errC error
	var treeABC [][]fr.Element
	var rootABC fr.Element
	var leavesABC []bn254.G1Affine
	var blABC []fr.Element

	var wg sync.WaitGroup
	wg.Add(3)
	startMatrixEncoding := time.Now()

	// Matrix A
	go func() {
		defer wg.Done()
		colsEncA, errA = encoder.EncodeRowsToColumns(matA)
	}()

	// Matrix B
	go func() {
		defer wg.Done()
		colsEncB, errB = encoder.EncodeRowsToColumns(matB)
	}()

	// Matrix C
	go func() {
		defer wg.Done()
		colsEncC, errC = encoder.EncodeRowsToColumns(matC)
	}()

	wg.Wait()
	matrixEncodingTime := time.Since(startMatrixEncoding).Seconds()
	if errA != nil || errB != nil || errC != nil {
		log.Fatalf("❌ Matrix encoding failed: A=%v B=%v C=%v", errA, errB, errC)
	}

	leavesABC, blABC = crypto.BatchPedersenCommitABCBlinded(colsEncA, colsEncB, colsEncC, ckABC)
	treeABC, rootABC = crypto.BuildMerkleTreeFromGroupElements(leavesABC, depth)

	CmABC := crypto.HashElementsMiMC(rootABC)
	ChallengeR := crypto.HashElements(CmABC)
	ChallengeRPowers := matrix.Powers(ChallengeR, K)
	ChallengeB := crypto.HashElements(CmABC, uint64Element(challengeBLabel))
	ChallengeBPowers := matrix.Powers(ChallengeB, K)
	matrixTotalCommitTime := time.Since(startMatCommit).Seconds()
	matCommitTime := matrixTotalCommitTime - matrixEncodingTime

	// =========================================================================
	// 3. Compute x, yz = x*B, and an independent structured fold of B.
	// =========================================================================
	startVecCommit := time.Now()
	vecX := matrix.VecMatMul(ChallengeRPowers, matA, K)
	vecYZ := matrix.VecMatMul(vecX, matB, K)
	vecBTest := matrix.VecMatMul(ChallengeBPowers, matB, K)

	startVectorEncoding := time.Now()
	_, encX, _ := encoder.Encode(vecX)
	_, encYZ, _ := encoder.Encode(vecYZ)
	_, encBTest, err := encoder.Encode(vecBTest)
	vectorEncodingTime := time.Since(startVectorEncoding).Seconds()
	if err != nil {
		log.Fatalf("❌ B proximity vector encoding failed: %v", err)
	}

	colsXYZ := combineXYZScalars(encX, encYZ, encBTest)
	leavesXYZ, blXYZ := crypto.BatchPedersenCommitBlinded(colsXYZ, ckXYZ)
	treeXYZ, rootXYZ := crypto.BuildMerkleTreeFromGroupElements(leavesXYZ, depth)

	CmXYZ := crypto.HashElementsMiMC(rootXYZ)
	indices, err := crypto.GenerateUniqueIndices(CmXYZ, N, L)
	if err != nil {
		log.Fatalf("❌ Query index derivation failed: %v", err)
	}
	rsPointX, rsPointYZ, _ := protocol.GenerateRSEvaluationPoints(CmXYZ, N)
	rsPointB, err := protocol.GenerateRSEvaluationPointWithLabel(CmXYZ, rsPointBLabel, N, nil)
	if err != nil {
		log.Fatalf("❌ B proximity evaluation-point derivation failed: %v", err)
	}
	vectorTotalCommitTime := time.Since(startVecCommit).Seconds()
	vecCommitTime := vectorTotalCommitTime - vectorEncodingTime
	encodingTime := matrixEncodingTime + vectorEncodingTime
	commitTime := matCommitTime + vecCommitTime
	totalCommitTime := encodingTime + commitTime

	// =========================================================================
	// 4. Circuit Compile & Setup
	// =========================================================================
	fmt.Println("=== Circuit Setup & Prove ===")
	startDomainSetup := time.Now()
	domainN := fft.NewDomain(uint64(N))
	rootsN := crypto.GetDomainRoots(domainN, N)
	weightsN := crypto.PrecomputeBarycentricWeights(rootsN)

	domainK := fft.NewDomain(uint64(K))
	rootsK := crypto.GetDomainRoots(domainK, K)
	weightsK := crypto.PrecomputeBarycentricWeights(rootsK)
	protocolSetupTime += time.Since(startDomainSetup).Seconds()

	emptyCircuit := &circuit.LAMPCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		ColsEncABC: make([][]frontend.Variable, L),
		Indices:    make([]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		VecBTest: make([]frontend.Variable, K),
		EncX:     make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		EncBTest:         make([]frontend.Variable, N),
		QueriedEncValues: make([][]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncABC[i] = make([]frontend.Variable, 3*K)
		emptyCircuit.QueriedEncValues[i] = make([]frontend.Variable, 3)
	}

	r1csSystem, _ := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	nbConstraints := r1csSystem.GetNbConstraints()

	startSetup := time.Now()
	pk, vk, _ := groth16.Setup(r1csSystem)
	circuitSetupTime += time.Since(startSetup).Seconds()

	// =========================================================================
	// 5. Generate Proof
	// =========================================================================
	assignment := &circuit.LAMPCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		RootABC: rootABC, RootXYZ: rootXYZ, CmABC: CmABC, CmXYZ: CmXYZ,
		ChallengeR: ChallengeR, ChallengeB: ChallengeB,
		RSPointX: rsPointX, RSPointYZ: rsPointYZ, RSPointB: rsPointB,
		ColsEncABC: make([][]frontend.Variable, L),
		Indices:    make([]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		VecBTest: make([]frontend.Variable, K),
		EncX:     make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		EncBTest:         make([]frontend.Variable, N),
		QueriedEncValues: make([][]frontend.Variable, L),
	}

	for i := 0; i < K; i++ {
		assignment.VecX[i] = vecX[i]
		assignment.VecYZ[i] = vecYZ[i]
		assignment.VecBTest[i] = vecBTest[i]
	}
	for i := 0; i < N; i++ {
		assignment.EncX[i] = encX[i]
		assignment.EncYZ[i] = encYZ[i]
		assignment.EncBTest[i] = encBTest[i]
	}

	for i, idx := range indices {
		assignment.Indices[i] = idx
		assignment.QueriedEncValues[i] = []frontend.Variable{encX[idx], encYZ[idx], encBTest[idx]}
		assignment.ColsEncABC[i] = make([]frontend.Variable, 3*K)
		for j := 0; j < K; j++ {
			assignment.ColsEncABC[i][j] = colsEncA[idx][j]
			assignment.ColsEncABC[i][K+j] = colsEncB[idx][j]
			assignment.ColsEncABC[i][2*K+j] = colsEncC[idx][j]
		}
	}

	startProtocolBindSetup := time.Now()
	proverWithPK := protocol.NewProver(pk, ckABC, encoder)
	verifier := protocol.NewVerifier(vk, ckABC, proverWithPK.CK2)
	protocolSetupTime += time.Since(startProtocolBindSetup).Seconds()

	columnCommitIndex := -1
	scalarCommitIndex := -1
	for i, ck := range proverWithPK.CK2 {
		if len(ck.G) == 3*L*K {
			columnCommitIndex = i
		} else if len(ck.G) == 3*L {
			scalarCommitIndex = i
		}
	}

	if columnCommitIndex < 0 || scalarCommitIndex < 0 {
		log.Fatalf("❌ Grouped commitment mismatch: expected grouped column len=%d and scalar len=%d", 3*L*K, 3*L)
	}

	var columnLinkPK crypto.QALinkProvingKey
	var columnLinkVK crypto.QALinkVerifyingKey
	var scalarLinkPK crypto.QALinkProvingKey
	var scalarLinkVK crypto.QALinkVerifyingKey
	startCPLinkSetup := time.Now()
	columnLinkPK, columnLinkVK, err = crypto.SetupQALink(L, 3*K, proverWithPK.CK2[columnCommitIndex], ckABC)
	if err != nil {
		log.Fatalf("❌ Column QA-link setup failed: %v", err)
	}
	scalarLinkPK, scalarLinkVK, err = crypto.SetupQALink(L, 3, proverWithPK.CK2[scalarCommitIndex], ckXYZ)
	if err != nil {
		log.Fatalf("❌ Scalar QA-link setup failed: %v", err)
	}
	cpLinkSetupTime += time.Since(startCPLinkSetup).Seconds()
	setupTime := protocolSetupTime + circuitSetupTime + cpLinkSetupTime

	fmt.Println("=== 3. Generating Proof ===")
	proofWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ Failed to create witness for proving: %v", err)
	}
	startCircuitProve := time.Now()
	circuitProof, err := groth16.Prove(r1csSystem, pk, proofWitness)
	if err != nil {
		log.Fatalf("❌ Circuit proof failed: %v", err)
	}
	circuitProveTime := time.Since(startCircuitProve).Seconds()
	fmt.Printf("   ✅ Prove Time: %s\n", benchmark.FormatDurationSeconds(circuitProveTime))
	cmVec2, blindingsIn := protocol.ExtractGroth16CommitmentsAndBlindings(circuitProof)

	// =========================================================================
	// 6. Off-line Proof Generation for Merkle & CPLink
	// =========================================================================
	fmt.Println("=== Generating Off-line Proofs ===")

	var mmpABC crypto.MerkleMultiProof
	var mmpXYZ crypto.MerkleMultiProof

	startMerkleProve := time.Now()
	mmpABC = crypto.GetMerkleMultiProof(treeABC, indices, depth)
	mmpXYZ = crypto.GetMerkleMultiProof(treeXYZ, indices, depth)
	merkleProveTime := time.Since(startMerkleProve).Seconds()

	startCPLinkProve := time.Now()

	columnBlocks := make([][]fr.Element, 0, L)
	columnExternalCommitments := make([]bn254.G1Affine, 0, L)
	columnExternalBlindings := make([]fr.Element, 0, L)
	for _, idx := range indices {
		columnBlocks = append(columnBlocks, combineABCColumn(colsEncA[idx], colsEncB[idx], colsEncC[idx], K))
		columnExternalCommitments = append(columnExternalCommitments, leavesABC[idx])
		columnExternalBlindings = append(columnExternalBlindings, blABC[idx])
	}

	scalarBlocks := make([][]fr.Element, 0, L)
	scalarExternalCommitments := make([]bn254.G1Affine, 0, L)
	scalarExternalBlindings := make([]fr.Element, 0, L)
	for _, idx := range indices {
		scalarBlocks = append(scalarBlocks, []fr.Element{encX[idx], encYZ[idx], encBTest[idx]})
		scalarExternalCommitments = append(scalarExternalCommitments, leavesXYZ[idx])
		scalarExternalBlindings = append(scalarExternalBlindings, blXYZ[idx])
	}

	columnLinkProof, err := crypto.ProveQALink(
		columnBlocks,
		blindingsIn[columnCommitIndex],
		columnExternalBlindings,
		columnLinkPK,
	)
	if err != nil {
		log.Fatalf("❌ Column QA-link proof failed: %v", err)
	}
	scalarLinkProof, err := crypto.ProveQALink(
		scalarBlocks,
		blindingsIn[scalarCommitIndex],
		scalarExternalBlindings,
		scalarLinkPK,
	)
	if err != nil {
		log.Fatalf("❌ Scalar QA-link proof failed: %v", err)
	}
	cpLinkProveTime := time.Since(startCPLinkProve).Seconds()

	// =========================================================================
	// 7. Verify All Proofs
	// =========================================================================
	publicWitness, err := proofWitness.Public()
	if err != nil {
		log.Fatalf("❌ Failed to create public witness for verification: %v", err)
	}

	fmt.Println("=== Verifying All Proofs ===")
	startVerify := time.Now()
	expectedCmABC := crypto.HashElementsMiMC(rootABC)
	expectedChallengeR := crypto.HashElements(expectedCmABC)
	expectedChallengeB := crypto.HashElements(expectedCmABC, uint64Element(challengeBLabel))
	expectedCmXYZ := crypto.HashElementsMiMC(rootXYZ)
	expectedIndices, err := crypto.GenerateUniqueIndices(expectedCmXYZ, N, L)
	if err != nil {
		log.Fatalf("❌ Query index re-derivation failed: %v", err)
	}
	expectedRSPointX, expectedRSPointYZ, _ := protocol.GenerateRSEvaluationPoints(expectedCmXYZ, N)
	expectedRSPointB, err := protocol.GenerateRSEvaluationPointWithLabel(expectedCmXYZ, rsPointBLabel, N, nil)
	if err != nil {
		log.Fatalf("❌ B proximity evaluation-point re-derivation failed: %v", err)
	}
	if !CmABC.Equal(&expectedCmABC) || !ChallengeR.Equal(&expectedChallengeR) || !ChallengeB.Equal(&expectedChallengeB) || !CmXYZ.Equal(&expectedCmXYZ) || !rsPointX.Equal(&expectedRSPointX) || !rsPointYZ.Equal(&expectedRSPointYZ) || !rsPointB.Equal(&expectedRSPointB) {
		log.Fatal("❌ Transcript derivation failed")
	}
	for i := range indices {
		if indices[i] != expectedIndices[i] {
			log.Fatal("❌ Query index derivation failed")
		}
	}

	startCircuitVerify := time.Now()
	if err := groth16.Verify(circuitProof, vk, publicWitness); err != nil {
		log.Fatalf("❌ Groth16 Verify failed: %v", err)
	}
	circuitVerifyTime := time.Since(startCircuitVerify).Seconds()

	var merkleVerifyTime float64
	var cpLinkVerifyTime float64

	startMerkleVerify := time.Now()
	if !verifier.VerifyMultiMembership(rootABC, selectCommitments(leavesABC, indices), indices, mmpABC, depth) {
		log.Fatal("❌ Merkle ABC multiproof failed")
	}
	if !verifier.VerifyMultiMembership(rootXYZ, selectCommitments(leavesXYZ, indices), indices, mmpXYZ, depth) {
		log.Fatal("❌ Merkle XYZ multiproof failed")
	}
	merkleVerifyTime = time.Since(startMerkleVerify).Seconds()

	startCpLink := time.Now()
	linkChecks := []crypto.QALinkVerification{
		{
			SnarkCommit:     cmVec2[columnCommitIndex],
			ExternalCommits: columnExternalCommitments,
			Proof:           columnLinkProof,
			VK:              columnLinkVK,
		},
		{
			SnarkCommit:     cmVec2[scalarCommitIndex],
			ExternalCommits: scalarExternalCommitments,
			Proof:           scalarLinkProof,
			VK:              scalarLinkVK,
		},
	}
	if !crypto.VerifyQALinksBatched(linkChecks, lampLinkBatchContext([]fr.Element{rootABC, rootXYZ}, indices)...) {
		log.Fatal("❌ Batched QA-link verification failed")
	}
	cpLinkVerifyTime += time.Since(startCpLink).Seconds()

	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %s\n", benchmark.FormatDurationSeconds(totalVerifyTime))
	fmt.Println("✅ ALL BLINDED ZK PROOFS VERIFIED SUCCESSFULLY!")

	totalProveTime := totalCommitTime + merkleProveTime + circuitProveTime + cpLinkProveTime

	var buf bytes.Buffer
	circuitProof.WriteTo(&buf)
	groth16ProofSize := buf.Len()

	merkleProofSize := crypto.MerkleMultiProofSizeBytes(mmpABC) +
		crypto.MerkleMultiProofSizeBytes(mmpXYZ) +
		L*2*crypto.G1AffineSizeBytes

	cpLinkProofSize := crypto.QALinkProofSizeBytes(columnLinkProof) + crypto.QALinkProofSizeBytes(scalarLinkProof)

	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize

	fmt.Printf("📊 Proof Sizes -> Groth16: %d B, Merkle: %d B, CPLink: %d B | Total: %d B\n",
		groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.LAMPResult{
		LogK:              logK,
		Rho:               rhoStr,
		Linker:            linkerQALink,
		Merkle:            merkle,
		N:                 N,
		NumQueries:        L,
		Constraints:       nbConstraints,
		MatrixComputeTime: matrixComputeTime,
		SetupTime:         setupTime,
		ProtocolSetupTime: protocolSetupTime,
		CircuitSetupTime:  circuitSetupTime,
		CPLinkSetupTime:   cpLinkSetupTime,
		MatrixCommitTime:  matCommitTime,
		VectorCommitTime:  vecCommitTime,
		EncodingTime:      encodingTime,
		CommitTime:        commitTime,
		TotalCommitTime:   totalCommitTime,
		MerkleProveTime:   merkleProveTime,
		CircuitProveTime:  circuitProveTime,
		CPLinkProveTime:   cpLinkProveTime,
		TotalProveTime:    totalProveTime,
		CircuitVerifyTime: circuitVerifyTime,
		MerkleVerifyTime:  merkleVerifyTime,
		CPLinkVerifyTime:  cpLinkVerifyTime,
		TotalVerifyTime:   totalVerifyTime,
		MerkleProofSize:   merkleProofSize,
		Groth16ProofSize:  groth16ProofSize,
		CPLinkProofSize:   cpLinkProofSize,
		TotalProofSize:    totalProofSize,
		PeakMemoryBytes:   benchmark.PeakRSSBytes(),
	}
}

func selectCommitments(leaves []bn254.G1Affine, indices []int) []bn254.G1Affine {
	out := make([]bn254.G1Affine, len(indices))
	for i, idx := range indices {
		out[i] = leaves[idx]
	}
	return out
}

func combineABCColumn(a, b, c []fr.Element, blockLen int) []fr.Element {
	out := make([]fr.Element, 0, 3*blockLen)
	out = append(out, a...)
	out = append(out, b...)
	out = append(out, c...)
	return out
}

func combineXYZScalars(x, yz, bTest []fr.Element) [][]fr.Element {
	out := make([][]fr.Element, len(x))
	for i := range x {
		out[i] = []fr.Element{x[i], yz[i], bTest[i]}
	}
	return out
}

func lampLinkBatchContext(roots []fr.Element, indices []int) []fr.Element {
	context := make([]fr.Element, 0, 2+len(roots)+len(indices))
	context = append(context, uint64Element(0x4c414d504c494e4b), uint64Element(uint64(len(indices))))
	context = append(context, roots...)
	for _, idx := range indices {
		context = append(context, uint64Element(uint64(idx)))
	}
	return context
}

func uint64Element(value uint64) fr.Element {
	var out fr.Element
	out.SetUint64(value)
	return out
}
