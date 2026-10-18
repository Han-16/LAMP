package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"path/filepath"
	"runtime"
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
)

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	logKFlag := flag.Int("K", config.GetInt("LAMP_LOG_K", 10), "Log base 2 of K")
	rhoFlag := flag.String("rho", config.GetString("LAMP_RHO", "1/2"), "Code rate")
	LFlag := flag.Int("L", config.GetInt("LAMP_L", 309), "Number of sampled indices L")
	allFlag := flag.Bool("all", config.GetBool("LAMP_ALL", false), "Run benchmark range")
	fromFlag := flag.Int("from", config.GetInt("LAMP_LOG_K_FROM", 7), "First logK when -all is enabled")
	toFlag := flag.Int("to", config.GetInt("LAMP_LOG_K_TO", 20), "Last logK when -all is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("LAMP_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("LAMP_ONLY_COMPILE", false), "Alias for -compile")
	matrixSourceFlag := flag.String("matrix-source", config.GetString("LAMP_MATRIX_SOURCE", "auto"), "Matrix input: auto, file, or generate")
	matrixDirFlag := flag.String("matrix-dir", config.OutputDir("LAMP_MATRIX_DIR", "matrices"), "Directory containing matrices_k<K>.bin")
	repeatFlag := flag.Int("repeat", config.GetInt("LAMP_REPEAT", 1), "repetitions per configuration, each with fresh setup keys")
	flag.Parse()
	if *repeatFlag < 1 {
		log.Fatal("repeat must be at least 1")
	}

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("LAMP_OUTPUT_DIR", filepath.Join("benchmark", "lamp"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "lamp_benchmark_results.csv")
	writer, err := benchmark.InitLAMPCSV(csvPath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := writer.Close(); err != nil {
			log.Fatal(err)
		}
	}()

	first, last := *logKFlag, *logKFlag
	if *allFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid logK range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		first, last = *fromFlag, *toFlag
	}
	for logK := first; logK <= last; logK++ {
		if err := runRepeatedExperiments(logK, *rhoFlag, *LFlag, onlyCompile, *matrixSourceFlag, *matrixDirFlag, *repeatFlag, writer); err != nil {
			log.Fatal(err)
		}
	}
	if err := writer.SaveAverages(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("🎉 All LAMP ZK tasks finished!")
}

func runExperiment(logK int, rhoStr string, L int, onlyCompile bool, matrixSource, matrixDir string) benchmark.LAMPResult {
	var input matrix.Input
	if !onlyCompile {
		var err error
		input, err = matrix.Prepare(1<<logK, matrixSource, matrixDir)
		if err != nil {
			log.Fatalf("matrix input: %v", err)
		}
	}
	return runExperimentWithInput(logK, rhoStr, L, onlyCompile, input)
}

func runRepeatedExperiments(logK int, rho string, L int, onlyCompile bool, matrixSource, matrixDir string, repeats int, writer *benchmark.LAMPCSV) error {
	if repeats < 1 {
		return fmt.Errorf("repeat must be at least 1")
	}
	var input matrix.Input
	if !onlyCompile {
		var err error
		input, err = matrix.Prepare(1<<logK, matrixSource, matrixDir)
		if err != nil {
			return fmt.Errorf("matrix input: %w", err)
		}
	}
	for repetition := 1; repetition <= repeats; repetition++ {
		runtime.GC() // Release the previous setup/prover state outside all timers.
		fmt.Printf("Repeat %d/%d | logk=%d\n", repetition, repeats, logK)
		result := runExperimentWithInput(logK, rho, L, onlyCompile, input)
		result.Repeat = repetition
		if err := benchmark.AppendLAMPResultToCSV(writer, result); err != nil {
			return err
		}
	}
	return nil
}

func runExperimentWithInput(logK int, rhoStr string, L int, onlyCompile bool, input matrix.Input) benchmark.LAMPResult {
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
			MatrixSource:    "compile",
			PeakMemoryBytes: benchmark.PeakRSSBytes(),
		}
	}

	// =========================================================================
	// 0. Setup Phase
	// =========================================================================
	var protocolSetupTime float64
	var cpLinkSetupTime float64
	setupSampler := benchmark.StartMemory()
	startProtocolSetup := time.Now()
	ckABC := crypto.SetupCommitKey(3 * K)
	ckXYZ := crypto.SetupCommitKey(3)
	encoder := crypto.NewEncoder(K, N)
	protocolSetupTime += time.Since(startProtocolSetup).Seconds()
	setupMemory := setupSampler.Stop()

	// =========================================================================
	// 1. Compute Matrices A, B, C
	// =========================================================================
	matrixComputeTime := input.Compute.Seconds()
	fmt.Printf("   Matrix input: %s (%s); load: %s; compute: %s\n", input.Source, input.Path,
		benchmark.FormatDurationSeconds(input.Load.Seconds()), benchmark.FormatDurationSeconds(matrixComputeTime))
	matA, matB, matC := input.A, input.B, input.C

	// =========================================================================
	// 2. Encode & Commit Matrices A, B, C
	// =========================================================================
	commitSampler := benchmark.StartMemory()
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

	startPedersen := time.Now()
	leavesABC, blABC = crypto.BatchPedersenCommitABCBlinded(colsEncA, colsEncB, colsEncC, ckABC)
	pedersenCommitTime := time.Since(startPedersen).Seconds()
	startMerkleCommit := time.Now()
	treeABC, rootABC = crypto.BuildMerkleTreeFromGroupElements(leavesABC, depth)
	merkleCommitTime := time.Since(startMerkleCommit).Seconds()

	commitOtherTime := time.Since(startMatCommit).Seconds() - matrixEncodingTime - pedersenCommitTime - merkleCommitTime
	matCommitTime := matrixEncodingTime + pedersenCommitTime + merkleCommitTime
	commitMemory := commitSampler.Stop()

	proveSampler := benchmark.StartMemory()
	startVecCompute := time.Now()
	CmABC := crypto.HashElementsMiMC(rootABC)
	ChallengeR := crypto.HashElements(CmABC)
	ChallengeRPowers := matrix.Powers(ChallengeR, K)
	ChallengeB := crypto.HashElements(CmABC, uint64Element(challengeBLabel))
	ChallengeBPowers := matrix.Powers(ChallengeB, K)

	// =========================================================================
	// 3. Compute x, yz = x*B, and an independent structured fold of B.
	// =========================================================================
	vecX := matrix.VecMatMul(ChallengeRPowers, matA, K)
	vecYZ := matrix.VecMatMul(vecX, matB, K)
	vecBTest := matrix.VecMatMul(ChallengeBPowers, matB, K)

	_, encX, _ := encoder.Encode(vecX)
	_, encYZ, _ := encoder.Encode(vecYZ)
	_, encBTest, err := encoder.Encode(vecBTest)
	if err != nil {
		log.Fatalf("❌ B proximity vector encoding failed: %v", err)
	}

	vectorComputeTime := time.Since(startVecCompute).Seconds()
	startVecCommit := time.Now()
	colsXYZ := combineXYZScalars(encX, encYZ, encBTest)
	leavesXYZ, blXYZ := crypto.BatchPedersenCommitBlinded(colsXYZ, ckXYZ)
	treeXYZ, rootXYZ := crypto.BuildMerkleTreeFromGroupElements(leavesXYZ, depth)

	vecCommitTime := time.Since(startVecCommit).Seconds()
	startQueries := time.Now()
	CmXYZ := crypto.HashElementsMiMC(rootXYZ)
	indices, err := crypto.GenerateIndices(CmXYZ, N, L)
	if err != nil {
		log.Fatalf("❌ Query index derivation failed: %v", err)
	}
	vectorComputeTime += time.Since(startQueries).Seconds()
	encodingTime := matrixEncodingTime // ABC encoding, already included in abc_commit_time.
	commitTime := matCommitTime + vecCommitTime
	totalCommitTime := commitTime + vectorComputeTime

	// =========================================================================
	// 4. Circuit Compile & Setup
	// =========================================================================
	fmt.Println("=== Circuit Setup & Prove ===")
	proveMemory := proveSampler.Stop()
	setupSampler = benchmark.StartMemory()
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

	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("circuit compilation failed: %v", err)
	}
	nbConstraints := r1csSystem.GetNbConstraints()

	// Match LED: circuit setup measures only Groth16 setup, excluding compilation.
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("Groth16 setup failed: %v", err)
	}
	circuitSetupTime := time.Since(startSetup).Seconds()
	setupMemory = setupMemory.Merge(setupSampler.Stop())

	// =========================================================================
	// 5. Generate Proof
	// =========================================================================
	assignment := &circuit.LAMPCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		RootABC: rootABC, RootXYZ: rootXYZ, CmABC: CmABC, CmXYZ: CmXYZ,
		ChallengeR: ChallengeR, ChallengeB: ChallengeB,
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

	setupSampler = benchmark.StartMemory()
	startProtocolBindSetup := time.Now()
	proverWithPK := protocol.NewProver(pk, ckABC, encoder)
	verifier := protocol.NewVerifier(vk, ckABC, proverWithPK.CK2)
	protocolSetupTime += time.Since(startProtocolBindSetup).Seconds()

	const (
		columnCommitIndex = iota
		scalarCommitIndex
		rsWitnessCommitIndex
	)
	if len(proverWithPK.CK2) <= rsWitnessCommitIndex ||
		len(proverWithPK.CK2[columnCommitIndex].G) != 3*L*K ||
		len(proverWithPK.CK2[scalarCommitIndex].G) != 3*L ||
		len(proverWithPK.CK2[rsWitnessCommitIndex].G) != 3*(K+N) {
		log.Fatalf("❌ Commitment layout mismatch: expected column=%d scalar=%d RS-witness=%d", 3*L*K, 3*L, 3*(K+N))
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
	setupMemory = setupMemory.Merge(setupSampler.Stop())
	proveSampler = benchmark.StartMemory()

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
	fmt.Printf("   ✅ Circuit Prove Time: %s\n", benchmark.FormatDurationSeconds(circuitProveTime))
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

	// Count sampled input selection/packing as vector preparation.
	startLinkInputs := time.Now()

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

	vectorComputeTime += time.Since(startLinkInputs).Seconds()
	totalCommitTime = commitTime + vectorComputeTime
	startCPLinkProve := time.Now()
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
	proveMemory = proveMemory.Merge(proveSampler.Stop())

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
	expectedIndices, err := crypto.GenerateIndices(expectedCmXYZ, N, L)
	if err != nil {
		log.Fatalf("❌ Query index re-derivation failed: %v", err)
	}
	if !CmABC.Equal(&expectedCmABC) || !ChallengeR.Equal(&expectedChallengeR) || !ChallengeB.Equal(&expectedChallengeB) || !CmXYZ.Equal(&expectedCmXYZ) {
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

	totalProveTime := merkleProveTime + circuitProveTime + cpLinkProveTime
	commitAndProveTime := totalCommitTime + totalProveTime
	fmt.Printf("   Commit: ABC=%s, vector compute=%s, vector commit=%s, total=%s\n",
		benchmark.FormatDurationSeconds(matCommitTime), benchmark.FormatDurationSeconds(vectorComputeTime),
		benchmark.FormatDurationSeconds(vecCommitTime), benchmark.FormatDurationSeconds(totalCommitTime))
	fmt.Printf("   Total Prove Time: %s; Commit and Prove Time: %s\n",
		benchmark.FormatDurationSeconds(totalProveTime), benchmark.FormatDurationSeconds(commitAndProveTime))

	snarkBytes, err := circuitProof.WriteTo(io.Discard)
	if err != nil {
		log.Fatalf("measure SNARK proof: %v", err)
	}
	groth16ProofSize := int(snarkBytes)

	merkleProofSize := crypto.MerkleMultiProofSizeBytes(mmpABC) +
		crypto.MerkleMultiProofSizeBytes(mmpXYZ)
	queryCommitmentsSize := L * 2 * crypto.G1AffineSizeBytes

	cpLinkProofSize := crypto.QALinkProofSizeBytes(columnLinkProof) + crypto.QALinkProofSizeBytes(scalarLinkProof)

	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize + queryCommitmentsSize

	fmt.Printf("📊 Proof Sizes -> Groth16: %d B, Merkle: %d B, CPLink: %d B, Query commitments: %d B | Total: %d B\n",
		groth16ProofSize, merkleProofSize, cpLinkProofSize, queryCommitmentsSize, totalProofSize)

	return benchmark.LAMPResult{
		LogK:                 logK,
		Rho:                  rhoStr,
		Linker:               linkerQALink,
		Merkle:               merkle,
		N:                    N,
		NumQueries:           L,
		Constraints:          nbConstraints,
		MatrixComputeTime:    matrixComputeTime,
		MatrixSource:         input.Source,
		MatrixPath:           input.Path,
		MatrixLoadTime:       input.Load.Seconds(),
		SetupTime:            setupTime,
		ProtocolSetupTime:    protocolSetupTime,
		CircuitSetupTime:     circuitSetupTime,
		CPLinkSetupTime:      cpLinkSetupTime,
		MatrixCommitTime:     matCommitTime,
		PedersenCommitTime:   pedersenCommitTime,
		MerkleCommitTime:     merkleCommitTime,
		CommitOtherTime:      commitOtherTime,
		MatrixWorkers:        input.Workers,
		SetupMemory:          setupMemory,
		CommitMemory:         commitMemory,
		ProveMemory:          proveMemory,
		VectorCommitTime:     vecCommitTime,
		VectorComputeTime:    vectorComputeTime,
		EncodingTime:         encodingTime,
		CommitTime:           commitTime,
		TotalCommitTime:      totalCommitTime,
		MerkleProveTime:      merkleProveTime,
		CircuitProveTime:     circuitProveTime,
		CPLinkProveTime:      cpLinkProveTime,
		TotalProveTime:       totalProveTime,
		CommitAndProveTime:   commitAndProveTime,
		CircuitVerifyTime:    circuitVerifyTime,
		MerkleVerifyTime:     merkleVerifyTime,
		CPLinkVerifyTime:     cpLinkVerifyTime,
		TotalVerifyTime:      totalVerifyTime,
		MerkleProofSize:      merkleProofSize,
		Groth16ProofSize:     groth16ProofSize,
		CPLinkProofSize:      cpLinkProofSize,
		TotalProofSize:       totalProofSize,
		QueryCommitmentsSize: queryCommitmentsSize,
		PeakMemoryBytes:      benchmark.PeakRSSBytes(),
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
