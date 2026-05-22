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
	"github.com/Han-16/meow/config"
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

const (
	linkerSigma  = "sigma"
	linkerQANIZK = "qa_nizk"
)

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	logKFlag := flag.Int("K", config.GetInt("MEOW_LOG_K", 10), "Log base 2 of K")
	rhoFlag := flag.String("rho", config.GetString("MEOW_RHO", "1/2"), "Code rate")
	LFlag := flag.Int("L", config.GetInt("MEOW_L", 128), "Number of unique indices L")
	linkerFlag := flag.String("linker", config.GetString("MEOW_LINKER", linkerSigma), "CP-link backend: sigma or qa_nizk")
	allFlag := flag.Bool("all", config.GetBool("MEOW_ALL", false), "Run benchmark range")
	fromFlag := flag.Int("from", config.GetInt("MEOW_LOG_K_FROM", 7), "First logK when -all is enabled")
	toFlag := flag.Int("to", config.GetInt("MEOW_LOG_K_TO", 20), "Last logK when -all is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("MEOW_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("MEOW_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("MEOW_OUTPUT_DIR", filepath.Join("benchmark", "meow"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "meow_benchmark_results.csv")
	file, writer := benchmark.InitMeowCSV(csvPath)
	defer file.Close()

	if *allFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid logK range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		if onlyCompile {
			fmt.Printf("🚀 [OnlyCompile MODE] Checking constraints for logK=%d..%d...\n", *fromFlag, *toFlag)
		} else {
			fmt.Printf("🚀 [ALL MODE] Running Meow ZK benchmarks for logK=%d..%d...\n", *fromFlag, *toFlag)
		}

		for logK := *fromFlag; logK <= *toFlag; logK++ {
			res := runExperiment(logK, *rhoFlag, *LFlag, *linkerFlag, onlyCompile)
			benchmark.AppendMeowResultToCSV(writer, res)
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag, *linkerFlag, onlyCompile)
		benchmark.AppendMeowResultToCSV(writer, res)
	}
	fmt.Println("🎉 All Meow ZK tasks finished!")
}

func runExperiment(logK int, rhoStr string, L int, linker string, onlyCompile bool) benchmark.MeowResult {
	linker = normalizeLinker(linker)
	K := 1 << logK
	N := K << 1
	if rhoStr == "1/4" {
		N = K << 2
	}
	depth := int(math.Log2(float64(N)))
	field := ecc.BN254.ScalarField()

	fmt.Printf("🔥 [Meow ZK Protocol] logK=%d, K=%d, N=%d, L=%d, linker=%s\n", logK, K, N, L, linker)

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
			Indices: make([]frontend.Variable, L),
			VecX:    make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
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
			Linker:      linker,
			N:           N,
			NumQueries:  L,
			Constraints: nbConstraints,
		}
	}

	// =========================================================================
	// 0. Setup Phase
	// =========================================================================
	var protocolSetupTime float64
	var circuitSetupTime float64
	var cpLinkSetupTime float64
	startProtocolSetup := time.Now()
	ck1 := crypto.SetupCommitKey(K)
	ckScalar := crypto.SetupCommitKey(1)
	encoder := crypto.NewEncoder(K, N)
	prover := protocol.NewProver(nil, ck1, encoder)
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
	ChallengeR := crypto.HashElements(CmABC)
	ChallengeRPowers := matrix.Powers(ChallengeR, K)
	matCommitTime := time.Since(startMatCommit).Seconds()

	// =========================================================================
	// 3. Compute vector x, yz = x*B & their commitments
	// =========================================================================
	startVecCommit := time.Now()
	vecX := matrix.VecMatMul(ChallengeRPowers, matA, K)
	vecYZ := matrix.VecMatMul(vecX, matB, K)

	_, encX, _ := encoder.Encode(vecX)
	_, encYZ, _ := encoder.Encode(vecYZ)

	treeX, cmX, leavesX, blX := prover.CommitScalarsBlinded(encX, depth, ckScalar)
	treeYZ, cmYZ, leavesYZ, blYZ := prover.CommitScalarsBlinded(encYZ, depth, ckScalar)

	CmXYZ := crypto.HashElementsMiMC(cmX, cmYZ)
	indices, _ := crypto.GenerateUniqueIndices(CmXYZ, N, L)
	rsPointX, rsPointYZ, _ := protocol.GenerateRSEvaluationPoints(CmXYZ, N)
	vecCommitTime := time.Since(startVecCommit).Seconds()

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

	emptyCircuit := &circuit.MeowCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		Indices: make([]frontend.Variable, L),
		VecX:    make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
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

	startSetup := time.Now()
	pk, vk, _ := groth16.Setup(r1csSystem)
	circuitSetupTime += time.Since(startSetup).Seconds()

	// =========================================================================
	// 5. Generate Proof
	// =========================================================================
	assignment := &circuit.MeowCircuit{
		K: K, N: N, Depth: depth,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		Roots: [5]frontend.Variable{cmA, cmB, cmC, cmX, cmYZ}, CmABC: CmABC, CmXYZ: CmXYZ,
		ChallengeR: ChallengeR, RSPointX: rsPointX, RSPointYZ: rsPointYZ,
		ColsEncA: make([][]frontend.Variable, L), ColsEncB: make([][]frontend.Variable, L), ColsEncC: make([][]frontend.Variable, L),
		Indices: make([]frontend.Variable, L),
		VecX:    make([]frontend.Variable, K), VecYZ: make([]frontend.Variable, K),
		EncX: make([]frontend.Variable, N), EncYZ: make([]frontend.Variable, N),
		TargetEncX: make([]frontend.Variable, L), TargetEncYZ: make([]frontend.Variable, L),
	}

	for i := 0; i < K; i++ {
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

	startProtocolBindSetup := time.Now()
	proverWithPK := protocol.NewProver(pk, ck1, encoder)
	verifier := protocol.NewVerifier(vk, ck1, proverWithPK.CK2)
	protocolSetupTime += time.Since(startProtocolBindSetup).Seconds()

	columnCommitIndex := -1
	scalarCommitIndex := -1
	for i, ck := range proverWithPK.CK2 {
		if len(ck.G) == 3*L*K {
			columnCommitIndex = i
		} else if len(ck.G) == 2*L {
			scalarCommitIndex = i
		}
	}

	if columnCommitIndex < 0 || scalarCommitIndex < 0 {
		log.Fatalf("❌ Grouped commitment mismatch: expected grouped column len=%d and scalar len=%d", 3*L*K, 2*L)
	}

	var columnQAPK crypto.QALinkProvingKey
	var columnQAVK crypto.QALinkVerifyingKey
	var scalarQAPK crypto.QALinkProvingKey
	var scalarQAVK crypto.QALinkVerifyingKey
	if linker == linkerQANIZK {
		startCPLinkSetup := time.Now()
		var err error
		columnQAPK, columnQAVK, err = crypto.SetupQALink(3*L, K, proverWithPK.CK2[columnCommitIndex], ck1)
		if err != nil {
			log.Fatalf("❌ Column QA-NIZK setup failed: %v", err)
		}
		scalarQAPK, scalarQAVK, err = crypto.SetupQALink(2*L, 1, proverWithPK.CK2[scalarCommitIndex], ckScalar)
		if err != nil {
			log.Fatalf("❌ Scalar QA-NIZK setup failed: %v", err)
		}
		cpLinkSetupTime += time.Since(startCPLinkSetup).Seconds()
	}
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

	mpA := make([][]fr.Element, L)
	mpB := make([][]fr.Element, L)
	mpC := make([][]fr.Element, L)
	mpX := make([][]fr.Element, L)
	mpYZ := make([][]fr.Element, L)

	startMerkleProve := time.Now()
	for i, idx := range indices {
		mpA[i] = proverWithPK.GenerateMembershipProof(treeA, idx, depth)
		mpB[i] = proverWithPK.GenerateMembershipProof(treeB, idx, depth)
		mpC[i] = proverWithPK.GenerateMembershipProof(treeC, idx, depth)
		mpX[i] = proverWithPK.GenerateMembershipProof(treeX, idx, depth)
		mpYZ[i] = proverWithPK.GenerateMembershipProof(treeYZ, idx, depth)
	}
	merkleProveTime := time.Since(startMerkleProve).Seconds()

	startCPLinkProve := time.Now()

	columnBlocks := make([][]fr.Element, 0, 3*L)
	columnExternalCommitments := make([]bn254.G1Affine, 0, 3*L)
	columnExternalBlindings := make([]fr.Element, 0, 3*L)
	for _, idx := range indices {
		columnBlocks = append(columnBlocks, colsEncA[idx])
		columnExternalCommitments = append(columnExternalCommitments, leavesA[idx])
		columnExternalBlindings = append(columnExternalBlindings, blA[idx])
	}
	for _, idx := range indices {
		columnBlocks = append(columnBlocks, colsEncB[idx])
		columnExternalCommitments = append(columnExternalCommitments, leavesB[idx])
		columnExternalBlindings = append(columnExternalBlindings, blB[idx])
	}
	for _, idx := range indices {
		columnBlocks = append(columnBlocks, colsEncC[idx])
		columnExternalCommitments = append(columnExternalCommitments, leavesC[idx])
		columnExternalBlindings = append(columnExternalBlindings, blC[idx])
	}

	scalarBlocks := make([][]fr.Element, 0, 2*L)
	scalarExternalCommitments := make([]bn254.G1Affine, 0, 2*L)
	scalarExternalBlindings := make([]fr.Element, 0, 2*L)
	for _, idx := range indices {
		scalarBlocks = append(scalarBlocks, []fr.Element{encX[idx]})
		scalarExternalCommitments = append(scalarExternalCommitments, leavesX[idx])
		scalarExternalBlindings = append(scalarExternalBlindings, blX[idx])
	}
	for _, idx := range indices {
		scalarBlocks = append(scalarBlocks, []fr.Element{encYZ[idx]})
		scalarExternalCommitments = append(scalarExternalCommitments, leavesYZ[idx])
		scalarExternalBlindings = append(scalarExternalBlindings, blYZ[idx])
	}

	var columnSigmaProof crypto.AmComEqProof
	var scalarSigmaProof crypto.AmComEqProof
	var columnQAProof crypto.QALinkProof
	var scalarQAProof crypto.QALinkProof
	switch linker {
	case linkerSigma:
		columnSigmaProof, err = crypto.ProveAmComEq(
			columnBlocks,
			blindingsIn[columnCommitIndex],
			columnExternalBlindings,
			proverWithPK.CK2[columnCommitIndex],
			ck1,
			cmVec2[columnCommitIndex],
			columnExternalCommitments,
		)
		if err != nil {
			log.Fatalf("❌ Column AmComEq proof failed: %v", err)
		}
		scalarSigmaProof, err = crypto.ProveAmComEq(
			scalarBlocks,
			blindingsIn[scalarCommitIndex],
			scalarExternalBlindings,
			proverWithPK.CK2[scalarCommitIndex],
			ckScalar,
			cmVec2[scalarCommitIndex],
			scalarExternalCommitments,
		)
		if err != nil {
			log.Fatalf("❌ Scalar AmComEq proof failed: %v", err)
		}
	case linkerQANIZK:
		columnQAProof, err = crypto.ProveQALink(
			columnBlocks,
			blindingsIn[columnCommitIndex],
			columnExternalBlindings,
			columnQAPK,
		)
		if err != nil {
			log.Fatalf("❌ Column QA-NIZK proof failed: %v", err)
		}
		scalarQAProof, err = crypto.ProveQALink(
			scalarBlocks,
			blindingsIn[scalarCommitIndex],
			scalarExternalBlindings,
			scalarQAPK,
		)
		if err != nil {
			log.Fatalf("❌ Scalar QA-NIZK proof failed: %v", err)
		}
	default:
		log.Fatalf("unsupported linker %q", linker)
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
	expectedCmABC := crypto.HashElementsMiMC(cmA, cmB, cmC)
	expectedChallengeR := crypto.HashElements(expectedCmABC)
	expectedCmXYZ := crypto.HashElementsMiMC(cmX, cmYZ)
	expectedIndices, _ := crypto.GenerateUniqueIndices(expectedCmXYZ, N, L)
	expectedRSPointX, expectedRSPointYZ, _ := protocol.GenerateRSEvaluationPoints(expectedCmXYZ, N)
	if !CmABC.Equal(&expectedCmABC) || !ChallengeR.Equal(&expectedChallengeR) || !CmXYZ.Equal(&expectedCmXYZ) || !rsPointX.Equal(&expectedRSPointX) || !rsPointYZ.Equal(&expectedRSPointYZ) {
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
	}

	startCpLink := time.Now()
	switch linker {
	case linkerSigma:
		if !crypto.VerifyAmComEq(cmVec2[columnCommitIndex], columnExternalCommitments, columnSigmaProof, verifier.CK2[columnCommitIndex], ck1) {
			log.Fatal("❌ Column AmComEq Failed")
		}
		if !crypto.VerifyAmComEq(cmVec2[scalarCommitIndex], scalarExternalCommitments, scalarSigmaProof, verifier.CK2[scalarCommitIndex], ckScalar) {
			log.Fatal("❌ Scalar AmComEq Failed")
		}
	case linkerQANIZK:
		if !crypto.VerifyQALink(cmVec2[columnCommitIndex], columnExternalCommitments, columnQAProof, columnQAVK) {
			log.Fatal("❌ Column QA-NIZK link failed")
		}
		if !crypto.VerifyQALink(cmVec2[scalarCommitIndex], scalarExternalCommitments, scalarQAProof, scalarQAVK) {
			log.Fatal("❌ Scalar QA-NIZK link failed")
		}
	default:
		log.Fatalf("unsupported linker %q", linker)
	}
	cpLinkVerifyTime += time.Since(startCpLink).Seconds()

	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %s\n", benchmark.FormatDurationSeconds(totalVerifyTime))
	fmt.Println("✅ ALL BLINDED ZK PROOFS VERIFIED SUCCESSFULLY!")

	totalProveTime := matCommitTime + vecCommitTime + merkleProveTime + circuitProveTime + cpLinkProveTime

	var buf bytes.Buffer
	circuitProof.WriteTo(&buf)
	groth16ProofSize := buf.Len()

	merkleProofSize := L * 5 * depth * 32

	cpLinkProofSize := 0
	switch linker {
	case linkerSigma:
		cpLinkProofSize = crypto.AmComEqProofSizeBytes(columnSigmaProof) + crypto.AmComEqProofSizeBytes(scalarSigmaProof)
	case linkerQANIZK:
		cpLinkProofSize = crypto.QALinkProofSizeBytes(columnQAProof) + crypto.QALinkProofSizeBytes(scalarQAProof)
	}

	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize

	fmt.Printf("📊 Proof Sizes -> Groth16: %d B, Merkle: %d B, CPLink: %d B | Total: %d B\n",
		groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.MeowResult{
		LogK:              logK,
		Rho:               rhoStr,
		Linker:            linker,
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
	}
}

func normalizeLinker(linker string) string {
	switch linker {
	case "", linkerSigma:
		return linkerSigma
	case linkerQANIZK, "qa", "qanizk":
		return linkerQANIZK
	default:
		log.Fatalf("unsupported linker %q; use %q or %q", linker, linkerSigma, linkerQANIZK)
	}
	return linkerSigma
}
