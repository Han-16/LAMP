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
)

const (
	labelChallengeR = 0x524c4352 // "RLCR"
	labelChallengeB = 0x524c4342 // "RLCB"
	labelGamma      = 0x524c4347 // "RLCG"
	labelQueries    = 0x524c4351 // "RLCQ"
)

type batchProduct struct {
	A, B, C            [][]fr.Element
	ColsEncA, ColsEncB [][]fr.Element
	ColsEncC           [][]fr.Element
	VecX, EncX         []fr.Element
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	logKFlag := flag.Int("K", config.GetInt("LAMP_BATCH_LOG_K", 10), "Log base 2 of K")
	rhoFlag := flag.String("rho", config.GetString("LAMP_BATCH_RHO", "1/2"), "Code rate")
	LFlag := flag.Int("L", config.GetInt("LAMP_BATCH_L", 128), "Number of sampled indices L")
	batchFlag := flag.Int("batch", config.GetInt("LAMP_BATCH_SIZE", 5), "Number of matrix multiplications in the batch")
	allFlag := flag.Bool("all", config.GetBool("LAMP_BATCH_ALL", false), "Run benchmark range")
	batchRangeFlag := flag.Bool("batch-range", config.GetBool("LAMP_BATCH_RANGE", false), "Run benchmark range over batch sizes")
	fromFlag := flag.Int("from", config.GetInt("LAMP_BATCH_LOG_K_FROM", 7), "First logK when -all is enabled")
	toFlag := flag.Int("to", config.GetInt("LAMP_BATCH_LOG_K_TO", 13), "Last logK when -all is enabled")
	batchFromFlag := flag.Int("batch-from", config.GetInt("LAMP_BATCH_FROM", 1), "First batch size when -batch-range is enabled")
	batchToFlag := flag.Int("batch-to", config.GetInt("LAMP_BATCH_TO", 10), "Last batch size when -batch-range is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("LAMP_BATCH_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("LAMP_BATCH_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("LAMP_BATCH_OUTPUT_DIR", filepath.Join("benchmark", "lamp_batch"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "lamp_batch_benchmark_results.csv")
	file, writer := benchmark.InitLAMPBATCHCSV(csvPath)
	defer file.Close()

	runLogKFrom, runLogKTo := *logKFlag, *logKFlag
	if *allFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid logK range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		runLogKFrom, runLogKTo = *fromFlag, *toFlag
	}

	runBatchFrom, runBatchTo := *batchFlag, *batchFlag
	if *batchRangeFlag {
		if *batchFromFlag > *batchToFlag {
			log.Fatalf("invalid batch range: from=%d, to=%d", *batchFromFlag, *batchToFlag)
		}
		runBatchFrom, runBatchTo = *batchFromFlag, *batchToFlag
	}

	if *allFlag || *batchRangeFlag {
		if onlyCompile {
			fmt.Printf("🚀 [OnlyCompile MODE] Checking LAMPBATCH constraints for logK=%d..%d, batch=%d..%d...\n", runLogKFrom, runLogKTo, runBatchFrom, runBatchTo)
		} else {
			fmt.Printf("🚀 [RANGE MODE] Running LAMPBATCH benchmarks for logK=%d..%d, batch=%d..%d...\n", runLogKFrom, runLogKTo, runBatchFrom, runBatchTo)
		}
		for logK := runLogKFrom; logK <= runLogKTo; logK++ {
			for batch := runBatchFrom; batch <= runBatchTo; batch++ {
				res := runExperiment(logK, *rhoFlag, *LFlag, batch, onlyCompile)
				benchmark.AppendLAMPBATCHResultToCSV(writer, res)
			}
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag, *batchFlag, onlyCompile)
		benchmark.AppendLAMPBATCHResultToCSV(writer, res)
	}
	fmt.Println("🎉 All LAMPBATCH tasks finished!")
}

func runExperiment(logK int, rhoStr string, L int, batch int, onlyCompile bool) benchmark.LAMPBATCHResult {
	merkle := merkleMulti
	if batch <= 0 {
		log.Fatalf("batch must be positive, got %d", batch)
	}

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

	fmt.Printf("🔥 [LAMPBATCH Protocol] logK=%d, K=%d, N=%d, L=%d, batch=%d, linker=%s, merkle=%s\n", logK, K, N, L, batch, linkerQALink, merkle)

	if onlyCompile {
		fmt.Println("=== 🔍 Compiling LAMPBATCH Circuit for Constraints ===")
		rootsK, weightsK, rootsN, weightsN := buildDomains(K, N)
		emptyCircuit := newLAMPBATCHCircuit(K, N, batch, L, rootsK, weightsK, rootsN, weightsN)

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("❌ Compilation failed: %v", err)
		}

		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("✅ Circuit compiled successfully! Total Constraints: %d\n", nbConstraints)

		return benchmark.LAMPBATCHResult{
			LogK:            logK,
			Rho:             rhoStr,
			Linker:          linkerQALink,
			Merkle:          merkle,
			Batch:           batch,
			N:               N,
			NumQueries:      L,
			Constraints:     nbConstraints,
			PeakMemoryBytes: benchmark.PeakRSSBytes(),
		}
	}

	var protocolSetupTime float64
	var circuitSetupTime float64
	var cpLinkSetupTime float64

	startProtocolSetup := time.Now()
	ckABC := crypto.SetupCommitKey(3 * batch * K)
	ckXYZ := crypto.SetupCommitKey(batch + 2)
	encoder := crypto.NewEncoder(K, N)
	protocolSetupTime += time.Since(startProtocolSetup).Seconds()

	products := make([]batchProduct, batch)
	for i := range products {
		products[i].A = matrix.GenerateRandomMatrix(K, K)
		products[i].B = matrix.GenerateRandomMatrix(K, K)
	}

	startCompute := time.Now()
	for i := range products {
		products[i].C = matrix.MatMul(products[i].A, products[i].B, K)
	}
	matrixComputeTime := time.Since(startCompute).Seconds()
	fmt.Printf("   ✅ Matrix Compute Time: %.2f s\n", matrixComputeTime)

	startMatCommit := time.Now()
	startMatrixEncoding := time.Now()
	encodeBatchProducts(products, encoder)
	matrixEncodingTime := time.Since(startMatrixEncoding).Seconds()
	abcBlocks := buildABCBlocks(products, N, K)
	leavesABC, blABC := crypto.BatchPedersenCommitBlinded(abcBlocks, ckABC)
	treeABC, rootABC := crypto.BuildMerkleTreeFromGroupElements(leavesABC, depth)

	cmABC := crypto.HashElementsMiMC(rootABC)
	challengeR := deriveLAMPBATCHChallenge(cmABC, labelChallengeR)
	challengeB := deriveLAMPBATCHChallenge(cmABC, labelChallengeB)
	gamma := deriveLAMPBATCHChallenge(cmABC, labelGamma)
	rPowers := matrix.Powers(challengeR, K)
	bPowers := matrix.Powers(challengeB, K)
	gammaPowers := matrix.Powers(gamma, batch)
	matrixTotalCommitTime := time.Since(startMatCommit).Seconds()
	matCommitTime := matrixTotalCommitTime - matrixEncodingTime

	startVecCommit := time.Now()
	vectorEncodingTime := 0.0
	vecW := make([]fr.Element, K)
	vecBTest := make([]fr.Element, K)
	for i := range products {
		products[i].VecX = matrix.VecMatMul(rPowers, products[i].A, K)
		startEncoding := time.Now()
		_, encX, err := encoder.Encode(products[i].VecX)
		vectorEncodingTime += time.Since(startEncoding).Seconds()
		if err != nil {
			log.Fatalf("❌ Failed to encode VecX for batch item %d: %v", i, err)
		}
		products[i].EncX = encX

		yi := matrix.VecMatMul(products[i].VecX, products[i].B, K)
		addScaledVector(vecW, yi, gammaPowers[i])

		biTest := matrix.VecMatMul(bPowers, products[i].B, K)
		addScaledVector(vecBTest, biTest, gammaPowers[i])
	}
	startEncoding := time.Now()
	_, encW, err := encoder.Encode(vecW)
	vectorEncodingTime += time.Since(startEncoding).Seconds()
	if err != nil {
		log.Fatalf("❌ Failed to encode batch output vector: %v", err)
	}
	startEncoding = time.Now()
	_, encBTest, err := encoder.Encode(vecBTest)
	vectorEncodingTime += time.Since(startEncoding).Seconds()
	if err != nil {
		log.Fatalf("❌ Failed to encode batch B proximity vector: %v", err)
	}

	xyzBlocks := buildXYZBlocks(products, encW, encBTest, N)
	leavesXYZ, blXYZ := crypto.BatchPedersenCommitBlinded(xyzBlocks, ckXYZ)
	treeXYZ, rootXYZ := crypto.BuildMerkleTreeFromGroupElements(leavesXYZ, depth)

	cmXYZ := crypto.HashElementsMiMC(rootXYZ)
	indices, err := protocol.GenerateIndicesWithLabel(cmXYZ, labelQueries, N, L)
	if err != nil {
		log.Fatalf("❌ Failed to sample query indices: %v", err)
	}
	vectorTotalCommitTime := time.Since(startVecCommit).Seconds()
	vecCommitTime := vectorTotalCommitTime - vectorEncodingTime
	encodingTime := matrixEncodingTime + vectorEncodingTime
	commitTime := matCommitTime + vecCommitTime
	totalCommitTime := encodingTime + commitTime

	fmt.Println("=== Circuit Setup & Prove ===")
	startDomainSetup := time.Now()
	rootsK, weightsK, rootsN, weightsN := buildDomains(K, N)
	protocolSetupTime += time.Since(startDomainSetup).Seconds()

	emptyCircuit := newLAMPBATCHCircuit(K, N, batch, L, rootsK, weightsK, rootsN, weightsN)
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ Compilation failed: %v", err)
	}
	nbConstraints := r1csSystem.GetNbConstraints()

	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("❌ Groth16 setup failed: %v", err)
	}
	circuitSetupTime += time.Since(startSetup).Seconds()

	assignment := newLAMPBATCHCircuit(K, N, batch, L, rootsK, weightsK, rootsN, weightsN)
	assignment.RootABC = rootABC
	assignment.RootXYZ = rootXYZ
	assignment.CmABC = cmABC
	assignment.CmXYZ = cmXYZ
	assignment.ChallengeR = challengeR
	assignment.ChallengeB = challengeB
	assignment.Gamma = gamma

	fillLAMPBATCHAssignment(assignment, products, vecW, encW, vecBTest, encBTest, abcBlocks, xyzBlocks, indices, K, N)

	startProtocolBindSetup := time.Now()
	proverWithPK := protocol.NewProver(pk, ckABC, encoder)
	verifier := protocol.NewVerifier(vk, ckABC, proverWithPK.CK2)
	protocolSetupTime += time.Since(startProtocolBindSetup).Seconds()

	const (
		columnCommitIndex = iota
		scalarCommitIndex
		rsWitnessCommitIndex
	)
	rsWitnessLen := (batch + 2) * (K + N)
	if len(proverWithPK.CK2) <= rsWitnessCommitIndex ||
		len(proverWithPK.CK2[columnCommitIndex].G) != L*3*batch*K ||
		len(proverWithPK.CK2[scalarCommitIndex].G) != L*(batch+2) ||
		len(proverWithPK.CK2[rsWitnessCommitIndex].G) != rsWitnessLen {
		log.Fatalf("❌ Commitment layout mismatch: expected column=%d scalar=%d RS-witness=%d", L*3*batch*K, L*(batch+2), rsWitnessLen)
	}

	startCPLinkSetup := time.Now()
	columnLinkPK, columnLinkVK, err := crypto.SetupQALink(L, 3*batch*K, proverWithPK.CK2[columnCommitIndex], ckABC)
	if err != nil {
		log.Fatalf("❌ Column QA-link setup failed: %v", err)
	}
	scalarLinkPK, scalarLinkVK, err := crypto.SetupQALink(L, batch+2, proverWithPK.CK2[scalarCommitIndex], ckXYZ)
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

	fmt.Println("=== Generating Off-line Proofs ===")
	var mmpABC crypto.MerkleMultiProof
	var mmpXYZ crypto.MerkleMultiProof

	startMerkleProve := time.Now()
	mmpABC = crypto.GetMerkleMultiProof(treeABC, indices, depth)
	mmpXYZ = crypto.GetMerkleMultiProof(treeXYZ, indices, depth)
	merkleProveTime := time.Since(startMerkleProve).Seconds()

	startCPLinkProve := time.Now()
	columnBlocks, columnExternalCommitments, columnExternalBlindings := selectBlocksAndOpenings(abcBlocks, leavesABC, blABC, indices)
	scalarBlocks, scalarExternalCommitments, scalarExternalBlindings := selectBlocksAndOpenings(xyzBlocks, leavesXYZ, blXYZ, indices)

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

	publicWitness, err := proofWitness.Public()
	if err != nil {
		log.Fatalf("❌ Failed to create public witness for verification: %v", err)
	}

	fmt.Println("=== Verifying All Proofs ===")
	startVerify := time.Now()
	verifyTranscript(rootABC, rootXYZ, cmABC, cmXYZ, challengeR, challengeB, gamma, indices, N, L)

	startCircuitVerify := time.Now()
	if err := groth16.Verify(circuitProof, vk, publicWitness); err != nil {
		log.Fatalf("❌ Groth16 Verify failed: %v", err)
	}
	circuitVerifyTime := time.Since(startCircuitVerify).Seconds()

	startMerkleVerify := time.Now()
	if !verifier.VerifyMultiMembership(rootABC, selectCommitments(leavesABC, indices), indices, mmpABC, depth) {
		log.Fatal("❌ Merkle ABC multiproof failed")
	}
	if !verifier.VerifyMultiMembership(rootXYZ, selectCommitments(leavesXYZ, indices), indices, mmpXYZ, depth) {
		log.Fatal("❌ Merkle XYZ multiproof failed")
	}
	merkleVerifyTime := time.Since(startMerkleVerify).Seconds()

	startCPLinkVerify := time.Now()
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
	if !crypto.VerifyQALinksBatched(linkChecks, lampBatchLinkContext([]fr.Element{rootABC, rootXYZ}, indices, batch, K, N, L)...) {
		log.Fatal("❌ Batched QA-link verification failed")
	}
	cpLinkVerifyTime := time.Since(startCPLinkVerify).Seconds()

	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %s\n", benchmark.FormatDurationSeconds(totalVerifyTime))
	fmt.Println("✅ ALL LAMPBATCH PROOFS VERIFIED SUCCESSFULLY!")

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

	return benchmark.LAMPBATCHResult{
		LogK:              logK,
		Rho:               rhoStr,
		Linker:            linkerQALink,
		Merkle:            merkle,
		Batch:             batch,
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

func buildDomains(K, N int) ([]fr.Element, []fr.Element, []fr.Element, []fr.Element) {
	domainK := fft.NewDomain(uint64(K))
	rootsK := crypto.GetDomainRoots(domainK, K)
	weightsK := crypto.PrecomputeBarycentricWeights(rootsK)

	domainN := fft.NewDomain(uint64(N))
	rootsN := crypto.GetDomainRoots(domainN, N)
	weightsN := crypto.PrecomputeBarycentricWeights(rootsN)

	return rootsK, weightsK, rootsN, weightsN
}

func newLAMPBATCHCircuit(K, N, batch, L int, rootsK, weightsK, rootsN, weightsN []fr.Element) *circuit.LAMPBATCHCircuit {
	c := &circuit.LAMPBATCHCircuit{
		K: K, N: N, Batch: batch,
		DomainK: rootsK, WeightsK: weightsK,
		DomainN: rootsN, WeightsN: weightsN,
		Indices:          make([]frontend.Variable, L),
		ColsEncABC:       make([][]frontend.Variable, L),
		QueriedEncValues: make([][]frontend.Variable, L),
		VecX:             make([][]frontend.Variable, batch),
		EncX:             make([][]frontend.Variable, batch),
		VecW:             make([]frontend.Variable, K),
		EncW:             make([]frontend.Variable, N),
		VecBTest:         make([]frontend.Variable, K),
		EncBTest:         make([]frontend.Variable, N),
	}
	for i := 0; i < L; i++ {
		c.ColsEncABC[i] = make([]frontend.Variable, 3*batch*K)
		c.QueriedEncValues[i] = make([]frontend.Variable, batch+2)
	}
	for i := 0; i < batch; i++ {
		c.VecX[i] = make([]frontend.Variable, K)
		c.EncX[i] = make([]frontend.Variable, N)
	}
	return c
}

func encodeBatchProducts(products []batchProduct, encoder *crypto.Encoder) {
	var wg sync.WaitGroup
	errs := make([]error, len(products))
	for i := range products {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			products[i].ColsEncA, err = encoder.EncodeRowsToColumns(products[i].A)
			if err != nil {
				errs[i] = fmt.Errorf("batch item %d A: %w", i, err)
				return
			}
			products[i].ColsEncB, err = encoder.EncodeRowsToColumns(products[i].B)
			if err != nil {
				errs[i] = fmt.Errorf("batch item %d B: %w", i, err)
				return
			}
			products[i].ColsEncC, err = encoder.EncodeRowsToColumns(products[i].C)
			if err != nil {
				errs[i] = fmt.Errorf("batch item %d C: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			log.Fatalf("❌ Matrix encoding failed: %v", err)
		}
	}
}

func buildABCBlocks(products []batchProduct, N, K int) [][]fr.Element {
	blocks := make([][]fr.Element, N)
	for col := 0; col < N; col++ {
		block := make([]fr.Element, 0, 3*len(products)*K)
		for i := range products {
			block = append(block, products[i].ColsEncA[col]...)
			block = append(block, products[i].ColsEncB[col]...)
			block = append(block, products[i].ColsEncC[col]...)
		}
		blocks[col] = block
	}
	return blocks
}

func buildXYZBlocks(products []batchProduct, encW, encBTest []fr.Element, N int) [][]fr.Element {
	blocks := make([][]fr.Element, N)
	for col := 0; col < N; col++ {
		block := make([]fr.Element, 0, len(products)+2)
		for i := range products {
			block = append(block, products[i].EncX[col])
		}
		block = append(block, encW[col])
		block = append(block, encBTest[col])
		blocks[col] = block
	}
	return blocks
}

func fillLAMPBATCHAssignment(
	assignment *circuit.LAMPBATCHCircuit,
	products []batchProduct,
	vecW []fr.Element,
	encW []fr.Element,
	vecBTest []fr.Element,
	encBTest []fr.Element,
	abcBlocks [][]fr.Element,
	xyzBlocks [][]fr.Element,
	indices []int,
	K, N int,
) {
	for i := range products {
		for j := 0; j < K; j++ {
			assignment.VecX[i][j] = products[i].VecX[j]
		}
		for j := 0; j < N; j++ {
			assignment.EncX[i][j] = products[i].EncX[j]
		}
	}
	for j := 0; j < K; j++ {
		assignment.VecW[j] = vecW[j]
	}
	for j := 0; j < N; j++ {
		assignment.EncW[j] = encW[j]
	}
	for j := 0; j < K; j++ {
		assignment.VecBTest[j] = vecBTest[j]
	}
	for j := 0; j < N; j++ {
		assignment.EncBTest[j] = encBTest[j]
	}
	for q, idx := range indices {
		assignment.Indices[q] = idx
		copyElementsToVariables(assignment.ColsEncABC[q], abcBlocks[idx])
		copyElementsToVariables(assignment.QueriedEncValues[q], xyzBlocks[idx])
	}
}

func copyElementsToVariables(dst []frontend.Variable, src []fr.Element) {
	for i := range src {
		dst[i] = src[i]
	}
}

func addScaledVector(dst []fr.Element, src []fr.Element, scale fr.Element) {
	for i := range dst {
		var term fr.Element
		term.Mul(&scale, &src[i])
		dst[i].Add(&dst[i], &term)
	}
}

func selectBlocksAndOpenings(blocks [][]fr.Element, leaves []bn254.G1Affine, blindings []fr.Element, indices []int) ([][]fr.Element, []bn254.G1Affine, []fr.Element) {
	selectedBlocks := make([][]fr.Element, 0, len(indices))
	selectedCommitments := make([]bn254.G1Affine, 0, len(indices))
	selectedBlindings := make([]fr.Element, 0, len(indices))
	for _, idx := range indices {
		selectedBlocks = append(selectedBlocks, blocks[idx])
		selectedCommitments = append(selectedCommitments, leaves[idx])
		selectedBlindings = append(selectedBlindings, blindings[idx])
	}
	return selectedBlocks, selectedCommitments, selectedBlindings
}

func verifyTranscript(
	rootABC fr.Element,
	rootXYZ fr.Element,
	cmABC fr.Element,
	cmXYZ fr.Element,
	challengeR fr.Element,
	challengeB fr.Element,
	gamma fr.Element,
	indices []int,
	N, L int,
) {
	expectedCmABC := crypto.HashElementsMiMC(rootABC)
	expectedChallengeR := deriveLAMPBATCHChallenge(expectedCmABC, labelChallengeR)
	expectedChallengeB := deriveLAMPBATCHChallenge(expectedCmABC, labelChallengeB)
	expectedGamma := deriveLAMPBATCHChallenge(expectedCmABC, labelGamma)
	expectedCmXYZ := crypto.HashElementsMiMC(rootXYZ)
	expectedIndices, err := protocol.GenerateIndicesWithLabel(expectedCmXYZ, labelQueries, N, L)
	if err != nil {
		log.Fatalf("❌ Query index derivation failed: %v", err)
	}

	if !cmABC.Equal(&expectedCmABC) || !challengeR.Equal(&expectedChallengeR) || !challengeB.Equal(&expectedChallengeB) || !gamma.Equal(&expectedGamma) || !cmXYZ.Equal(&expectedCmXYZ) {
		log.Fatal("❌ Transcript derivation failed")
	}
	for i := range indices {
		if indices[i] != expectedIndices[i] {
			log.Fatal("❌ Query index derivation failed")
		}
	}
}

func deriveLAMPBATCHChallenge(seed fr.Element, label uint64) fr.Element {
	return crypto.HashElements(seed, uint64Element(label))
}

func selectCommitments(leaves []bn254.G1Affine, indices []int) []bn254.G1Affine {
	out := make([]bn254.G1Affine, len(indices))
	for i, idx := range indices {
		out[i] = leaves[idx]
	}
	return out
}

func lampBatchLinkContext(roots []fr.Element, indices []int, batch, K, N, L int) []fr.Element {
	context := make([]fr.Element, 0, 7+len(roots)+len(indices))
	context = append(
		context,
		uint64Element(0x4c414d504c494e4b), // "LAMPLINK"
		uint64Element(uint64(batch)),
		uint64Element(uint64(K)),
		uint64Element(uint64(N)),
		uint64Element(uint64(L)),
		uint64Element(uint64(len(indices))),
	)
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
