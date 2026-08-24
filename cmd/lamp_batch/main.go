package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Han-16/lamp/benchmark"
	"github.com/Han-16/lamp/circuit"
	"github.com/Han-16/lamp/config"
	"github.com/Han-16/lamp/crypto"
	"github.com/Han-16/lamp/matrix"
	"github.com/Han-16/lamp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	linkerQABatch = "qa_batch"
)

const (
	merkleSingle = "single"
	merkleMulti  = "multi"
)

const (
	labelChallengeR = 0x524c4352 // "RLCR"
	labelGamma      = 0x524c4347 // "RLCG"
	labelQueries    = 0x524c4351 // "RLCQ"
	labelRSXBase    = 1000
	labelRSW        = 2000
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
	LFlag := flag.Int("L", config.GetInt("LAMP_BATCH_L", 128), "Number of unique indices L")
	batchFlag := flag.Int("batch", config.GetInt("LAMP_BATCH_SIZE", 5), "Number of matrix multiplications in the batch")
	merkleFlag := flag.String("merkle", config.GetString("LAMP_BATCH_MERKLE", merkleMulti), "Merkle opening backend: single or multi")
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
				res := runExperiment(logK, *rhoFlag, *LFlag, batch, *merkleFlag, onlyCompile)
				benchmark.AppendLAMPBATCHResultToCSV(writer, res)
			}
		}
	} else {
		res := runExperiment(*logKFlag, *rhoFlag, *LFlag, *batchFlag, *merkleFlag, onlyCompile)
		benchmark.AppendLAMPBATCHResultToCSV(writer, res)
	}
	fmt.Println("🎉 All LAMPBATCH tasks finished!")
}

func runExperiment(logK int, rhoStr string, L int, batch int, merkle string, onlyCompile bool) benchmark.LAMPBATCHResult {
	merkle = normalizeMerkle(merkle)
	if batch <= 0 {
		log.Fatalf("batch must be positive, got %d", batch)
	}

	K := 1 << logK
	N := K << 1
	if rhoStr == "1/4" {
		N = K << 2
	} else if rhoStr != "1/2" {
		log.Fatalf("unsupported rho %q; use 1/2 or 1/4", rhoStr)
	}
	if L > N {
		log.Fatalf("L=%d exceeds codeword length N=%d", L, N)
	}
	depth := int(math.Log2(float64(N)))
	field := ecc.BLS12_381.ScalarField()

	fmt.Printf("🔥 [LAMPBATCH Protocol] logK=%d, K=%d, N=%d, L=%d, batch=%d, linker=%s, merkle=%s\n", logK, K, N, L, batch, linkerQABatch, merkle)

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
			LogK:        logK,
			Rho:         rhoStr,
			Linker:      linkerQABatch,
			Merkle:      merkle,
			Batch:       batch,
			N:           N,
			NumQueries:  L,
			Constraints: nbConstraints,
		}
	}

	var protocolSetupTime float64
	var circuitSetupTime float64
	var cpLinkSetupTime float64

	startProtocolSetup := time.Now()
	ckABC := crypto.SetupCommitKey(3 * batch * K)
	ckXYZ := crypto.SetupCommitKey(batch + 1)
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
	encodeBatchProducts(products, encoder)
	abcBlocks := buildABCBlocks(products, N, K)
	leavesABC, blABC := crypto.BatchPedersenCommitBlinded(abcBlocks, ckABC)
	treeABC, rootABC := crypto.BuildMerkleTreeFromGroupElements(leavesABC, depth)

	cmABC := crypto.HashElementsMiMC(rootABC)
	challengeR := deriveLAMPBATCHChallenge(cmABC, labelChallengeR)
	gamma := deriveLAMPBATCHChallenge(cmABC, labelGamma)
	rPowers := matrix.Powers(challengeR, K)
	gammaPowers := matrix.Powers(gamma, batch)
	matCommitTime := time.Since(startMatCommit).Seconds()

	startVecCommit := time.Now()
	vecW := make([]fr.Element, K)
	for i := range products {
		products[i].VecX = matrix.VecMatMul(rPowers, products[i].A, K)
		_, encX, err := encoder.Encode(products[i].VecX)
		if err != nil {
			log.Fatalf("❌ Failed to encode VecX for batch item %d: %v", i, err)
		}
		products[i].EncX = encX

		yi := matrix.VecMatMul(products[i].VecX, products[i].B, K)
		addScaledVector(vecW, yi, gammaPowers[i])
	}
	_, encW, err := encoder.Encode(vecW)
	if err != nil {
		log.Fatalf("❌ Failed to encode batch output vector: %v", err)
	}

	xyzBlocks := buildXYZBlocks(products, encW, N)
	leavesXYZ, blXYZ := crypto.BatchPedersenCommitBlinded(xyzBlocks, ckXYZ)
	treeXYZ, rootXYZ := crypto.BuildMerkleTreeFromGroupElements(leavesXYZ, depth)

	cmXYZ := crypto.HashElementsMiMC(rootXYZ)
	indices, err := protocol.GenerateUniqueIndicesWithLabel(cmXYZ, labelQueries, N, L)
	if err != nil {
		log.Fatalf("❌ Failed to sample query indices: %v", err)
	}
	rsPointsX := make([]fr.Element, batch)
	for i := range rsPointsX {
		rsPointsX[i], err = protocol.GenerateRSEvaluationPointWithLabel(cmXYZ, labelRSXBase+uint64(i), N, nil)
		if err != nil {
			log.Fatalf("❌ Failed to sample RS point for X batch item %d: %v", i, err)
		}
	}
	rsPointW, err := protocol.GenerateRSEvaluationPointWithLabel(cmXYZ, labelRSW, N, nil)
	if err != nil {
		log.Fatalf("❌ Failed to sample RS point for W: %v", err)
	}
	vecCommitTime := time.Since(startVecCommit).Seconds()

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
	assignment.Gamma = gamma
	assignment.RSPointW = rsPointW
	for i := range rsPointsX {
		assignment.RSPointsX[i] = rsPointsX[i]
	}

	fillLAMPBATCHAssignment(assignment, products, vecW, encW, abcBlocks, xyzBlocks, indices, K, N)

	startProtocolBindSetup := time.Now()
	proverWithPK := protocol.NewProver(pk, ckABC, encoder)
	verifier := protocol.NewVerifier(vk, ckABC, proverWithPK.CK2)
	protocolSetupTime += time.Since(startProtocolBindSetup).Seconds()

	columnCommitIndex, scalarCommitIndex := findCommitmentKeys(proverWithPK.CK2, L*3*batch*K, L*(batch+1))
	if columnCommitIndex < 0 || scalarCommitIndex < 0 {
		log.Fatalf("❌ Grouped commitment mismatch: expected grouped column len=%d and scalar len=%d", L*3*batch*K, L*(batch+1))
	}

	startCPLinkSetup := time.Now()
	columnQABatchPK, columnQABatchVK, err := crypto.SetupQABatchLink(L, 3*batch*K, proverWithPK.CK2[columnCommitIndex], ckABC)
	if err != nil {
		log.Fatalf("❌ Column QA-batch setup failed: %v", err)
	}
	scalarQABatchPK, scalarQABatchVK, err := crypto.SetupQABatchLink(L, batch+1, proverWithPK.CK2[scalarCommitIndex], ckXYZ)
	if err != nil {
		log.Fatalf("❌ Scalar QA-batch setup failed: %v", err)
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
	var mpABC [][]fr.Element
	var mpXYZ [][]fr.Element
	var mmpABC crypto.MerkleMultiProof
	var mmpXYZ crypto.MerkleMultiProof

	startMerkleProve := time.Now()
	switch merkle {
	case merkleSingle:
		mpABC = make([][]fr.Element, L)
		mpXYZ = make([][]fr.Element, L)
		for i, idx := range indices {
			mpABC[i] = proverWithPK.GenerateMembershipProof(treeABC, idx, depth)
			mpXYZ[i] = proverWithPK.GenerateMembershipProof(treeXYZ, idx, depth)
		}
	case merkleMulti:
		mmpABC = crypto.GetMerkleMultiProof(treeABC, indices, depth)
		mmpXYZ = crypto.GetMerkleMultiProof(treeXYZ, indices, depth)
	default:
		log.Fatalf("unsupported merkle opening %q", merkle)
	}
	merkleProveTime := time.Since(startMerkleProve).Seconds()

	startCPLinkProve := time.Now()
	columnBlocks, columnExternalCommitments, columnExternalBlindings := selectBlocksAndOpenings(abcBlocks, leavesABC, blABC, indices)
	scalarBlocks, scalarExternalCommitments, scalarExternalBlindings := selectBlocksAndOpenings(xyzBlocks, leavesXYZ, blXYZ, indices)

	columnContext := lampBatchQABatchContext(1, []fr.Element{rootABC}, indices, batch, K, N, L)
	scalarContext := lampBatchQABatchContext(2, []fr.Element{rootXYZ}, indices, batch, K, N, L)

	columnQABatchProof, err := crypto.ProveQABatchLink(
		columnBlocks,
		blindingsIn[columnCommitIndex],
		columnExternalBlindings,
		columnQABatchPK,
		cmVec2[columnCommitIndex],
		columnExternalCommitments,
		columnContext...,
	)
	if err != nil {
		log.Fatalf("❌ Column QA-batch proof failed: %v", err)
	}
	scalarQABatchProof, err := crypto.ProveQABatchLink(
		scalarBlocks,
		blindingsIn[scalarCommitIndex],
		scalarExternalBlindings,
		scalarQABatchPK,
		cmVec2[scalarCommitIndex],
		scalarExternalCommitments,
		scalarContext...,
	)
	if err != nil {
		log.Fatalf("❌ Scalar QA-batch proof failed: %v", err)
	}
	cpLinkProveTime := time.Since(startCPLinkProve).Seconds()

	publicWitness, err := proofWitness.Public()
	if err != nil {
		log.Fatalf("❌ Failed to create public witness for verification: %v", err)
	}

	fmt.Println("=== Verifying All Proofs ===")
	startVerify := time.Now()
	verifyTranscript(rootABC, rootXYZ, cmABC, cmXYZ, challengeR, gamma, indices, rsPointsX, rsPointW, N, L)

	startCircuitVerify := time.Now()
	if err := groth16.Verify(circuitProof, vk, publicWitness); err != nil {
		log.Fatalf("❌ Groth16 Verify failed: %v", err)
	}
	circuitVerifyTime := time.Since(startCircuitVerify).Seconds()

	startMerkleVerify := time.Now()
	switch merkle {
	case merkleSingle:
		for i, idx := range indices {
			if !verifier.VerifyMembership(rootABC, leavesABC[idx], mpABC[i], idx, depth) {
				log.Fatal("❌ Merkle ABC failed")
			}
			if !verifier.VerifyMembership(rootXYZ, leavesXYZ[idx], mpXYZ[i], idx, depth) {
				log.Fatal("❌ Merkle XYZ failed")
			}
		}
	case merkleMulti:
		if !verifier.VerifyMultiMembership(rootABC, selectCommitments(leavesABC, indices), indices, mmpABC, depth) {
			log.Fatal("❌ Merkle ABC multiproof failed")
		}
		if !verifier.VerifyMultiMembership(rootXYZ, selectCommitments(leavesXYZ, indices), indices, mmpXYZ, depth) {
			log.Fatal("❌ Merkle XYZ multiproof failed")
		}
	default:
		log.Fatalf("unsupported merkle opening %q", merkle)
	}
	merkleVerifyTime := time.Since(startMerkleVerify).Seconds()

	startCPLinkVerify := time.Now()
	if !crypto.VerifyQABatchLink(cmVec2[columnCommitIndex], columnExternalCommitments, columnQABatchProof, columnQABatchVK, columnContext...) {
		log.Fatal("❌ Column QA-batch link failed")
	}
	if !crypto.VerifyQABatchLink(cmVec2[scalarCommitIndex], scalarExternalCommitments, scalarQABatchProof, scalarQABatchVK, scalarContext...) {
		log.Fatal("❌ Scalar QA-batch link failed")
	}
	cpLinkVerifyTime := time.Since(startCPLinkVerify).Seconds()

	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Printf("   ✅ Verify Time: %s\n", benchmark.FormatDurationSeconds(totalVerifyTime))
	fmt.Println("✅ ALL LAMPBATCH PROOFS VERIFIED SUCCESSFULLY!")

	totalProveTime := matCommitTime + vecCommitTime + merkleProveTime + circuitProveTime + cpLinkProveTime

	var buf bytes.Buffer
	circuitProof.WriteTo(&buf)
	groth16ProofSize := buf.Len()

	merkleProofSize := 0
	switch merkle {
	case merkleSingle:
		merkleProofSize = L*2*depth*crypto.MerkleHashSizeBytes + L*2*crypto.G1AffineSizeBytes
	case merkleMulti:
		merkleProofSize = crypto.MerkleMultiProofSizeBytes(mmpABC) +
			crypto.MerkleMultiProofSizeBytes(mmpXYZ) +
			L*2*crypto.G1AffineSizeBytes
	}

	cpLinkProofSize := crypto.QABatchLinkProofSizeBytes(columnQABatchProof) + crypto.QABatchLinkProofSizeBytes(scalarQABatchProof)
	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize

	fmt.Printf("📊 Proof Sizes -> Groth16: %d B, Merkle: %d B, CPLink: %d B | Total: %d B\n",
		groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.LAMPBATCHResult{
		LogK:              logK,
		Rho:               rhoStr,
		Linker:            linkerQABatch,
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
		Indices:    make([]frontend.Variable, L),
		RSPointsX:  make([]frontend.Variable, batch),
		ColsEncABC: make([][]frontend.Variable, L),
		TargetXYZ:  make([][]frontend.Variable, L),
		VecX:       make([][]frontend.Variable, batch),
		EncX:       make([][]frontend.Variable, batch),
		VecW:       make([]frontend.Variable, K),
		EncW:       make([]frontend.Variable, N),
	}
	for i := 0; i < L; i++ {
		c.ColsEncABC[i] = make([]frontend.Variable, 3*batch*K)
		c.TargetXYZ[i] = make([]frontend.Variable, batch+1)
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

func buildXYZBlocks(products []batchProduct, encW []fr.Element, N int) [][]fr.Element {
	blocks := make([][]fr.Element, N)
	for col := 0; col < N; col++ {
		block := make([]fr.Element, 0, len(products)+1)
		for i := range products {
			block = append(block, products[i].EncX[col])
		}
		block = append(block, encW[col])
		blocks[col] = block
	}
	return blocks
}

func fillLAMPBATCHAssignment(
	assignment *circuit.LAMPBATCHCircuit,
	products []batchProduct,
	vecW []fr.Element,
	encW []fr.Element,
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
	for q, idx := range indices {
		assignment.Indices[q] = idx
		copyElementsToVariables(assignment.ColsEncABC[q], abcBlocks[idx])
		copyElementsToVariables(assignment.TargetXYZ[q], xyzBlocks[idx])
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

func findCommitmentKeys(keys []crypto.CommitKey, columnLen, scalarLen int) (int, int) {
	columnCommitIndex := -1
	scalarCommitIndex := -1
	for i, ck := range keys {
		switch len(ck.G) {
		case columnLen:
			columnCommitIndex = i
		case scalarLen:
			scalarCommitIndex = i
		}
	}
	return columnCommitIndex, scalarCommitIndex
}

func selectBlocksAndOpenings(blocks [][]fr.Element, leaves []bls12381.G1Affine, blindings []fr.Element, indices []int) ([][]fr.Element, []bls12381.G1Affine, []fr.Element) {
	selectedBlocks := make([][]fr.Element, 0, len(indices))
	selectedCommitments := make([]bls12381.G1Affine, 0, len(indices))
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
	gamma fr.Element,
	indices []int,
	rsPointsX []fr.Element,
	rsPointW fr.Element,
	N, L int,
) {
	expectedCmABC := crypto.HashElementsMiMC(rootABC)
	expectedChallengeR := deriveLAMPBATCHChallenge(expectedCmABC, labelChallengeR)
	expectedGamma := deriveLAMPBATCHChallenge(expectedCmABC, labelGamma)
	expectedCmXYZ := crypto.HashElementsMiMC(rootXYZ)
	expectedIndices, err := protocol.GenerateUniqueIndicesWithLabel(expectedCmXYZ, labelQueries, N, L)
	if err != nil {
		log.Fatalf("❌ Query index derivation failed: %v", err)
	}

	if !cmABC.Equal(&expectedCmABC) || !challengeR.Equal(&expectedChallengeR) || !gamma.Equal(&expectedGamma) || !cmXYZ.Equal(&expectedCmXYZ) {
		log.Fatal("❌ Transcript derivation failed")
	}
	for i := range indices {
		if indices[i] != expectedIndices[i] {
			log.Fatal("❌ Query index derivation failed")
		}
	}
	for i := range rsPointsX {
		expected, err := protocol.GenerateRSEvaluationPointWithLabel(expectedCmXYZ, labelRSXBase+uint64(i), N, nil)
		if err != nil {
			log.Fatalf("❌ RS point X derivation failed: %v", err)
		}
		if !rsPointsX[i].Equal(&expected) {
			log.Fatal("❌ RS point X derivation failed")
		}
	}
	expectedRSPointW, err := protocol.GenerateRSEvaluationPointWithLabel(expectedCmXYZ, labelRSW, N, nil)
	if err != nil {
		log.Fatalf("❌ RS point W derivation failed: %v", err)
	}
	if !rsPointW.Equal(&expectedRSPointW) {
		log.Fatal("❌ RS point W derivation failed")
	}
}

func deriveLAMPBATCHChallenge(seed fr.Element, label uint64) fr.Element {
	return crypto.HashElements(seed, uint64Element(label))
}

func normalizeMerkle(merkle string) string {
	switch strings.ToLower(strings.TrimSpace(merkle)) {
	case "":
		return merkleMulti
	case merkleSingle:
		return merkleSingle
	case merkleMulti:
		return merkleMulti
	default:
		log.Fatalf("unsupported merkle opening %q; use %q or %q", merkle, merkleSingle, merkleMulti)
	}
	return merkleMulti
}

func selectCommitments(leaves []bls12381.G1Affine, indices []int) []bls12381.G1Affine {
	out := make([]bls12381.G1Affine, len(indices))
	for i, idx := range indices {
		out[i] = leaves[idx]
	}
	return out
}

func lampBatchQABatchContext(label uint64, roots []fr.Element, indices []int, batch, K, N, L int) []fr.Element {
	context := make([]fr.Element, 0, 8+len(roots)+len(indices))
	context = append(
		context,
		uint64Element(0x4c414d5042415443), // "LAMPBATC"
		uint64Element(label),
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
