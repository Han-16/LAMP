package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"strings"
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
	gpt2LogD          = 10
	gpt2LogDh         = 6
	gpt2LogM          = 12
	gpt2D             = 1 << gpt2LogD
	gpt2Dh            = 1 << gpt2LogDh
	gpt2M             = 1 << gpt2LogM
	gpt2Heads         = 16
	gpt2QKVCols       = 3 * gpt2D
	gpt2PackedQKVCols = 4 * gpt2D
)

const (
	linkerQALink = "qa_link"
	merkleMulti  = "multi"
)

const (
	groupS = iota
	groupD
	groupDh
	groupM
	groupScalar
	numGroups
)

type tensor struct {
	id        int
	name      string
	rows      int
	cols      int
	group     int
	data      [][]fr.Element
	colsEnc   [][]fr.Element
	leafStart int
}

type foldedCodeword struct {
	id        int
	name      string
	enc       []fr.Element
	leafStart int
}

type extGroup struct {
	id        int
	blockLen  int
	ck        crypto.CommitKey
	blocks    [][]fr.Element
	commits   []bn254.G1Affine
	blindings []fr.Element
	metas     []crypto.MerkleLeafMeta
	tree      [][]fr.Element
	root      fr.Element
	depth     int
}

type sampleGroup struct {
	blockLen      int
	blocks        [][]fr.Element
	commits       []bn254.G1Affine
	blindings     []fr.Element
	metas         []crypto.MerkleLeafMeta
	leafIndices   []int
	proofs        [][]fr.Element
	multiProof    crypto.MerkleMultiProof
	cache         map[string]int
	merkleProofSz int
}

type claimSpec struct {
	id   int
	name string
	A    *tensor
	B    *tensor
	C    *tensor
}

type claimWitness struct {
	spec       claimSpec
	vecX       []fr.Element
	vecYZ      []fr.Element
	encX       []fr.Element
	encYZ      []fr.Element
	foldX      *foldedCodeword
	foldYZ     *foldedCodeword
	indicesIn  []int
	indicesOut []int
	rsPointX   fr.Element
	rsPointYZ  fr.Element
	skipRSX    bool
	skipRSYZ   bool
}

type rsBatchTermWitness struct {
	claimIndex int
	side       int
}

type rsBatchWitness struct {
	id      int
	name    string
	k       int
	n       int
	terms   []rsBatchTermWitness
	rsPoint fr.Element
}

type preparedLayer struct {
	seqLog int
	seqLen int
	rho    string
	L      int
	merkle string

	extGroups    [numGroups]*extGroup
	sampleGroups [numGroups]*sampleGroup

	tensorCm fr.Element
	globalCm fr.Element

	domainCache map[domainCacheKey]domains

	inputTensor     *tensor
	outputTensor    *tensor
	claims          []claimWitness
	rsBatches       []rsBatchWitness
	equalityChecks  []circuit.LAMPGPT2EntryEqualityCheck
	transposeChecks []circuit.LAMPGPT2TransposeCheck

	scalars          []fr.Element
	scalarBlocks     [][]fr.Element
	scalarCommits    []bn254.G1Affine
	scalarBlindings  []fr.Element
	scalarMetas      []crypto.MerkleLeafMeta
	scalarLeafIdx    []int
	scalarProofs     [][]fr.Element
	scalarMultiProof crypto.MerkleMultiProof
	scalarCache      map[string]int

	matrixComputeTime float64
	setupTime         float64
	commitTime        float64
	merkleProveTime   float64
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	seqFlag := flag.Int("seq", config.GetInt("LAMP_GPT2_SEQ", 1), "Log2 sequence length")
	rhoFlag := flag.String("rho", config.GetString("LAMP_GPT2_RHO", "1/2"), "Code rate, 1/2 or 1/4")
	LFlag := flag.Int("L", config.GetInt("LAMP_GPT2_L", 1), "Number of sampled queries per matmul and wiring check")
	allFlag := flag.Bool("all", config.GetBool("LAMP_GPT2_ALL", false), "Run benchmark range")
	rangeFlag := flag.Bool("range", false, "Alias for -all")
	fromFlag := flag.Int("from", config.GetInt("LAMP_GPT2_SEQ_FROM", 0), "First log2 sequence length when range mode is enabled")
	toFlag := flag.Int("to", config.GetInt("LAMP_GPT2_SEQ_TO", 4), "Last log2 sequence length when range mode is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("LAMP_GPT2_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	flag.Parse()

	outputDir := config.OutputDir("LAMP_GPT2_OUTPUT_DIR", filepath.Join("benchmark", "lamp_gpt2"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "lamp_gpt2_benchmark_results.csv")
	file, writer := benchmark.InitLAMPGPT2CSV(csvPath)
	defer file.Close()

	if *allFlag || *rangeFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid seq range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		fmt.Printf("Running LAMP GPT-2 range: seq=%d..%d, rho=%s, L=%d, linker=%s, merkle=%s\n", *fromFlag, *toFlag, *rhoFlag, *LFlag, linkerQALink, merkleMulti)
		for seqLog := *fromFlag; seqLog <= *toFlag; seqLog++ {
			res := runExperiment(seqLog, *rhoFlag, *LFlag, *compileFlag)
			benchmark.AppendLAMPGPT2ResultToCSV(writer, res)
			fmt.Println("----------------------------------------------------------------")
		}
		return
	}

	res := runExperiment(*seqFlag, *rhoFlag, *LFlag, *compileFlag)
	benchmark.AppendLAMPGPT2ResultToCSV(writer, res)
}

func runExperiment(seqLog int, rho string, L int, onlyCompile bool) benchmark.LAMPGPT2Result {
	linker := linkerQALink
	merkle := merkleMulti
	if seqLog < 0 || L <= 0 {
		log.Fatalf("invalid parameters: seq=%d L=%d", seqLog, L)
	}
	seqLen := 1 << seqLog
	fmt.Printf("LAMP GPT-2 medium packed-QKV layer: seq=2^%d=%d, rho=%s, L=%d, linker=%s, merkle=%s\n", seqLog, seqLen, rho, L, linker, merkle)

	var prep *preparedLayer
	if onlyCompile {
		prep = prepareLayerShapeOnly(seqLog, rho, L)
	} else {
		prep = prepareLayer(seqLog, rho, L)
		fmt.Printf("   ✅ Matrix Compute Time: %.2f s\n", prep.matrixComputeTime)
	}
	emptyCircuit := buildCircuit(prep, false)

	field := ecc.BN254.ScalarField()
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("LAMP GPT-2 compilation failed: %v", err)
	}
	nbConstraints := r1csSystem.GetNbConstraints()

	if onlyCompile {
		fmt.Printf("LAMP GPT-2 circuit compiled. Constraints: %d\n", nbConstraints)
		return benchmark.LAMPGPT2Result{
			SeqLog:            seqLog,
			SeqLen:            seqLen,
			Rho:               rho,
			Linker:            linker,
			Merkle:            merkle,
			NumQueries:        L,
			NumClaims:         len(prep.claims),
			NumCommitGroups:   numGroups,
			Constraints:       nbConstraints,
			MatrixComputeTime: prep.matrixComputeTime,
			SetupTime:         prep.setupTime,
			ProtocolSetupTime: prep.setupTime,
			CommitTime:        prep.commitTime,
			MerkleProveTime:   prep.merkleProveTime,
		}
	}

	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("LAMP GPT-2 setup failed: %v", err)
	}
	circuitSetupTime := time.Since(startSetup).Seconds()
	protocolSetupTime := prep.setupTime

	assignment := buildCircuit(prep, true)
	startProtocolBindSetup := time.Now()
	prover := protocol.NewProver(pk, prep.extGroups[groupS].ck, nil)
	verifier := protocol.NewVerifier(vk, prep.extGroups[groupS].ck, prover.CK2)
	protocolSetupTime += time.Since(startProtocolBindSetup).Seconds()
	if len(prover.CK2) < numGroups {
		log.Fatalf("expected at least %d committed groups, got keys=%d", numGroups, len(prover.CK2))
	}

	cpLinkSetupTime := 0.0
	linkProvingKeys := make([]crypto.QALinkProvingKey, numGroups)
	linkVerifyingKeys := make([]crypto.QALinkVerifyingKey, numGroups)
	startCPLinkSetup := time.Now()
	for groupID := 0; groupID < numGroups; groupID++ {
		blocks, _, _ := prep.sampleCPLinkData(groupID)
		linkPK, linkVK, err := crypto.SetupQALink(len(blocks), prep.extGroups[groupID].blockLen, prover.CK2[groupID], prep.extGroups[groupID].ck)
		if err != nil {
			log.Fatalf("group %d QA-link setup failed: %v", groupID, err)
		}
		linkProvingKeys[groupID] = linkPK
		linkVerifyingKeys[groupID] = linkVK
	}
	cpLinkSetupTime = time.Since(startCPLinkSetup).Seconds()
	setupTime := protocolSetupTime + circuitSetupTime + cpLinkSetupTime

	proofWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("failed to build witness for proving: %v", err)
	}
	startCircuitProve := time.Now()
	proof, err := groth16.Prove(r1csSystem, pk, proofWitness)
	if err != nil {
		log.Fatalf("LAMP GPT-2 proof failed: %v", err)
	}
	circuitProveTime := time.Since(startCircuitProve).Seconds()
	cmVec2, blindingsIn := protocol.ExtractGroth16CommitmentsAndBlindings(proof)
	if len(cmVec2) < numGroups || len(blindingsIn) < numGroups || len(prover.CK2) < numGroups {
		log.Fatalf("expected %d committed groups, got commitments=%d blindings=%d keys=%d", numGroups, len(cmVec2), len(blindingsIn), len(prover.CK2))
	}

	startOffline := time.Now()
	linkProofs := make([]crypto.QALinkProof, numGroups)
	for groupID := 0; groupID < numGroups; groupID++ {
		blocks, _, blindings := prep.sampleCPLinkData(groupID)
		linkProof, err := crypto.ProveQALink(
			blocks,
			blindingsIn[groupID],
			blindings,
			linkProvingKeys[groupID],
		)
		if err != nil {
			log.Fatalf("group %d QA-link proof failed: %v", groupID, err)
		}
		linkProofs[groupID] = linkProof
	}
	cpLinkProveTime := time.Since(startOffline).Seconds()

	publicWitness, err := proofWitness.Public()
	if err != nil {
		log.Fatalf("failed to build public witness: %v", err)
	}

	startVerify := time.Now()
	startCircuitVerify := time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatalf("LAMP GPT-2 Groth16 verification failed: %v", err)
	}
	circuitVerifyTime := time.Since(startCircuitVerify).Seconds()

	startMerkle := time.Now()
	for groupID := 0; groupID < numGroups; groupID++ {
		if !prep.verifyMerkleGroup(verifier, groupID) {
			log.Fatalf("group %d Merkle verification failed", groupID)
		}
	}
	merkleVerifyTime := time.Since(startMerkle).Seconds()

	startCPLink := time.Now()
	linkChecks := make([]crypto.QALinkVerification, 0, numGroups)
	for groupID := 0; groupID < numGroups; groupID++ {
		_, commits, _ := prep.sampleCPLinkData(groupID)
		linkChecks = append(linkChecks, crypto.QALinkVerification{
			SnarkCommit:     cmVec2[groupID],
			ExternalCommits: commits,
			Proof:           linkProofs[groupID],
			VK:              linkVerifyingKeys[groupID],
		})
	}
	if !crypto.VerifyQALinksBatched(linkChecks, prep.linkBatchContext()...) {
		log.Fatal("batched QA-link verification failed")
	}
	cpLinkVerifyTime := time.Since(startCPLink).Seconds()
	totalVerifyTime := time.Since(startVerify).Seconds()

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	groth16ProofSize := buf.Len()
	merkleProofSize := prep.merkleProofSize()
	cpLinkProofSize := 0
	for i := range linkProofs {
		cpLinkProofSize += crypto.QALinkProofSizeBytes(linkProofs[i])
	}
	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize
	totalProveTime := prep.commitTime + prep.merkleProveTime + circuitProveTime + cpLinkProveTime

	fmt.Println("LAMP GPT-2 proof verified successfully")
	fmt.Printf("Proof sizes: Groth16=%d B, Merkle=%d B, CPLink=%d B, Total=%d B\n", groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.LAMPGPT2Result{
		SeqLog:            seqLog,
		SeqLen:            seqLen,
		Rho:               rho,
		Linker:            linker,
		Merkle:            merkle,
		NumQueries:        L,
		NumClaims:         len(prep.claims),
		NumCommitGroups:   numGroups,
		Constraints:       nbConstraints,
		MatrixComputeTime: prep.matrixComputeTime,
		SetupTime:         setupTime,
		ProtocolSetupTime: protocolSetupTime,
		CircuitSetupTime:  circuitSetupTime,
		CPLinkSetupTime:   cpLinkSetupTime,
		CommitTime:        prep.commitTime,
		MerkleProveTime:   prep.merkleProveTime,
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

func prepareLayer(seqLog int, rho string, L int) *preparedLayer {
	seqLen := 1 << seqLog
	p := &preparedLayer{
		seqLog:      seqLog,
		seqLen:      seqLen,
		rho:         rho,
		L:           L,
		merkle:      merkleMulti,
		domainCache: make(map[domainCacheKey]domains),
		scalarCache: make(map[string]int),
	}

	p.initGroups()

	tensors, specs, matrixComputeTime := buildGPT2MediumTensors(seqLen)
	byName := tensorMap(tensors)
	p.inputTensor = byName["X"]
	p.outputTensor = byName["Out"]
	p.matrixComputeTime = matrixComputeTime

	startCommit := time.Now()
	for _, t := range tensors {
		p.commitTensor(t, rho)
	}
	for i := 0; i < groupScalar; i++ {
		p.buildGroupTree(i)
	}
	p.tensorCm = crypto.HashElementsMiMC(p.extGroups[groupS].root, p.extGroups[groupD].root, p.extGroups[groupDh].root, p.extGroups[groupM].root)

	for _, spec := range specs {
		p.claims = append(p.claims, p.prepareClaim(spec))
	}
	p.buildGroupTree(groupScalar)
	p.globalCm = crypto.HashElementsMiMC(p.extGroups[groupS].root, p.extGroups[groupD].root, p.extGroups[groupDh].root, p.extGroups[groupM].root, p.extGroups[groupScalar].root)

	p.addScoreValueRSBatches()
	for i := range p.claims {
		p.sampleClaim(&p.claims[i])
	}
	p.addClaimSamples()
	p.addPackedAttentionChecks(tensors, L)
	p.generateMerkleMultiProofs()
	p.commitTime = time.Since(startCommit).Seconds() - p.merkleProveTime
	if p.commitTime < 0 {
		p.commitTime = 0
	}

	return p
}

func prepareLayerShapeOnly(seqLog int, rho string, L int) *preparedLayer {
	seqLen := 1 << seqLog
	p := &preparedLayer{
		seqLog:      seqLog,
		seqLen:      seqLen,
		rho:         rho,
		L:           L,
		merkle:      merkleMulti,
		domainCache: make(map[domainCacheKey]domains),
		scalarCache: make(map[string]int),
	}
	p.initGroups()

	tensors, specs := buildGPT2MediumTensorShapes(seqLen)
	byName := tensorMap(tensors)
	p.inputTensor = byName["X"]
	p.outputTensor = byName["Out"]
	for _, spec := range specs {
		p.claims = append(p.claims, claimWitness{spec: spec})
	}
	p.addScoreValueRSBatches()
	p.addPackedAttentionChecks(tensors, L)
	return p
}

func (p *preparedLayer) initGroups() {
	startSetup := time.Now()
	p.extGroups[groupS] = newExtGroup(groupS, p.seqLen)
	p.extGroups[groupD] = newExtGroup(groupD, gpt2D)
	p.extGroups[groupDh] = newExtGroup(groupDh, gpt2Dh)
	p.extGroups[groupM] = newExtGroup(groupM, gpt2M)
	p.extGroups[groupScalar] = newExtGroup(groupScalar, 1)
	p.setupTime += time.Since(startSetup).Seconds()
	for i := 0; i < numGroups; i++ {
		p.sampleGroups[i] = &sampleGroup{
			blockLen: p.extGroups[i].blockLen,
			cache:    make(map[string]int),
		}
	}
}

func newExtGroup(id, blockLen int) *extGroup {
	return &extGroup{
		id:       id,
		blockLen: blockLen,
		ck:       crypto.SetupCommitKey(blockLen),
	}
}

func buildGPT2MediumTensors(seqLen int) ([]*tensor, []claimSpec, float64) {
	nextID := 0
	tensors := make([]*tensor, 0)
	claims := make([]claimSpec, 0)
	var matrixComputeTime time.Duration

	newTensor := func(name string, data [][]fr.Element, group int) *tensor {
		rows := len(data)
		cols := len(data[0])
		t := &tensor{id: nextID, name: name, rows: rows, cols: cols, group: group, data: data}
		nextID++
		tensors = append(tensors, t)
		return t
	}
	addClaim := func(name string, A, B, C *tensor) {
		claims = append(claims, claimSpec{id: len(claims), name: name, A: A, B: B, C: C})
	}
	matMulRect := func(A, B [][]fr.Element, rows, inner, cols int) [][]fr.Element {
		start := time.Now()
		out := matrix.MatMulRect(A, B, rows, inner, cols)
		matrixComputeTime += time.Since(start)
		return out
	}

	X := newTensor("X", matrix.GenerateRandomMatrix(seqLen, gpt2D), groupS)

	WQKV := newTensor("WQKV", generatePaddedQKVWeights(), groupD)
	QKV := newTensor("QKV", matMulRect(X.data, WQKV.data, seqLen, gpt2D, gpt2PackedQKVCols), groupS)
	addClaim("qkv_proj", X, WQKV, QKV)

	Ctxs := make([]*tensor, gpt2Heads)
	for h := 0; h < gpt2Heads; h++ {
		Q := newTensor(fmt.Sprintf("Q_%02d", h), sliceColumns(QKV.data, h*gpt2Dh, gpt2Dh), groupS)
		K := newTensor(fmt.Sprintf("K_%02d", h), sliceColumns(QKV.data, gpt2D+h*gpt2Dh, gpt2Dh), groupS)
		V := newTensor(fmt.Sprintf("V_%02d", h), sliceColumns(QKV.data, 2*gpt2D+h*gpt2Dh, gpt2Dh), groupS)
		KT := newTensor(fmt.Sprintf("KT_%02d", h), matrix.Transpose(K.data, seqLen, gpt2Dh), groupDh)

		Score := newTensor(fmt.Sprintf("Score_%02d", h), matMulRect(Q.data, KT.data, seqLen, gpt2Dh, seqLen), groupS)
		Ctx := newTensor(fmt.Sprintf("Ctx_%02d", h), matMulRect(Score.data, V.data, seqLen, seqLen, gpt2Dh), groupS)
		Ctxs[h] = Ctx

		addClaim(fmt.Sprintf("score_%02d", h), Q, KT, Score)
		addClaim(fmt.Sprintf("value_%02d", h), Score, V, Ctx)
	}

	Context := newTensor("Context", concatHeadColumns(Ctxs, seqLen), groupS)
	Wout := newTensor("Wout", matrix.GenerateRandomMatrix(gpt2D, gpt2D), groupD)
	AttnOut := newTensor("AttnOut", matMulRect(Context.data, Wout.data, seqLen, gpt2D, gpt2D), groupS)
	Wup := newTensor("Wup", matrix.GenerateRandomMatrix(gpt2D, gpt2M), groupD)
	Hidden := newTensor("Hidden", matMulRect(AttnOut.data, Wup.data, seqLen, gpt2D, gpt2M), groupS)
	Wdown := newTensor("Wdown", matrix.GenerateRandomMatrix(gpt2M, gpt2D), groupM)
	Out := newTensor("Out", matMulRect(Hidden.data, Wdown.data, seqLen, gpt2M, gpt2D), groupS)

	addClaim("attn_out", Context, Wout, AttnOut)
	addClaim("mlp_up", AttnOut, Wup, Hidden)
	addClaim("mlp_down", Hidden, Wdown, Out)

	return tensors, claims, matrixComputeTime.Seconds()
}

func generatePaddedQKVWeights() [][]fr.Element {
	weights := make([][]fr.Element, gpt2D)
	qkv := matrix.GenerateRandomMatrix(gpt2D, gpt2QKVCols)
	for row := 0; row < gpt2D; row++ {
		weights[row] = make([]fr.Element, gpt2PackedQKVCols)
		copy(weights[row], qkv[row])
	}
	return weights
}

func sliceColumns(data [][]fr.Element, offset, width int) [][]fr.Element {
	out := make([][]fr.Element, len(data))
	for row := range data {
		out[row] = make([]fr.Element, width)
		copy(out[row], data[row][offset:offset+width])
	}
	return out
}

func concatHeadColumns(heads []*tensor, rows int) [][]fr.Element {
	out := make([][]fr.Element, rows)
	for row := 0; row < rows; row++ {
		out[row] = make([]fr.Element, gpt2D)
		for h := 0; h < gpt2Heads; h++ {
			copy(out[row][h*gpt2Dh:(h+1)*gpt2Dh], heads[h].data[row])
		}
	}
	return out
}

func buildGPT2MediumTensorShapes(seqLen int) ([]*tensor, []claimSpec) {
	nextID := 0
	tensors := make([]*tensor, 0)
	claims := make([]claimSpec, 0)

	newTensor := func(name string, rows, cols int, group int) *tensor {
		t := &tensor{id: nextID, name: name, rows: rows, cols: cols, group: group}
		nextID++
		tensors = append(tensors, t)
		return t
	}
	addClaim := func(name string, A, B, C *tensor) {
		claims = append(claims, claimSpec{id: len(claims), name: name, A: A, B: B, C: C})
	}

	X := newTensor("X", seqLen, gpt2D, groupS)
	WQKV := newTensor("WQKV", gpt2D, gpt2PackedQKVCols, groupD)
	QKV := newTensor("QKV", seqLen, gpt2PackedQKVCols, groupS)
	addClaim("qkv_proj", X, WQKV, QKV)

	Ctxs := make([]*tensor, gpt2Heads)
	for h := 0; h < gpt2Heads; h++ {
		Q := newTensor(fmt.Sprintf("Q_%02d", h), seqLen, gpt2Dh, groupS)
		newTensor(fmt.Sprintf("K_%02d", h), seqLen, gpt2Dh, groupS)
		V := newTensor(fmt.Sprintf("V_%02d", h), seqLen, gpt2Dh, groupS)
		KT := newTensor(fmt.Sprintf("KT_%02d", h), gpt2Dh, seqLen, groupDh)
		Score := newTensor(fmt.Sprintf("Score_%02d", h), seqLen, seqLen, groupS)
		Ctx := newTensor(fmt.Sprintf("Ctx_%02d", h), seqLen, gpt2Dh, groupS)
		Ctxs[h] = Ctx

		addClaim(fmt.Sprintf("score_%02d", h), Q, KT, Score)
		addClaim(fmt.Sprintf("value_%02d", h), Score, V, Ctx)
	}

	Context := newTensor("Context", seqLen, gpt2D, groupS)
	_ = Ctxs
	Wout := newTensor("Wout", gpt2D, gpt2D, groupD)
	AttnOut := newTensor("AttnOut", seqLen, gpt2D, groupS)
	Wup := newTensor("Wup", gpt2D, gpt2M, groupD)
	Hidden := newTensor("Hidden", seqLen, gpt2M, groupS)
	Wdown := newTensor("Wdown", gpt2M, gpt2D, groupM)
	Out := newTensor("Out", seqLen, gpt2D, groupS)

	addClaim("attn_out", Context, Wout, AttnOut)
	addClaim("mlp_up", AttnOut, Wup, Hidden)
	addClaim("mlp_down", Hidden, Wdown, Out)

	return tensors, claims
}

func (p *preparedLayer) commitTensor(t *tensor, rho string) {
	n := codewordLength(t.cols, rho)
	encoder := crypto.NewEncoder(t.cols, n)
	_, enc, err := encoder.EncodeRows(t.data)
	if err != nil {
		log.Fatalf("failed to encode tensor %s: %v", t.name, err)
	}
	t.colsEnc = matrix.Transpose(enc, t.rows, n)
	group := p.extGroups[t.group]
	commits, blindings := crypto.BatchPedersenCommitBlinded(t.colsEnc, group.ck)
	t.leafStart = len(group.commits)
	group.blocks = append(group.blocks, t.colsEnc...)
	group.commits = append(group.commits, commits...)
	group.blindings = append(group.blindings, blindings...)
	for i := range commits {
		group.metas = append(group.metas, crypto.MerkleLeafMeta{GroupID: uint64(t.group), ItemID: uint64(t.id), Index: uint64(i)})
	}
}

func (p *preparedLayer) buildGroupTree(groupID int) {
	group := p.extGroups[groupID]
	tree, root, depth := crypto.BuildMerkleTreeFromGroupElementsWithMeta(group.commits, group.metas)
	group.tree = tree
	group.root = root
	group.depth = depth
}

func (p *preparedLayer) prepareClaim(spec claimSpec) claimWitness {
	challenge := challengeForClaim(p.tensorCm, spec.id)
	powers := matrix.Powers(challenge, spec.A.rows)
	vecX := matrix.VecMatMulRect(powers, spec.A.data, spec.A.rows, spec.A.cols)
	vecYZ := matrix.VecMatMulRect(vecX, spec.B.data, spec.B.rows, spec.B.cols)

	encoderIn := crypto.NewEncoder(spec.A.cols, codewordLength(spec.A.cols, p.rho))
	encoderOut := crypto.NewEncoder(spec.C.cols, codewordLength(spec.C.cols, p.rho))
	_, encX, err := encoderIn.Encode(vecX)
	if err != nil {
		log.Fatalf("failed to encode folded X for %s: %v", spec.name, err)
	}
	_, encYZ, err := encoderOut.Encode(vecYZ)
	if err != nil {
		log.Fatalf("failed to encode folded YZ for %s: %v", spec.name, err)
	}

	foldX := p.commitFoldedCodeword(fmt.Sprintf("%s.x", spec.name), encX)
	foldYZ := p.commitFoldedCodeword(fmt.Sprintf("%s.yz", spec.name), encYZ)

	return claimWitness{spec: spec, vecX: vecX, vecYZ: vecYZ, encX: encX, encYZ: encYZ, foldX: foldX, foldYZ: foldYZ}
}

func (p *preparedLayer) commitFoldedCodeword(name string, enc []fr.Element) *foldedCodeword {
	id := len(p.extGroups[groupScalar].metas)
	matrixRows := make([][]fr.Element, len(enc))
	for i := range enc {
		matrixRows[i] = []fr.Element{enc[i]}
	}
	group := p.extGroups[groupScalar]
	commits, blindings := crypto.BatchPedersenCommitBlinded(matrixRows, group.ck)
	start := len(group.commits)
	group.blocks = append(group.blocks, matrixRows...)
	group.commits = append(group.commits, commits...)
	group.blindings = append(group.blindings, blindings...)
	for i := range commits {
		group.metas = append(group.metas, crypto.MerkleLeafMeta{GroupID: uint64(groupScalar), ItemID: uint64(id), Index: uint64(i)})
	}
	return &foldedCodeword{id: id, name: name, enc: enc, leafStart: start}
}

func (p *preparedLayer) sampleClaim(claim *claimWitness) {
	L := p.L
	NIn := codewordLength(claim.spec.A.cols, p.rho)
	NOut := codewordLength(claim.spec.C.cols, p.rho)
	if L > NIn || L > NOut {
		log.Fatalf("L=%d exceeds sampled domains for %s: NIn=%d NOut=%d", L, claim.spec.name, NIn, NOut)
	}

	var err error
	claim.indicesIn, err = protocol.GenerateUniqueIndicesWithLabel(p.globalCm, labelFor(claim.spec.id, 1), NIn, L)
	if err != nil {
		log.Fatalf("failed to sample input indices for %s: %v", claim.spec.name, err)
	}
	claim.indicesOut, err = protocol.GenerateUniqueIndicesWithLabel(p.globalCm, labelFor(claim.spec.id, 2), NOut, L)
	if err != nil {
		log.Fatalf("failed to sample output indices for %s: %v", claim.spec.name, err)
	}

	var excludedPoint *fr.Element
	if !claim.skipRSX {
		claim.rsPointX, err = protocol.GenerateRSEvaluationPointWithLabel(p.globalCm, labelFor(claim.spec.id, 3), NIn, nil)
		if err != nil {
			log.Fatalf("failed to sample RS point X for %s: %v", claim.spec.name, err)
		}
		excludedPoint = &claim.rsPointX
	}
	if !claim.skipRSYZ {
		claim.rsPointYZ, err = protocol.GenerateRSEvaluationPointWithLabel(p.globalCm, labelFor(claim.spec.id, 4), NOut, excludedPoint)
		if err != nil {
			log.Fatalf("failed to sample RS point YZ for %s: %v", claim.spec.name, err)
		}
	}
}

func (p *preparedLayer) addScoreValueRSBatches() {
	scoreClaims := p.claimIndicesByPrefix("score_")
	valueClaims := p.claimIndicesByPrefix("value_")
	if len(scoreClaims) != gpt2Heads {
		log.Fatalf("expected %d score claims for RS batching, got %d", gpt2Heads, len(scoreClaims))
	}
	if len(valueClaims) != gpt2Heads {
		log.Fatalf("expected %d value claims for RS batching, got %d", gpt2Heads, len(valueClaims))
	}

	p.addRSBatch("score.x", gpt2Dh, codewordLength(gpt2Dh, p.rho), scoreClaims, circuit.LAMPGPT2RSSideX)
	p.addRSBatch("score.yz", p.seqLen, codewordLength(p.seqLen, p.rho), scoreClaims, circuit.LAMPGPT2RSSideYZ)
	p.addRSBatch("value.x", p.seqLen, codewordLength(p.seqLen, p.rho), valueClaims, circuit.LAMPGPT2RSSideX)
	p.addRSBatch("value.yz", gpt2Dh, codewordLength(gpt2Dh, p.rho), valueClaims, circuit.LAMPGPT2RSSideYZ)
}

func (p *preparedLayer) claimIndicesByPrefix(prefix string) []int {
	indices := make([]int, 0, gpt2Heads)
	for i := range p.claims {
		if strings.HasPrefix(p.claims[i].spec.name, prefix) {
			indices = append(indices, i)
		}
	}
	return indices
}

func (p *preparedLayer) addRSBatch(name string, k, n int, claimIndices []int, side int) {
	id := len(p.rsBatches)
	terms := make([]rsBatchTermWitness, 0, len(claimIndices))

	for _, claimIndex := range claimIndices {
		if claimIndex < 0 || claimIndex >= len(p.claims) {
			log.Fatalf("invalid claim index %d for RS batch %s", claimIndex, name)
		}

		claim := &p.claims[claimIndex]
		p.markClaimRSBatched(claim, claimIndex, side, k, n, name)
		terms = append(terms, rsBatchTermWitness{claimIndex: claimIndex, side: side})
	}

	rsPoint, err := protocol.GenerateRSEvaluationPointWithLabel(p.globalCm, labelForRSBatch(id), n, nil)
	if err != nil {
		log.Fatalf("failed to sample RS point for batch %s: %v", name, err)
	}

	p.rsBatches = append(p.rsBatches, rsBatchWitness{
		id:      id,
		name:    name,
		k:       k,
		n:       n,
		terms:   terms,
		rsPoint: rsPoint,
	})
}

func (p *preparedLayer) markClaimRSBatched(claim *claimWitness, claimIndex int, side int, k int, n int, batchName string) {
	switch side {
	case circuit.LAMPGPT2RSSideX:
		if claim.spec.A.cols != k || codewordLength(claim.spec.A.cols, p.rho) != n {
			log.Fatalf("invalid X-side domain for claim %s in RS batch %s", claim.spec.name, batchName)
		}
		if claim.skipRSX {
			log.Fatalf("claim %s X-side was already assigned to an RS batch", claim.spec.name)
		}
		claim.skipRSX = true
	case circuit.LAMPGPT2RSSideYZ:
		if claim.spec.C.cols != k || codewordLength(claim.spec.C.cols, p.rho) != n {
			log.Fatalf("invalid YZ-side domain for claim %s in RS batch %s", claim.spec.name, batchName)
		}
		if claim.skipRSYZ {
			log.Fatalf("claim %s YZ-side was already assigned to an RS batch", claim.spec.name)
		}
		claim.skipRSYZ = true
	default:
		log.Fatalf("unknown RS side %d for claim %d in batch %s", side, claimIndex, batchName)
	}
}

func labelForRSBatch(id int) uint64 {
	return uint64(30000 + id)
}

func (p *preparedLayer) addClaimSamples() {
	for i := range p.claims {
		claim := &p.claims[i]
		for j := 0; j < p.L; j++ {
			inCol := claim.indicesIn[j]
			outCol := claim.indicesOut[j]
			p.addTensorSample(claim.spec.A, inCol)
			p.addTensorSample(claim.spec.B, outCol)
			p.addTensorSample(claim.spec.C, outCol)
			p.addScalarSample(claim.foldX, inCol)
			p.addScalarSample(claim.foldYZ, outCol)
		}
	}
}

func labelFor(id int, kind uint64) uint64 {
	return uint64(1000 + id*10 + int(kind))
}

func challengeForClaim(tensorCm fr.Element, id int) fr.Element {
	var idElement fr.Element
	idElement.SetUint64(uint64(id))
	return crypto.HashElementsMiMC(tensorCm, idElement)
}

func (p *preparedLayer) addTensorSample(t *tensor, col int) int {
	key := fmt.Sprintf("%d:%d", t.id, col)
	sg := p.sampleGroups[t.group]
	if idx, ok := sg.cache[key]; ok {
		return idx
	}
	if t.colsEnc == nil {
		idx := len(sg.blocks)
		sg.cache[key] = idx
		sg.blocks = append(sg.blocks, make([]fr.Element, sg.blockLen))
		return idx
	}
	ext := p.extGroups[t.group]
	leafIdx := t.leafStart + col
	idx := len(sg.blocks)
	sg.cache[key] = idx
	sg.blocks = append(sg.blocks, t.colsEnc[col])
	sg.commits = append(sg.commits, ext.commits[leafIdx])
	sg.blindings = append(sg.blindings, ext.blindings[leafIdx])
	sg.metas = append(sg.metas, ext.metas[leafIdx])
	sg.leafIndices = append(sg.leafIndices, leafIdx)
	return idx
}

func (p *preparedLayer) addScalarSample(f *foldedCodeword, col int) int {
	if f == nil {
		idx := len(p.scalars)
		p.scalars = append(p.scalars, fr.Element{})
		p.scalarBlocks = append(p.scalarBlocks, []fr.Element{{}})
		return idx
	}
	key := fmt.Sprintf("%d:%d", f.id, col)
	if idx, ok := p.scalarCache[key]; ok {
		return idx
	}
	ext := p.extGroups[groupScalar]
	leafIdx := f.leafStart + col
	idx := len(p.scalars)
	p.scalarCache[key] = idx
	p.scalars = append(p.scalars, f.enc[col])
	p.scalarBlocks = append(p.scalarBlocks, []fr.Element{f.enc[col]})
	p.scalarCommits = append(p.scalarCommits, ext.commits[leafIdx])
	p.scalarBlindings = append(p.scalarBlindings, ext.blindings[leafIdx])
	p.scalarMetas = append(p.scalarMetas, ext.metas[leafIdx])
	p.scalarLeafIdx = append(p.scalarLeafIdx, leafIdx)
	return idx
}

func (p *preparedLayer) generateMerkleMultiProofs() {
	start := time.Now()
	for groupID := 0; groupID < groupScalar; groupID++ {
		sg := p.sampleGroups[groupID]
		if len(sg.leafIndices) == 0 {
			continue
		}
		ext := p.extGroups[groupID]
		sg.multiProof = crypto.GetMerkleMultiProof(ext.tree, sg.leafIndices, ext.depth)
	}
	if len(p.scalarLeafIdx) > 0 {
		ext := p.extGroups[groupScalar]
		p.scalarMultiProof = crypto.GetMerkleMultiProof(ext.tree, p.scalarLeafIdx, ext.depth)
	}
	p.merkleProveTime += time.Since(start).Seconds()
}

func (p *preparedLayer) addPackedAttentionChecks(tensors []*tensor, L int) {
	p.addQKVSplitChecks(tensors, L)
	p.addTransposeChecks(tensors, L)
	p.addContextConcatChecks(tensors, L)
}

func (p *preparedLayer) addQKVSplitChecks(tensors []*tensor, L int) {
	byName := tensorMap(tensors)
	QKV := byName["QKV"]
	expDh := codewordLength(gpt2Dh, p.rho) / gpt2Dh
	expQKV := codewordLength(gpt2PackedQKVCols, p.rho) / gpt2PackedQKVCols

	for h := 0; h < gpt2Heads; h++ {
		targets := []*tensor{
			byName[fmt.Sprintf("Q_%02d", h)],
			byName[fmt.Sprintf("K_%02d", h)],
			byName[fmt.Sprintf("V_%02d", h)],
		}
		offsets := []int{h * gpt2Dh, gpt2D + h*gpt2Dh, 2*gpt2D + h*gpt2Dh}

		for part := 0; part < len(targets); part++ {
			pairs, err := protocol.GenerateUniqueIndicesWithLabel(p.globalCm, uint64(8000+part*1000+h), p.seqLen*gpt2Dh, L)
			if err != nil {
				log.Fatalf("failed to sample QKV split entry pairs for head %d part %d: %v", h, part, err)
			}
			check := circuit.LAMPGPT2EntryEqualityCheck{
				LeftGroup:    targets[part].group,
				RightGroup:   QKV.group,
				LeftBlocks:   make([]int, L),
				RightBlocks:  make([]int, L),
				LeftIndices:  make([]frontend.Variable, L),
				RightIndices: make([]frontend.Variable, L),
			}
			for i := 0; i < L; i++ {
				row := pairs[i] / gpt2Dh
				col := pairs[i] % gpt2Dh
				check.LeftBlocks[i] = p.addTensorSample(targets[part], col*expDh)
				check.RightBlocks[i] = p.addTensorSample(QKV, (offsets[part]+col)*expQKV)
				check.LeftIndices[i] = row
				check.RightIndices[i] = row
			}
			p.equalityChecks = append(p.equalityChecks, check)
		}
	}
}

func (p *preparedLayer) addTransposeChecks(tensors []*tensor, L int) {
	byName := tensorMap(tensors)
	expDh := codewordLength(gpt2Dh, p.rho) / gpt2Dh
	expS := codewordLength(p.seqLen, p.rho) / p.seqLen
	for h := 0; h < gpt2Heads; h++ {
		K := byName[fmt.Sprintf("K_%02d", h)]
		KT := byName[fmt.Sprintf("KT_%02d", h)]
		pairs, err := protocol.GenerateUniqueIndicesWithLabel(p.globalCm, uint64(5000+h*10), p.seqLen*gpt2Dh, L)
		if err != nil {
			log.Fatalf("failed to sample transpose entry pairs for head %d: %v", h, err)
		}
		check := circuit.LAMPGPT2TransposeCheck{
			LeftGroup:   K.group,
			RightGroup:  KT.group,
			LeftBlocks:  make([]int, L),
			RightBlocks: make([]int, L),
			RowIndices:  make([]frontend.Variable, L),
			ColIndices:  make([]frontend.Variable, L),
		}
		for i := 0; i < L; i++ {
			row := pairs[i] / gpt2Dh
			col := pairs[i] % gpt2Dh
			check.LeftBlocks[i] = p.addTensorSample(K, col*expDh)
			check.RightBlocks[i] = p.addTensorSample(KT, row*expS)
			check.RowIndices[i] = row
			check.ColIndices[i] = col
		}
		p.transposeChecks = append(p.transposeChecks, check)
	}
}

func (p *preparedLayer) addContextConcatChecks(tensors []*tensor, L int) {
	byName := tensorMap(tensors)
	Context := byName["Context"]
	expDh := codewordLength(gpt2Dh, p.rho) / gpt2Dh
	expD := codewordLength(gpt2D, p.rho) / gpt2D

	for h := 0; h < gpt2Heads; h++ {
		Ctx := byName[fmt.Sprintf("Ctx_%02d", h)]
		pairs, err := protocol.GenerateUniqueIndicesWithLabel(p.globalCm, uint64(12000+h), p.seqLen*gpt2Dh, L)
		if err != nil {
			log.Fatalf("failed to sample context concat entry pairs for head %d: %v", h, err)
		}
		check := circuit.LAMPGPT2EntryEqualityCheck{
			LeftGroup:    Ctx.group,
			RightGroup:   Context.group,
			LeftBlocks:   make([]int, L),
			RightBlocks:  make([]int, L),
			LeftIndices:  make([]frontend.Variable, L),
			RightIndices: make([]frontend.Variable, L),
		}
		for i := 0; i < L; i++ {
			row := pairs[i] / gpt2Dh
			col := pairs[i] % gpt2Dh
			check.LeftBlocks[i] = p.addTensorSample(Ctx, col*expDh)
			check.RightBlocks[i] = p.addTensorSample(Context, (h*gpt2Dh+col)*expD)
			check.LeftIndices[i] = row
			check.RightIndices[i] = row
		}
		p.equalityChecks = append(p.equalityChecks, check)
	}
}

func tensorMap(tensors []*tensor) map[string]*tensor {
	out := make(map[string]*tensor, len(tensors))
	for _, t := range tensors {
		out[t.name] = t
	}
	return out
}

func buildCircuit(p *preparedLayer, assignment bool) *circuit.LAMPGPT2Circuit {
	claims := make([]circuit.LAMPGPT2RectClaim, len(p.claims))
	for i := range p.claims {
		claims[i] = buildCircuitClaim(p, &p.claims[i], assignment)
	}
	rsBatches := buildCircuitRSBatches(p, assignment)

	c := &circuit.LAMPGPT2Circuit{
		Input:        make([]frontend.Variable, p.seqLen*gpt2D),
		Output:       make([]frontend.Variable, p.seqLen*gpt2D),
		ColumnGroups: make([]circuit.LAMPGPT2ColumnGroup, groupScalar),
		Scalars:      make([]frontend.Variable, len(p.scalars)),
		GroupRoots: [5]frontend.Variable{
			p.extGroups[groupS].root,
			p.extGroups[groupD].root,
			p.extGroups[groupDh].root,
			p.extGroups[groupM].root,
			p.extGroups[groupScalar].root,
		},
		TensorCm:        p.tensorCm,
		GlobalCm:        p.globalCm,
		Claims:          claims,
		RSBatches:       rsBatches,
		EqualityChecks:  cloneEqualityChecks(p.equalityChecks),
		TransposeChecks: cloneTransposeChecks(p.transposeChecks),
	}

	for groupID := 0; groupID < groupScalar; groupID++ {
		sg := p.sampleGroups[groupID]
		c.ColumnGroups[groupID] = circuit.LAMPGPT2ColumnGroup{
			BlockLen: sg.blockLen,
			Blocks:   make([][]frontend.Variable, len(sg.blocks)),
		}
		for i := range sg.blocks {
			c.ColumnGroups[groupID].Blocks[i] = make([]frontend.Variable, sg.blockLen)
			if assignment {
				for j := range sg.blocks[i] {
					c.ColumnGroups[groupID].Blocks[i][j] = sg.blocks[i][j]
				}
			}
		}
	}

	if assignment {
		assignFlat(c.Input, p.inputTensor.data)
		assignFlat(c.Output, p.outputTensor.data)
		for i := range p.scalars {
			c.Scalars[i] = p.scalars[i]
		}
	}

	return c
}

func cloneEqualityChecks(src []circuit.LAMPGPT2EntryEqualityCheck) []circuit.LAMPGPT2EntryEqualityCheck {
	out := make([]circuit.LAMPGPT2EntryEqualityCheck, len(src))
	for i := range src {
		out[i] = circuit.LAMPGPT2EntryEqualityCheck{
			LeftGroup:    src[i].LeftGroup,
			RightGroup:   src[i].RightGroup,
			LeftBlocks:   append([]int(nil), src[i].LeftBlocks...),
			RightBlocks:  append([]int(nil), src[i].RightBlocks...),
			LeftIndices:  append([]frontend.Variable(nil), src[i].LeftIndices...),
			RightIndices: append([]frontend.Variable(nil), src[i].RightIndices...),
		}
	}
	return out
}

func cloneTransposeChecks(src []circuit.LAMPGPT2TransposeCheck) []circuit.LAMPGPT2TransposeCheck {
	out := make([]circuit.LAMPGPT2TransposeCheck, len(src))
	for i := range src {
		out[i] = circuit.LAMPGPT2TransposeCheck{
			LeftGroup:   src[i].LeftGroup,
			RightGroup:  src[i].RightGroup,
			LeftBlocks:  append([]int(nil), src[i].LeftBlocks...),
			RightBlocks: append([]int(nil), src[i].RightBlocks...),
			RowIndices:  append([]frontend.Variable(nil), src[i].RowIndices...),
			ColIndices:  append([]frontend.Variable(nil), src[i].ColIndices...),
		}
	}
	return out
}

func buildCircuitRSBatches(p *preparedLayer, assignment bool) []circuit.LAMPGPT2RSBatch {
	out := make([]circuit.LAMPGPT2RSBatch, len(p.rsBatches))
	for i := range p.rsBatches {
		batch := &p.rsBatches[i]
		d := p.cachedDomainBundle(batch.k, batch.n, !assignment)
		out[i] = circuit.LAMPGPT2RSBatch{
			ID:       batch.id,
			K:        batch.k,
			N:        batch.n,
			DomainK:  d.domainK,
			WeightsK: d.weightsK,
			DomainN:  d.domainN,
			WeightsN: d.weightsN,
			Terms:    make([]circuit.LAMPGPT2RSBatchTerm, len(batch.terms)),
		}
		for j := range batch.terms {
			out[i].Terms[j] = circuit.LAMPGPT2RSBatchTerm{
				ClaimIndex: batch.terms[j].claimIndex,
				Side:       batch.terms[j].side,
			}
		}
		if assignment {
			out[i].RSPoint = batch.rsPoint
		}
	}
	return out
}

func buildCircuitClaim(p *preparedLayer, w *claimWitness, assignment bool) circuit.LAMPGPT2RectClaim {
	spec := w.spec
	rows, inner, cols := spec.A.rows, spec.A.cols, spec.C.cols
	NIn, NOut := codewordLength(inner, p.rho), codewordLength(cols, p.rho)
	dIn := p.cachedDomainBundle(inner, NIn, !assignment)
	dOut := p.cachedDomainBundle(cols, NOut, !assignment)

	claim := circuit.LAMPGPT2RectClaim{
		ID: spec.id, Rows: rows, Inner: inner, Cols: cols, NIn: NIn, NOut: NOut,
		DomainKIn: dIn.domainK, WeightsKIn: dIn.weightsK, DomainNIn: dIn.domainN, WeightsNIn: dIn.weightsN,
		DomainKOut: dOut.domainK, WeightsKOut: dOut.weightsK, DomainNOut: dOut.domainN, WeightsNOut: dOut.weightsN,
		IndicesIn:        make([]frontend.Variable, p.L),
		IndicesOut:       make([]frontend.Variable, p.L),
		AGroup:           spec.A.group,
		BGroup:           spec.B.group,
		CGroup:           spec.C.group,
		ABlocks:          make([]int, p.L),
		BBlocks:          make([]int, p.L),
		CBlocks:          make([]int, p.L),
		TargetXScalars:   make([]int, p.L),
		TargetYZScalars:  make([]int, p.L),
		BindPublicInput:  spec.A.name == "X",
		BindPublicOutput: spec.C.name == "Out",
		SkipRSX:          w.skipRSX,
		SkipRSYZ:         w.skipRSYZ,
		VecX:             make([]frontend.Variable, inner),
		VecYZ:            make([]frontend.Variable, cols),
		EncX:             make([]frontend.Variable, NIn),
		EncYZ:            make([]frontend.Variable, NOut),
	}

	for i := 0; i < p.L; i++ {
		inCol := 0
		outCol := 0
		if len(w.indicesIn) > i {
			inCol = w.indicesIn[i]
		}
		if len(w.indicesOut) > i {
			outCol = w.indicesOut[i]
		}
		claim.ABlocks[i] = p.addTensorSample(spec.A, inCol)
		claim.BBlocks[i] = p.addTensorSample(spec.B, outCol)
		claim.CBlocks[i] = p.addTensorSample(spec.C, outCol)
		claim.TargetXScalars[i] = p.addScalarSample(w.foldX, inCol)
		claim.TargetYZScalars[i] = p.addScalarSample(w.foldYZ, outCol)
		if assignment {
			claim.IndicesIn[i] = w.indicesIn[i]
			claim.IndicesOut[i] = w.indicesOut[i]
		}
	}

	if assignment {
		if !w.skipRSX {
			claim.RSPointX = w.rsPointX
		} else {
			claim.RSPointX = 0
		}
		if !w.skipRSYZ {
			claim.RSPointYZ = w.rsPointYZ
		} else {
			claim.RSPointYZ = 0
		}
		for i := range w.vecX {
			claim.VecX[i] = w.vecX[i]
		}
		for i := range w.vecYZ {
			claim.VecYZ[i] = w.vecYZ[i]
		}
		for i := range w.encX {
			claim.EncX[i] = w.encX[i]
		}
		for i := range w.encYZ {
			claim.EncYZ[i] = w.encYZ[i]
		}
	}

	return claim
}

func assignFlat(dst []frontend.Variable, src [][]fr.Element) {
	offset := 0
	for row := range src {
		for col := range src[row] {
			dst[offset] = src[row][col]
			offset++
		}
	}
}

type domains struct {
	domainK  []fr.Element
	weightsK []fr.Element
	domainN  []fr.Element
	weightsN []fr.Element
}

type domainCacheKey struct {
	k int
	n int
}

func domainBundle(k, n int) domains {
	domainK := fft.NewDomain(uint64(k))
	rootsK := crypto.GetDomainRoots(domainK, k)
	domainN := fft.NewDomain(uint64(n))
	rootsN := crypto.GetDomainRoots(domainN, n)
	return domains{
		domainK:  rootsK,
		weightsK: crypto.PrecomputeBarycentricWeights(rootsK),
		domainN:  rootsN,
		weightsN: crypto.PrecomputeBarycentricWeights(rootsN),
	}
}

func (p *preparedLayer) cachedDomainBundle(k, n int, countSetupTime bool) domains {
	key := domainCacheKey{k: k, n: n}
	if d, ok := p.domainCache[key]; ok {
		return d
	}

	start := time.Now()
	d := domainBundle(k, n)
	if countSetupTime {
		p.setupTime += time.Since(start).Seconds()
	}
	p.domainCache[key] = d
	return d
}

func codewordLength(k int, rho string) int {
	switch rho {
	case "1/2":
		return k << 1
	case "1/4":
		return k << 2
	default:
		log.Fatalf("unsupported rho %q; expected 1/2 or 1/4", rho)
		return 0
	}
}

func (p *preparedLayer) sampleCPLinkData(groupID int) ([][]fr.Element, []bn254.G1Affine, []fr.Element) {
	if groupID == groupScalar {
		return p.scalarBlocks, p.scalarCommits, p.scalarBlindings
	}
	sg := p.sampleGroups[groupID]
	return sg.blocks, sg.commits, sg.blindings
}

func (p *preparedLayer) linkBatchContext() []fr.Element {
	context := []fr.Element{
		uint64Element(0x475054324c494e4b), // "GPT2LINK"
		p.tensorCm,
		p.globalCm,
		uint64Element(uint64(numGroups)),
	}

	for groupID := 0; groupID < numGroups; groupID++ {
		ext := p.extGroups[groupID]
		context = append(
			context,
			uint64Element(uint64(groupID)),
			ext.root,
			uint64Element(uint64(ext.depth)),
		)

		if groupID == groupScalar {
			context = append(context, uint64Element(uint64(len(p.scalarLeafIdx))))
			for i, leafIdx := range p.scalarLeafIdx {
				context = appendMerkleOpeningContext(context, leafIdx, p.scalarMetas[i])
			}
			continue
		}

		sg := p.sampleGroups[groupID]
		context = append(context, uint64Element(uint64(len(sg.leafIndices))))
		for i, leafIdx := range sg.leafIndices {
			context = appendMerkleOpeningContext(context, leafIdx, sg.metas[i])
		}
	}

	return context
}

func (p *preparedLayer) verifyMerkleGroup(verifier *protocol.Verifier, groupID int) bool {
	ext := p.extGroups[groupID]
	if groupID == groupScalar {
		if len(p.scalarCommits) == 0 {
			return true
		}
		return verifier.VerifyMultiMembershipWithMeta(ext.root, p.scalarCommits, p.scalarMetas, p.scalarLeafIdx, p.scalarMultiProof, ext.depth)
	}
	sg := p.sampleGroups[groupID]
	if len(sg.commits) == 0 {
		return true
	}
	return verifier.VerifyMultiMembershipWithMeta(ext.root, sg.commits, sg.metas, sg.leafIndices, sg.multiProof, ext.depth)
}

func (p *preparedLayer) merkleProofSize() int {
	size := 0
	for groupID := 0; groupID < groupScalar; groupID++ {
		size += crypto.MerkleMultiProofSizeBytes(p.sampleGroups[groupID].multiProof)
	}
	size += crypto.MerkleMultiProofSizeBytes(p.scalarMultiProof)
	size += p.openedMerkleCommitmentCount() * crypto.G1AffineSizeBytes
	return size
}

func (p *preparedLayer) openedMerkleCommitmentCount() int {
	count := len(p.scalarCommits)
	for groupID := 0; groupID < groupScalar; groupID++ {
		count += len(p.sampleGroups[groupID].commits)
	}
	return count
}

func appendMerkleOpeningContext(context []fr.Element, leafIdx int, meta crypto.MerkleLeafMeta) []fr.Element {
	return append(
		context,
		uint64Element(uint64(leafIdx)),
		uint64Element(meta.GroupID),
		uint64Element(meta.ItemID),
		uint64Element(meta.Index),
	)
}

func uint64Element(value uint64) fr.Element {
	var out fr.Element
	out.SetUint64(value)
	return out
}
