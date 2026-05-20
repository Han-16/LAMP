package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
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
}

type preparedLayer struct {
	seqLog int
	seqLen int
	rho    string
	L      int

	extGroups    [numGroups]*extGroup
	sampleGroups [numGroups]*sampleGroup

	tensorCm fr.Element
	globalCm fr.Element

	inputTensor     *tensor
	outputTensor    *tensor
	claims          []claimWitness
	equalityChecks  []circuit.MeowGPT2EntryEqualityCheck
	transposeChecks []circuit.MeowGPT2TransposeCheck

	scalars         []fr.Element
	scalarBlocks    [][]fr.Element
	scalarCommits   []bn254.G1Affine
	scalarBlindings []fr.Element
	scalarMetas     []crypto.MerkleLeafMeta
	scalarLeafIdx   []int
	scalarProofs    [][]fr.Element
	scalarCache     map[string]int

	matrixComputeTime float64
	commitTime        float64
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	seqFlag := flag.Int("seq", config.GetInt("MEOW_GPT2_SEQ", 1), "Log2 sequence length")
	rhoFlag := flag.String("rho", config.GetString("MEOW_GPT2_RHO", "1/2"), "Code rate, 1/2 or 1/4")
	LFlag := flag.Int("L", config.GetInt("MEOW_GPT2_L", 1), "Number of sampled queries per matmul and wiring check")
	allFlag := flag.Bool("all", config.GetBool("MEOW_GPT2_ALL", false), "Run benchmark range")
	rangeFlag := flag.Bool("range", false, "Alias for -all")
	fromFlag := flag.Int("from", config.GetInt("MEOW_GPT2_SEQ_FROM", 0), "First log2 sequence length when range mode is enabled")
	toFlag := flag.Int("to", config.GetInt("MEOW_GPT2_SEQ_TO", 4), "Last log2 sequence length when range mode is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("MEOW_GPT2_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	flag.Parse()

	outputDir := config.OutputDir("MEOW_GPT2_OUTPUT_DIR", filepath.Join("benchmark", "meow_gpt2"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "meow_gpt2_benchmark_results.csv")
	file, writer := benchmark.InitMeowGPT2CSV(csvPath)
	defer file.Close()

	if *allFlag || *rangeFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid seq range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		fmt.Printf("Running Meow GPT-2 range: seq=%d..%d, rho=%s, L=%d\n", *fromFlag, *toFlag, *rhoFlag, *LFlag)
		for seqLog := *fromFlag; seqLog <= *toFlag; seqLog++ {
			res := runExperiment(seqLog, *rhoFlag, *LFlag, *compileFlag)
			benchmark.AppendMeowGPT2ResultToCSV(writer, res)
			fmt.Println("----------------------------------------------------------------")
		}
		return
	}

	res := runExperiment(*seqFlag, *rhoFlag, *LFlag, *compileFlag)
	benchmark.AppendMeowGPT2ResultToCSV(writer, res)
}

func runExperiment(seqLog int, rho string, L int, onlyCompile bool) benchmark.MeowGPT2Result {
	if seqLog < 0 || L <= 0 {
		log.Fatalf("invalid parameters: seq=%d L=%d", seqLog, L)
	}
	seqLen := 1 << seqLog
	fmt.Printf("Meow GPT-2 medium packed-QKV layer: seq=2^%d=%d, rho=%s, L=%d\n", seqLog, seqLen, rho, L)

	var prep *preparedLayer
	if onlyCompile {
		prep = prepareLayerShapeOnly(seqLog, rho, L)
	} else {
		prep = prepareLayer(seqLog, rho, L)
	}
	emptyCircuit := buildCircuit(prep, false)

	field := ecc.BN254.ScalarField()
	startSetup := time.Now()
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("Meow GPT-2 compilation failed: %v", err)
	}
	nbConstraints := r1csSystem.GetNbConstraints()

	if onlyCompile {
		fmt.Printf("Meow GPT-2 circuit compiled. Constraints: %d\n", nbConstraints)
		return benchmark.MeowGPT2Result{
			SeqLog:            seqLog,
			SeqLen:            seqLen,
			Rho:               rho,
			NumQueries:        L,
			NumClaims:         len(prep.claims),
			NumCommitGroups:   numGroups,
			Constraints:       nbConstraints,
			MatrixComputeTime: prep.matrixComputeTime,
			CommitTime:        prep.commitTime,
		}
	}

	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("Meow GPT-2 setup failed: %v", err)
	}
	setupTime := time.Since(startSetup).Seconds()

	assignment := buildCircuit(prep, true)
	prover := protocol.NewProver(pk, prep.extGroups[groupS].ck, nil)
	verifier := protocol.NewVerifier(vk, prep.extGroups[groupS].ck, prover.CK2)

	startCircuitProve := time.Now()
	proof, cmVec2, blindingsIn, err := prover.ProveCircuit(r1csSystem, assignment)
	if err != nil {
		log.Fatalf("Meow GPT-2 proof failed: %v", err)
	}
	if len(cmVec2) < numGroups || len(blindingsIn) < numGroups || len(prover.CK2) < numGroups {
		log.Fatalf("expected %d committed groups, got commitments=%d blindings=%d keys=%d", numGroups, len(cmVec2), len(blindingsIn), len(prover.CK2))
	}
	circuitProveTime := time.Since(startCircuitProve).Seconds()

	startOffline := time.Now()
	linkProofs := make([]crypto.AmComEqProof, numGroups)
	for groupID := 0; groupID < numGroups; groupID++ {
		blocks, commits, blindings := prep.sampleCPLinkData(groupID)
		linkProof, err := crypto.ProveAmComEq(blocks, blindingsIn[groupID], blindings, prover.CK2[groupID], prep.extGroups[groupID].ck, cmVec2[groupID], commits)
		if err != nil {
			log.Fatalf("group %d CPLink proof failed: %v", groupID, err)
		}
		linkProofs[groupID] = linkProof
	}
	cpLinkProveTime := time.Since(startOffline).Seconds()

	startVerify := time.Now()
	witnessForVerify, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("failed to build witness for verification: %v", err)
	}
	publicWitness, err := witnessForVerify.Public()
	if err != nil {
		log.Fatalf("failed to build public witness: %v", err)
	}

	startCircuitVerify := time.Now()
	if err := verifier.VerifyGroth16(proof, publicWitness); err != nil {
		log.Fatalf("Meow GPT-2 Groth16 verification failed: %v", err)
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
	for groupID := 0; groupID < numGroups; groupID++ {
		blocks, commits, _ := prep.sampleCPLinkData(groupID)
		_ = blocks
		if !crypto.VerifyAmComEq(cmVec2[groupID], commits, linkProofs[groupID], verifier.CK2[groupID], prep.extGroups[groupID].ck) {
			log.Fatalf("group %d CPLink verification failed", groupID)
		}
	}
	cpLinkVerifyTime := time.Since(startCPLink).Seconds()
	totalVerifyTime := time.Since(startVerify).Seconds()

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	groth16ProofSize := buf.Len()
	merkleProofSize := prep.merkleProofSize()
	cpLinkProofSize := 0
	for i := range linkProofs {
		cpLinkProofSize += crypto.AmComEqProofSizeBytes(linkProofs[i])
	}
	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize
	totalProveTime := prep.matrixComputeTime + prep.commitTime + circuitProveTime + cpLinkProveTime

	fmt.Println("Meow GPT-2 proof verified successfully")
	fmt.Printf("Proof sizes: Groth16=%d B, Merkle=%d B, CPLink=%d B, Total=%d B\n", groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.MeowGPT2Result{
		SeqLog:            seqLog,
		SeqLen:            seqLen,
		Rho:               rho,
		NumQueries:        L,
		NumClaims:         len(prep.claims),
		NumCommitGroups:   numGroups,
		Constraints:       nbConstraints,
		MatrixComputeTime: prep.matrixComputeTime,
		SetupTime:         setupTime,
		CommitTime:        prep.commitTime,
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
		scalarCache: make(map[string]int),
	}

	p.initGroups()

	startCompute := time.Now()
	tensors, specs := buildGPT2MediumTensors(seqLen)
	byName := tensorMap(tensors)
	p.inputTensor = byName["X"]
	p.outputTensor = byName["Out"]
	p.matrixComputeTime = time.Since(startCompute).Seconds()

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

	for i := range p.claims {
		p.sampleClaim(&p.claims[i])
	}
	p.addPackedAttentionChecks(tensors, L)
	p.commitTime = time.Since(startCommit).Seconds()

	return p
}

func prepareLayerShapeOnly(seqLog int, rho string, L int) *preparedLayer {
	seqLen := 1 << seqLog
	p := &preparedLayer{
		seqLog:      seqLog,
		seqLen:      seqLen,
		rho:         rho,
		L:           L,
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
	p.addPackedAttentionChecks(tensors, L)
	return p
}

func (p *preparedLayer) initGroups() {
	p.extGroups[groupS] = newExtGroup(groupS, p.seqLen)
	p.extGroups[groupD] = newExtGroup(groupD, gpt2D)
	p.extGroups[groupDh] = newExtGroup(groupDh, gpt2Dh)
	p.extGroups[groupM] = newExtGroup(groupM, gpt2M)
	p.extGroups[groupScalar] = newExtGroup(groupScalar, 1)
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

func buildGPT2MediumTensors(seqLen int) ([]*tensor, []claimSpec) {
	nextID := 0
	tensors := make([]*tensor, 0)
	claims := make([]claimSpec, 0)

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

	X := newTensor("X", matrix.GenerateRandomMatrix(seqLen, gpt2D), groupS)

	WQKV := newTensor("WQKV", generatePaddedQKVWeights(), groupD)
	QKV := newTensor("QKV", matrix.MatMulRect(X.data, WQKV.data, seqLen, gpt2D, gpt2PackedQKVCols), groupS)
	addClaim("qkv_proj", X, WQKV, QKV)

	Ctxs := make([]*tensor, gpt2Heads)
	for h := 0; h < gpt2Heads; h++ {
		Q := newTensor(fmt.Sprintf("Q_%02d", h), sliceColumns(QKV.data, h*gpt2Dh, gpt2Dh), groupS)
		K := newTensor(fmt.Sprintf("K_%02d", h), sliceColumns(QKV.data, gpt2D+h*gpt2Dh, gpt2Dh), groupS)
		V := newTensor(fmt.Sprintf("V_%02d", h), sliceColumns(QKV.data, 2*gpt2D+h*gpt2Dh, gpt2Dh), groupS)
		KT := newTensor(fmt.Sprintf("KT_%02d", h), matrix.Transpose(K.data, seqLen, gpt2Dh), groupDh)

		Score := newTensor(fmt.Sprintf("Score_%02d", h), matrix.MatMulRect(Q.data, KT.data, seqLen, gpt2Dh, seqLen), groupS)
		Ctx := newTensor(fmt.Sprintf("Ctx_%02d", h), matrix.MatMulRect(Score.data, V.data, seqLen, seqLen, gpt2Dh), groupS)
		Ctxs[h] = Ctx

		addClaim(fmt.Sprintf("score_%02d", h), Q, KT, Score)
		addClaim(fmt.Sprintf("value_%02d", h), Score, V, Ctx)
	}

	Context := newTensor("Context", concatHeadColumns(Ctxs, seqLen), groupS)
	Wout := newTensor("Wout", matrix.GenerateRandomMatrix(gpt2D, gpt2D), groupD)
	AttnOut := newTensor("AttnOut", matrix.MatMulRect(Context.data, Wout.data, seqLen, gpt2D, gpt2D), groupS)
	Wup := newTensor("Wup", matrix.GenerateRandomMatrix(gpt2D, gpt2M), groupD)
	Hidden := newTensor("Hidden", matrix.MatMulRect(AttnOut.data, Wup.data, seqLen, gpt2D, gpt2M), groupS)
	Wdown := newTensor("Wdown", matrix.GenerateRandomMatrix(gpt2M, gpt2D), groupM)
	Out := newTensor("Out", matrix.MatMulRect(Hidden.data, Wdown.data, seqLen, gpt2M, gpt2D), groupS)

	addClaim("attn_out", Context, Wout, AttnOut)
	addClaim("mlp_up", AttnOut, Wup, Hidden)
	addClaim("mlp_down", Hidden, Wdown, Out)

	return tensors, claims
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
	claim.rsPointX, err = protocol.GenerateRSEvaluationPointWithLabel(p.globalCm, labelFor(claim.spec.id, 3), NIn, nil)
	if err != nil {
		log.Fatalf("failed to sample RS point X for %s: %v", claim.spec.name, err)
	}
	claim.rsPointYZ, err = protocol.GenerateRSEvaluationPointWithLabel(p.globalCm, labelFor(claim.spec.id, 4), NOut, &claim.rsPointX)
	if err != nil {
		log.Fatalf("failed to sample RS point YZ for %s: %v", claim.spec.name, err)
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
	sg.proofs = append(sg.proofs, crypto.GetMerkleProof(ext.tree, leafIdx, ext.depth))
	sg.merkleProofSz += ext.depth * 32
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
	p.scalarProofs = append(p.scalarProofs, crypto.GetMerkleProof(ext.tree, leafIdx, ext.depth))
	return idx
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
			check := circuit.MeowGPT2EntryEqualityCheck{
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
		check := circuit.MeowGPT2TransposeCheck{
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
		check := circuit.MeowGPT2EntryEqualityCheck{
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

func buildCircuit(p *preparedLayer, assignment bool) *circuit.MeowGPT2Circuit {
	claims := make([]circuit.MeowGPT2RectClaim, len(p.claims))
	for i := range p.claims {
		claims[i] = buildCircuitClaim(p, &p.claims[i], assignment)
	}

	c := &circuit.MeowGPT2Circuit{
		Input:        make([]frontend.Variable, p.seqLen*gpt2D),
		Output:       make([]frontend.Variable, p.seqLen*gpt2D),
		ColumnGroups: make([]circuit.MeowGPT2ColumnGroup, groupScalar),
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
		EqualityChecks:  cloneEqualityChecks(p.equalityChecks),
		TransposeChecks: cloneTransposeChecks(p.transposeChecks),
	}

	for groupID := 0; groupID < groupScalar; groupID++ {
		sg := p.sampleGroups[groupID]
		c.ColumnGroups[groupID] = circuit.MeowGPT2ColumnGroup{
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

func cloneEqualityChecks(src []circuit.MeowGPT2EntryEqualityCheck) []circuit.MeowGPT2EntryEqualityCheck {
	out := make([]circuit.MeowGPT2EntryEqualityCheck, len(src))
	for i := range src {
		out[i] = circuit.MeowGPT2EntryEqualityCheck{
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

func cloneTransposeChecks(src []circuit.MeowGPT2TransposeCheck) []circuit.MeowGPT2TransposeCheck {
	out := make([]circuit.MeowGPT2TransposeCheck, len(src))
	for i := range src {
		out[i] = circuit.MeowGPT2TransposeCheck{
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

func buildCircuitClaim(p *preparedLayer, w *claimWitness, assignment bool) circuit.MeowGPT2RectClaim {
	spec := w.spec
	rows, inner, cols := spec.A.rows, spec.A.cols, spec.C.cols
	NIn, NOut := codewordLength(inner, p.rho), codewordLength(cols, p.rho)
	dIn := domainBundle(inner, NIn)
	dOut := domainBundle(cols, NOut)

	claim := circuit.MeowGPT2RectClaim{
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
		claim.RSPointX = w.rsPointX
		claim.RSPointYZ = w.rsPointYZ
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

func (p *preparedLayer) verifyMerkleGroup(verifier *protocol.Verifier, groupID int) bool {
	ext := p.extGroups[groupID]
	if groupID == groupScalar {
		for i := range p.scalarCommits {
			if !verifier.VerifyMembershipWithMeta(ext.root, p.scalarCommits[i], p.scalarMetas[i], p.scalarProofs[i], p.scalarLeafIdx[i], ext.depth) {
				return false
			}
		}
		return true
	}
	sg := p.sampleGroups[groupID]
	for i := range sg.commits {
		if !verifier.VerifyMembershipWithMeta(ext.root, sg.commits[i], sg.metas[i], sg.proofs[i], sg.leafIndices[i], ext.depth) {
			return false
		}
	}
	return true
}

func (p *preparedLayer) merkleProofSize() int {
	size := 0
	for groupID := 0; groupID < groupScalar; groupID++ {
		size += p.sampleGroups[groupID].merkleProofSz
	}
	size += len(p.scalarProofs) * p.extGroups[groupScalar].depth * 32
	return size
}
