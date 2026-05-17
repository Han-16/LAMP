package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/config"
	"github.com/Han-16/meow/crypto"
	"github.com/Han-16/meow/gpt2"
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

type resultRow struct {
	Protocol    string
	Model       string
	SeqLen      int
	L           int
	Constraints int
	SetupS      float64
	ProveS      float64
	VerifyS     float64
	ProofBytes  int
}

type meowMatmulData struct {
	opIndex            int
	claim              gpt2.MatmulClaim
	layout             meowMatmulLayout
	kx, ky, nx, ny     int
	colsEncA           [][]fr.Element
	colsEncB           [][]fr.Element
	colsEncC           [][]fr.Element
	cmABC, cmXYZ       fr.Element
	challengeR         fr.Element
	rsPointX           fr.Element
	rsPointYZ          fr.Element
	vecX, vecYZ        []fr.Element
	encX, encYZ        []fr.Element
	indicesX, indicesY []int
	sourceA, sourceB   [][]fr.Element
}

type meowMatmulLayout struct {
	rowsGroup   int
	innerGroup  int
	scalarGroup int
	aBase       int
	bBase       int
	cBase       int
	xBase       int
	yzBase      int
}

type meowBlockRef struct {
	group  int
	base   int
	blocks [][]fr.Element
}

type meowMatmulReuse struct {
	a *meowBlockRef
	b *meowBlockRef
	c *meowBlockRef
}

type meowGroupData struct {
	kind      int
	width     int
	depth     int
	ck        crypto.CommitKey
	blocks    [][]fr.Element
	leaves    []bn254.G1Affine
	blindings []fr.Element
	tree      [][]fr.Element
	root      fr.Element
}

type meowAttentionHeadData struct {
	Score meowMatmulData
	Value meowMatmulData
}

type meowAttentionData struct {
	QKV        meowMatmulData
	Heads      []meowAttentionHeadData
	Projection meowMatmulData
}

type meowMLPData struct {
	Up   meowMatmulData
	Down meowMatmulData
}

type meowLayerData struct {
	Input  [][]fr.Element
	Output [][]fr.Element

	Groups    []meowGroupData
	Attention meowAttentionData
	MLP       meowMLPData
}

type meowLinkProof struct {
	name            string
	commitIndex     int
	externalCommits []bn254.G1Affine
	externalCK      crypto.CommitKey
	proof           crypto.AmComEqProof
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	protocolFlag := flag.String("protocol", config.GetString("GPT2_PROTOCOL", "meow"), "meow, freivalds, or all")
	modelFlag := flag.String("model", config.GetString("GPT2_MODEL", "medium"), "small or medium")
	seqLenFlag := flag.Int("seq_len", config.GetInt("GPT2_SEQ_LEN", 1024), "sequence length")
	LFlag := flag.Int("L", config.GetInt("GPT2_L", 128), "Meow query count per domain")
	rhoFlag := flag.String("rho", config.GetString("GPT2_RHO", "1/2"), "Meow code rate")
	compileFlag := flag.Bool("compile", config.GetBool("GPT2_ONLY_COMPILE", false), "Only compile circuits")
	flag.Parse()

	model, err := gpt2.Model(*modelFlag)
	if err != nil {
		log.Fatal(err)
	}
	spec := gpt2.NewLayerSpec(model, *seqLenFlag)

	switch *protocolFlag {
	case "meow":
		runGPT2Meow(spec, *LFlag, *rhoFlag, *compileFlag)
	case "freivalds":
		runGPT2Freivalds(spec, *compileFlag)
	case "all":
		runGPT2Meow(spec, *LFlag, *rhoFlag, *compileFlag)
		runGPT2Freivalds(spec, *compileFlag)
	default:
		log.Fatalf("unknown protocol %q", *protocolFlag)
	}
}

func runGPT2Freivalds(spec gpt2.LayerSpec, onlyCompile bool) {
	fmt.Printf("🔥 [GPT2 Freivalds] model=%s, seq_len=%d, heads=%d, head_dim=%d, matmuls=%d\n",
		spec.Model.Name, spec.SeqLen, spec.Model.Heads, spec.HeadDim, spec.ClaimCount())
	field := ecc.BN254.ScalarField()
	emptyCircuit := newGPT2FreivaldsCircuit(spec)

	startSetup := time.Now()
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ GPT2 Freivalds compilation failed: %v", err)
	}
	constraints := r1csSystem.GetNbConstraints()
	fmt.Printf("   📊 Constraints: %d\n", constraints)
	if onlyCompile {
		writeResult(spec, resultRow{Protocol: "freivalds", Model: spec.Model.Name, SeqLen: spec.SeqLen, Constraints: constraints})
		return
	}

	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("❌ GPT2 Freivalds setup failed: %v", err)
	}
	setupS := time.Since(startSetup).Seconds()

	fmt.Println("=== Generating GPT2 multi-head matmul-only tensors ===")
	layer := gpt2.GenerateLayerData(spec)
	assignment := newGPT2FreivaldsCircuit(spec)
	assignGPT2Freivalds(assignment, layer)

	prover := protocol.NewProver(pk, crypto.CommitKey{}, nil)
	verifier := protocol.NewVerifier(vk, crypto.CommitKey{}, nil)

	startProve := time.Now()
	proof, _, _, err := prover.ProveCircuit(r1csSystem, assignment)
	if err != nil {
		log.Fatalf("❌ GPT2 Freivalds proof failed: %v", err)
	}
	proveS := time.Since(startProve).Seconds()

	startVerify := time.Now()
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ GPT2 Freivalds witness failed: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ GPT2 Freivalds public witness failed: %v", err)
	}
	if err := verifier.VerifyGroth16(proof, publicWitness); err != nil {
		log.Fatalf("❌ GPT2 Freivalds verification failed: %v", err)
	}
	verifyS := time.Since(startVerify).Seconds()

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	writeResult(spec, resultRow{
		Protocol:    "freivalds",
		Model:       spec.Model.Name,
		SeqLen:      spec.SeqLen,
		Constraints: constraints,
		SetupS:      setupS,
		ProveS:      proveS,
		VerifyS:     verifyS,
		ProofBytes:  buf.Len(),
	})
}

func runGPT2Meow(spec gpt2.LayerSpec, L int, rho string, onlyCompile bool) {
	fmt.Printf("🔥 [GPT2 Meow] model=%s, seq_len=%d, heads=%d, head_dim=%d, L=%d, rho=%s, matmuls=%d\n",
		spec.Model.Name, spec.SeqLen, spec.Model.Heads, spec.HeadDim, L, rho, spec.ClaimCount())
	field := ecc.BN254.ScalarField()
	emptyCircuit := newGPT2MeowCircuit(spec, L, rho)

	startSetup := time.Now()
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("❌ GPT2 Meow compilation failed: %v", err)
	}
	constraints := r1csSystem.GetNbConstraints()
	fmt.Printf("   📊 Constraints: %d\n", constraints)
	if onlyCompile {
		writeResult(spec, resultRow{Protocol: "meow", Model: spec.Model.Name, SeqLen: spec.SeqLen, L: L, Constraints: constraints})
		return
	}

	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("❌ GPT2 Meow setup failed: %v", err)
	}
	setupS := time.Since(startSetup).Seconds()

	fmt.Println("=== Generating GPT2 multi-head matmul-only tensors and Meow commitments ===")
	layer := gpt2.GenerateLayerData(spec)
	meowData := prepareMeowLayer(layer, L, rho)
	assignment := newGPT2MeowAssignment(spec, meowData, L, rho)

	proverWithPK := protocol.NewProver(pk, crypto.CommitKey{}, nil)
	verifier := protocol.NewVerifier(vk, crypto.CommitKey{}, proverWithPK.CK2)

	startProve := time.Now()
	proof, cmVec2, blindingsIn, err := proverWithPK.ProveCircuit(r1csSystem, assignment)
	if err != nil {
		log.Fatalf("❌ GPT2 Meow circuit proof failed: %v", err)
	}

	linkProofs, linkProofBytes := proveMeowLayerLinks(meowData, cmVec2, blindingsIn, proverWithPK.CK2)
	proveS := time.Since(startProve).Seconds()

	startVerify := time.Now()
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ GPT2 Meow witness failed: %v", err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("❌ GPT2 Meow public witness failed: %v", err)
	}
	if err := verifier.VerifyGroth16(proof, publicWitness); err != nil {
		log.Fatalf("❌ GPT2 Meow Groth16 verification failed: %v", err)
	}
	verifyMeowLayerTranscript(meowData, L)
	verifyMeowLinks(linkProofs, cmVec2, verifier.CK2)
	verifyMeowLayerMerkle(meowData)
	verifyS := time.Since(startVerify).Seconds()

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	merkleBytes := meowLayerMerkleProofBytes(meowData, L)
	writeResult(spec, resultRow{
		Protocol:    "meow",
		Model:       spec.Model.Name,
		SeqLen:      spec.SeqLen,
		L:           L,
		Constraints: constraints,
		SetupS:      setupS,
		ProveS:      proveS,
		VerifyS:     verifyS,
		ProofBytes:  buf.Len() + merkleBytes + linkProofBytes,
	})
}

func newGPT2FreivaldsCircuit(spec gpt2.LayerSpec) *circuit.GPT2FreivaldsCircuit {
	S := spec.SeqLen
	D := spec.Model.Embd
	Dh := spec.HeadDim
	M := spec.Model.MLP

	heads := make([]circuit.GPT2FreivaldsAttentionHeadBlock, spec.Model.Heads)
	for head := range heads {
		heads[head] = circuit.GPT2FreivaldsAttentionHeadBlock{
			Q:       makeTensor(S, Dh),
			K:       makeTensor(S, Dh),
			V:       makeTensor(S, Dh),
			KT:      makeTensor(Dh, S),
			Score:   makeTensor(S, S),
			Context: makeTensor(S, Dh),
		}
	}

	return &circuit.GPT2FreivaldsCircuit{
		Spec:   spec,
		Input:  makeTensor(S, D),
		Output: makeTensor(S, D),
		WQKV:   makeTensor(D, 3*D),
		QKV:    makeTensor(S, 3*D),
		Attention: circuit.GPT2FreivaldsAttentionBlock{
			Heads:   heads,
			Context: makeTensor(S, D),
			WOut:    makeTensor(D, D),
			Output:  makeTensor(S, D),
		},
		MLP: circuit.GPT2FreivaldsMLPBlock{
			WUp:    makeTensor(D, M),
			Hidden: makeTensor(S, M),
			WDown:  makeTensor(M, D),
		},
	}
}

func assignGPT2Freivalds(c *circuit.GPT2FreivaldsCircuit, layer gpt2.LayerData) {
	assignTensor(c.Input, layer.Input)
	assignTensor(c.Output, layer.Output)
	assignTensor(c.WQKV, layer.Attention.WQKV)
	assignTensor(c.QKV, layer.Attention.QKV)

	for head := range layer.Attention.Heads {
		assignTensor(c.Attention.Heads[head].Q, layer.Attention.Heads[head].Q)
		assignTensor(c.Attention.Heads[head].K, layer.Attention.Heads[head].K)
		assignTensor(c.Attention.Heads[head].V, layer.Attention.Heads[head].V)
		assignTensor(c.Attention.Heads[head].KT, layer.Attention.Heads[head].KT)
		assignTensor(c.Attention.Heads[head].Score, layer.Attention.Heads[head].Score)
		assignTensor(c.Attention.Heads[head].Context, layer.Attention.Heads[head].Context)
	}

	assignTensor(c.Attention.Context, layer.Attention.Context)
	assignTensor(c.Attention.WOut, layer.Attention.WOut)
	assignTensor(c.Attention.Output, layer.Attention.Output)
	assignTensor(c.MLP.WUp, layer.MLP.WUp)
	assignTensor(c.MLP.Hidden, layer.MLP.Hidden)
	assignTensor(c.MLP.WDown, layer.MLP.WDown)
}

func newGPT2MeowCircuit(spec gpt2.LayerSpec, L int, rho string) *circuit.GPT2MeowCircuit {
	groups := meowCircuitGroups(spec)
	heads := make([]circuit.GPT2MeowAttentionHeadBlock, len(spec.Attention.Heads))
	for head := range heads {
		heads[head] = circuit.GPT2MeowAttentionHeadBlock{
			Score: emptyMeowMatmulCircuit(spec.Attention.Heads[head].Score, groups, L, rho),
			Value: emptyMeowMatmulCircuit(spec.Attention.Heads[head].Value, groups, L, rho),
		}
	}

	return &circuit.GPT2MeowCircuit{
		Input:      makeTensor(spec.SeqLen, spec.Model.Embd),
		Output:     makeTensor(spec.SeqLen, spec.Model.Embd),
		GroupRoots: make([]frontend.Variable, len(groups)),
		Groups:     groups,
		Attention: circuit.GPT2MeowAttentionBlock{
			QKV:        emptyMeowMatmulCircuit(spec.Attention.QKV, groups, L, rho),
			Heads:      heads,
			Projection: emptyMeowMatmulCircuit(spec.Attention.Projection, groups, L, rho),
		},
		MLP: circuit.GPT2MeowMLPBlock{
			Up:   emptyMeowMatmulCircuit(spec.MLP.Up, groups, L, rho),
			Down: emptyMeowMatmulCircuit(spec.MLP.Down, groups, L, rho),
		},
	}
}

func emptyMeowMatmulCircuit(claim gpt2.MatmulClaim, groups []circuit.GPT2MeowGroup, L int, rho string) circuit.GPT2MeowMatmulClaim {
	kx := nextPowerOfTwo(claim.Inner)
	ky := nextPowerOfTwo(claim.Cols)
	nx := codewordSize(kx, rho)
	ny := codewordSize(ky, rho)
	depthX := int(math.Log2(float64(nx)))
	depthY := int(math.Log2(float64(ny)))

	domainInner, weightsInner := domainRootsAndWeights(kx)
	domainX, weightsX := domainRootsAndWeights(nx)
	domainCols, weightsCols := domainRootsAndWeights(ky)
	domainY, weightsY := domainRootsAndWeights(ny)

	c := circuit.GPT2MeowMatmulClaim{
		Rows: claim.Rows, Inner: claim.Inner, Cols: claim.Cols,
		KX: kx, KY: ky, NX: nx, NY: ny,
		DepthX: depthX, DepthY: depthY,
		DomainInner: domainInner, WeightsInner: weightsInner,
		DomainX: domainX, WeightsX: weightsX,
		DomainCols: domainCols, WeightsCols: weightsCols,
		DomainY: domainY, WeightsY: weightsY,
		RowsGroup:   meowCircuitGroupIndex(groups, circuit.GPT2MeowGroupMatrix, claim.Rows),
		InnerGroup:  meowCircuitGroupIndex(groups, circuit.GPT2MeowGroupMatrix, claim.Inner),
		ScalarGroup: meowCircuitGroupIndex(groups, circuit.GPT2MeowGroupScalar, 1),
		IndicesX:    make([]frontend.Variable, L),
		IndicesY:    make([]frontend.Variable, L),
		ColsEncA:    make([][]frontend.Variable, L),
		ColsEncB:    make([][]frontend.Variable, L),
		ColsEncC:    make([][]frontend.Variable, L),
		VecX:        make([]frontend.Variable, kx), VecYZ: make([]frontend.Variable, ky),
		EncX: make([]frontend.Variable, nx), EncYZ: make([]frontend.Variable, ny),
		TargetEncX: make([]frontend.Variable, L), TargetEncYZ: make([]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		c.ColsEncA[i] = make([]frontend.Variable, claim.Rows)
		c.ColsEncB[i] = make([]frontend.Variable, claim.Inner)
		c.ColsEncC[i] = make([]frontend.Variable, claim.Rows)
	}
	return c
}

func newGPT2MeowAssignment(spec gpt2.LayerSpec, data meowLayerData, L int, rho string) *circuit.GPT2MeowCircuit {
	c := newGPT2MeowCircuit(spec, L, rho)
	assignTensor(c.Input, data.Input)
	assignTensor(c.Output, data.Output)
	for i := range data.Groups {
		c.GroupRoots[i] = data.Groups[i].root
	}
	assignMeowMatmul(&c.Attention.QKV, data.Attention.QKV, L)
	for head := range data.Attention.Heads {
		assignMeowMatmul(&c.Attention.Heads[head].Score, data.Attention.Heads[head].Score, L)
		assignMeowMatmul(&c.Attention.Heads[head].Value, data.Attention.Heads[head].Value, L)
	}
	assignMeowMatmul(&c.Attention.Projection, data.Attention.Projection, L)
	assignMeowMatmul(&c.MLP.Up, data.MLP.Up, L)
	assignMeowMatmul(&c.MLP.Down, data.MLP.Down, L)
	return c
}

func assignMeowMatmul(c *circuit.GPT2MeowMatmulClaim, d meowMatmulData, L int) {
	c.CmABC = d.cmABC
	c.CmXYZ = d.cmXYZ
	c.ChallengeR = d.challengeR
	c.RSPointX = d.rsPointX
	c.RSPointYZ = d.rsPointYZ

	for i := 0; i < d.kx; i++ {
		c.VecX[i] = d.vecX[i]
	}
	for i := 0; i < d.ky; i++ {
		c.VecYZ[i] = d.vecYZ[i]
	}
	for i := 0; i < d.nx; i++ {
		c.EncX[i] = d.encX[i]
	}
	for i := 0; i < d.ny; i++ {
		c.EncYZ[i] = d.encYZ[i]
	}
	for i := 0; i < L; i++ {
		xIdx := d.indicesX[i]
		yIdx := d.indicesY[i]
		c.IndicesX[i] = xIdx
		c.IndicesY[i] = yIdx
		c.TargetEncX[i] = d.encX[xIdx]
		c.TargetEncYZ[i] = d.encYZ[yIdx]
		for j := 0; j < d.claim.Rows; j++ {
			c.ColsEncA[i][j] = d.colsEncA[xIdx][j]
			c.ColsEncC[i][j] = d.colsEncC[yIdx][j]
		}
		for j := 0; j < d.claim.Inner; j++ {
			c.ColsEncB[i][j] = d.colsEncB[yIdx][j]
		}
	}
}

func prepareMeowLayer(layer gpt2.LayerData, L int, rho string) meowLayerData {
	groups := newMeowGroups(layer.Spec)
	opIndex := 0

	attention := meowAttentionData{
		QKV: prepareMeowMatmulBase(
			opIndex,
			layer.Spec.Attention.QKV,
			layer.Input,
			layer.Attention.WQKV,
			layer.Attention.QKV,
			groups,
			rho,
		),
		Heads: make([]meowAttentionHeadData, len(layer.Spec.Attention.Heads)),
	}
	opIndex++

	for head := range layer.Spec.Attention.Heads {
		score := prepareMeowMatmulBase(
			opIndex,
			layer.Spec.Attention.Heads[head].Score,
			layer.Attention.Heads[head].Q,
			layer.Attention.Heads[head].KT,
			layer.Attention.Heads[head].Score,
			groups,
			rho,
		)
		opIndex++

		value := prepareMeowMatmulBaseWithReuse(
			opIndex,
			layer.Spec.Attention.Heads[head].Value,
			layer.Attention.Heads[head].Score,
			layer.Attention.Heads[head].V,
			layer.Attention.Heads[head].Context,
			groups,
			rho,
			meowMatmulReuse{a: meowCBlockRef(&score)},
		)
		attention.Heads[head] = meowAttentionHeadData{Score: score, Value: value}
		opIndex++
	}

	attention.Projection = prepareMeowMatmulBase(
		opIndex,
		layer.Spec.Attention.Projection,
		layer.Attention.Context,
		layer.Attention.WOut,
		layer.Attention.Output,
		groups,
		rho,
	)
	opIndex++

	mlpUp := prepareMeowMatmulBaseWithReuse(
		opIndex,
		layer.Spec.MLP.Up,
		layer.Attention.Output,
		layer.MLP.WUp,
		layer.MLP.Hidden,
		groups,
		rho,
		meowMatmulReuse{a: meowCBlockRef(&attention.Projection)},
	)
	opIndex++

	mlpDown := prepareMeowMatmulBaseWithReuse(
		opIndex,
		layer.Spec.MLP.Down,
		layer.MLP.Hidden,
		layer.MLP.WDown,
		layer.MLP.Output,
		groups,
		rho,
		meowMatmulReuse{a: meowCBlockRef(&mlpUp)},
	)

	data := meowLayerData{
		Input:     layer.Input,
		Output:    layer.Output,
		Groups:    groups,
		Attention: attention,
		MLP:       meowMLPData{Up: mlpUp, Down: mlpDown},
	}

	commitMeowMatrixGroups(data.Groups)
	for _, d := range meowMatmulsInOrder(&data) {
		deriveMeowChallengeAndScalars(d, data.Groups)
	}
	commitMeowScalarGroup(data.Groups)
	for _, d := range meowMatmulsInOrder(&data) {
		deriveMeowQueries(d, data.Groups, L)
	}
	return data
}

func prepareMeowMatmulBase(opIndex int, claim gpt2.MatmulClaim, A, B, C [][]fr.Element, groups []meowGroupData, rho string) meowMatmulData {
	return prepareMeowMatmulBaseWithReuse(opIndex, claim, A, B, C, groups, rho, meowMatmulReuse{})
}

func prepareMeowMatmulBaseWithReuse(opIndex int, claim gpt2.MatmulClaim, A, B, C [][]fr.Element, groups []meowGroupData, rho string, reuse meowMatmulReuse) meowMatmulData {
	kx := nextPowerOfTwo(claim.Inner)
	ky := nextPowerOfTwo(claim.Cols)
	nx := codewordSize(kx, rho)
	ny := codewordSize(ky, rho)

	encA := encodeRows(A, kx, nx)
	encB := encodeRows(B, ky, ny)
	encC := encodeRows(C, ky, ny)
	colsEncA := matrix.Transpose(encA, claim.Rows, nx)
	colsEncB := matrix.Transpose(encB, claim.Inner, ny)
	colsEncC := matrix.Transpose(encC, claim.Rows, ny)

	rowsGroup := meowGroupIndex(groups, circuit.GPT2MeowGroupMatrix, claim.Rows)
	innerGroup := meowGroupIndex(groups, circuit.GPT2MeowGroupMatrix, claim.Inner)
	scalarGroup := meowGroupIndex(groups, circuit.GPT2MeowGroupScalar, 1)

	layout := meowMatmulLayout{
		rowsGroup:   rowsGroup,
		innerGroup:  innerGroup,
		scalarGroup: scalarGroup,
	}

	if reuse.a != nil {
		ensureReusableMeowBlocks(claim.Name, "A", rowsGroup, colsEncA, *reuse.a)
		layout.aBase = reuse.a.base
		colsEncA = reuse.a.blocks
	} else {
		layout.aBase = appendMeowBlocks(&groups[rowsGroup], colsEncA)
	}
	if reuse.c != nil {
		ensureReusableMeowBlocks(claim.Name, "C", rowsGroup, colsEncC, *reuse.c)
		layout.cBase = reuse.c.base
		colsEncC = reuse.c.blocks
	} else {
		layout.cBase = appendMeowBlocks(&groups[rowsGroup], colsEncC)
	}
	if reuse.b != nil {
		ensureReusableMeowBlocks(claim.Name, "B", innerGroup, colsEncB, *reuse.b)
		layout.bBase = reuse.b.base
		colsEncB = reuse.b.blocks
	} else {
		layout.bBase = appendMeowBlocks(&groups[innerGroup], colsEncB)
	}

	return meowMatmulData{
		opIndex: opIndex,
		claim:   claim,
		layout:  layout,
		kx:      kx, ky: ky, nx: nx, ny: ny,
		colsEncA: colsEncA, colsEncB: colsEncB, colsEncC: colsEncC,
		sourceA: A, sourceB: B,
	}
}

func meowCBlockRef(d *meowMatmulData) *meowBlockRef {
	return &meowBlockRef{
		group:  d.layout.rowsGroup,
		base:   d.layout.cBase,
		blocks: d.colsEncC,
	}
}

func ensureReusableMeowBlocks(claimName, role string, expectedGroup int, encoded [][]fr.Element, ref meowBlockRef) {
	if ref.group != expectedGroup {
		log.Fatalf("cannot reuse %s.%s blocks from group %d in group %d", claimName, role, ref.group, expectedGroup)
	}
	if len(encoded) != len(ref.blocks) {
		log.Fatalf("cannot reuse %s.%s blocks: encoded length %d != reference length %d", claimName, role, len(encoded), len(ref.blocks))
	}
	for i := range encoded {
		if len(encoded[i]) != len(ref.blocks[i]) {
			log.Fatalf("cannot reuse %s.%s block %d: width %d != reference width %d", claimName, role, i, len(encoded[i]), len(ref.blocks[i]))
		}
		for j := range encoded[i] {
			if !encoded[i][j].Equal(&ref.blocks[i][j]) {
				log.Fatalf("cannot reuse %s.%s block %d element %d: encoded value differs from reference", claimName, role, i, j)
			}
		}
	}
}

func deriveMeowChallengeAndScalars(d *meowMatmulData, groups []meowGroupData) {
	d.cmABC = crypto.HashElementsMiMC(groups[d.layout.rowsGroup].root, groups[d.layout.innerGroup].root, groups[d.layout.rowsGroup].root)
	d.challengeR = meowTranscriptSeed(d.cmABC, d.opIndex, 1)

	powers := matrix.Powers(d.challengeR, d.claim.Rows)
	vecXActual := matrix.VecMatMulRect(powers, d.sourceA, d.claim.Rows, d.claim.Inner)
	vecYZActual := matrix.VecMatMulRect(vecXActual, d.sourceB, d.claim.Inner, d.claim.Cols)
	d.vecX = padVector(vecXActual, d.kx)
	d.vecYZ = padVector(vecYZActual, d.ky)

	var err error
	_, d.encX, err = crypto.NewEncoder(d.kx, d.nx).Encode(vecXActual)
	if err != nil {
		log.Fatalf("failed to encode x for %s: %v", d.claim.Name, err)
	}
	_, d.encYZ, err = crypto.NewEncoder(d.ky, d.ny).Encode(vecYZActual)
	if err != nil {
		log.Fatalf("failed to encode yz for %s: %v", d.claim.Name, err)
	}

	scalarGroup := d.layout.scalarGroup
	d.layout.xBase = appendMeowScalarBlocks(&groups[scalarGroup], d.encX)
	d.layout.yzBase = appendMeowScalarBlocks(&groups[scalarGroup], d.encYZ)
}

func deriveMeowQueries(d *meowMatmulData, groups []meowGroupData, L int) {
	d.cmXYZ = crypto.HashElementsMiMC(groups[d.layout.scalarGroup].root, groups[d.layout.scalarGroup].root)

	seedX := meowTranscriptSeed(d.cmXYZ, d.opIndex, 101)
	seedY := meowTranscriptSeed(d.cmXYZ, d.opIndex, 202)
	var err error
	d.indicesX, err = crypto.GenerateUniqueIndices(seedX, d.nx, L)
	if err != nil {
		log.Fatalf("failed to derive x indices for %s: %v", d.claim.Name, err)
	}
	d.indicesY, err = crypto.GenerateUniqueIndices(seedY, d.ny, L)
	if err != nil {
		log.Fatalf("failed to derive y indices for %s: %v", d.claim.Name, err)
	}
	d.rsPointX, _, err = protocol.GenerateRSEvaluationPoints(seedX, d.nx)
	if err != nil {
		log.Fatalf("failed to derive x RS point for %s: %v", d.claim.Name, err)
	}
	_, d.rsPointYZ, err = protocol.GenerateRSEvaluationPoints(seedY, d.ny)
	if err != nil {
		log.Fatalf("failed to derive yz RS point for %s: %v", d.claim.Name, err)
	}
}

func meowCircuitGroups(spec gpt2.LayerSpec) []circuit.GPT2MeowGroup {
	widths := map[int]bool{}
	add := func(claim gpt2.MatmulClaim) {
		widths[claim.Rows] = true
		widths[claim.Inner] = true
	}

	add(spec.Attention.QKV)
	for _, head := range spec.Attention.Heads {
		add(head.Score)
		add(head.Value)
	}
	add(spec.Attention.Projection)
	add(spec.MLP.Up)
	add(spec.MLP.Down)

	sortedWidths := make([]int, 0, len(widths))
	for width := range widths {
		sortedWidths = append(sortedWidths, width)
	}
	sort.Ints(sortedWidths)

	groups := make([]circuit.GPT2MeowGroup, 0, len(sortedWidths)+1)
	for _, width := range sortedWidths {
		groups = append(groups, circuit.GPT2MeowGroup{Kind: circuit.GPT2MeowGroupMatrix, Width: width})
	}
	groups = append(groups, circuit.GPT2MeowGroup{Kind: circuit.GPT2MeowGroupScalar, Width: 1})
	return groups
}

func meowCircuitGroupIndex(groups []circuit.GPT2MeowGroup, kind, width int) int {
	for i, group := range groups {
		if group.Kind == kind && group.Width == width {
			return i
		}
	}
	log.Fatalf("missing GPT2 Meow circuit group kind=%d width=%d", kind, width)
	return -1
}

func newMeowGroups(spec gpt2.LayerSpec) []meowGroupData {
	circuitGroups := meowCircuitGroups(spec)
	groups := make([]meowGroupData, len(circuitGroups))
	for i, group := range circuitGroups {
		groups[i] = meowGroupData{
			kind:  group.Kind,
			width: group.Width,
			ck:    crypto.SetupCommitKey(group.Width),
		}
	}
	return groups
}

func meowGroupIndex(groups []meowGroupData, kind, width int) int {
	for i, group := range groups {
		if group.kind == kind && group.width == width {
			return i
		}
	}
	log.Fatalf("missing GPT2 Meow group kind=%d width=%d", kind, width)
	return -1
}

func appendMeowBlocks(group *meowGroupData, blocks [][]fr.Element) int {
	base := len(group.blocks)
	group.blocks = append(group.blocks, blocks...)
	return base
}

func appendMeowScalarBlocks(group *meowGroupData, values []fr.Element) int {
	base := len(group.blocks)
	for i := range values {
		group.blocks = append(group.blocks, []fr.Element{values[i]})
	}
	return base
}

func commitMeowMatrixGroups(groups []meowGroupData) {
	for i := range groups {
		if groups[i].kind == circuit.GPT2MeowGroupMatrix {
			commitMeowGroup(&groups[i])
		}
	}
}

func commitMeowScalarGroup(groups []meowGroupData) {
	for i := range groups {
		if groups[i].kind == circuit.GPT2MeowGroupScalar {
			commitMeowGroup(&groups[i])
		}
	}
}

func commitMeowGroup(group *meowGroupData) {
	group.leaves, group.blindings = crypto.BatchPedersenCommitBlinded(group.blocks, group.ck)
	paddedLen := nextPowerOfTwo(len(group.leaves))
	group.depth = int(math.Log2(float64(paddedLen)))

	paddedLeaves := make([]bn254.G1Affine, paddedLen)
	copy(paddedLeaves, group.leaves)
	group.tree, group.root = crypto.BuildMerkleTreeFromGroupElements(paddedLeaves, group.depth)
}

func meowMatmulsInOrder(data *meowLayerData) []*meowMatmulData {
	claims := []*meowMatmulData{&data.Attention.QKV}
	for head := range data.Attention.Heads {
		claims = append(claims, &data.Attention.Heads[head].Score, &data.Attention.Heads[head].Value)
	}
	claims = append(claims, &data.Attention.Projection, &data.MLP.Up, &data.MLP.Down)
	return claims
}

func meowTranscriptSeed(base fr.Element, opIndex int, label uint64) fr.Element {
	var op, tag fr.Element
	op.SetUint64(uint64(opIndex + 1))
	tag.SetUint64(label)
	return crypto.HashElements(base, op, tag)
}

func proveMeowLayerLinks(data meowLayerData, cmVec2 []bn254.G1Affine, blindingsIn []fr.Element, proverCKs []crypto.CommitKey) ([]meowLinkProof, int) {
	var proofs []meowLinkProof
	total := 0
	usedCommitments := make([]bool, len(cmVec2))

	for groupIndex := range data.Groups {
		blocks, commits, blindings := meowLayerLinkInputs(&data, groupIndex)
		commitIndex := snarkCommitmentIndexForBlocks(blocks, cmVec2, blindingsIn, proverCKs, usedCommitments)
		proof, size := proveMeowLink(
			meowGroupName(data.Groups[groupIndex]),
			commitIndex,
			blocks,
			commits,
			blindings,
			data.Groups[groupIndex].ck,
			cmVec2,
			blindingsIn,
			proverCKs,
		)
		proofs = append(proofs, proof)
		total += size
	}
	return proofs, total
}

func snarkCommitmentIndexForBlocks(blocks [][]fr.Element, cmVec2 []bn254.G1Affine, blindingsIn []fr.Element, proverCKs []crypto.CommitKey, used []bool) int {
	flat := flattenMeowBlocks(blocks)
	for i := range cmVec2 {
		if used[i] || len(proverCKs[i].G) != len(flat) {
			continue
		}
		candidate := crypto.PedersenCommitBlinded(flat, blindingsIn[i], proverCKs[i])
		if candidate.Equal(&cmVec2[i]) {
			used[i] = true
			return i
		}
	}
	log.Fatalf("❌ GPT2 Meow could not match grouped witness to a Groth16 commitment")
	return -1
}

func flattenMeowBlocks(blocks [][]fr.Element) []fr.Element {
	total := 0
	for i := range blocks {
		total += len(blocks[i])
	}
	out := make([]fr.Element, 0, total)
	for i := range blocks {
		out = append(out, blocks[i]...)
	}
	return out
}

func proveMeowLink(name string, idx int, blocks [][]fr.Element, externalCommits []bn254.G1Affine, externalBlindings []fr.Element, externalCK crypto.CommitKey, cmVec2 []bn254.G1Affine, blindingsIn []fr.Element, proverCKs []crypto.CommitKey) (meowLinkProof, int) {
	proof, err := crypto.ProveAmComEq(blocks, blindingsIn[idx], externalBlindings, proverCKs[idx], externalCK, cmVec2[idx], externalCommits)
	if err != nil {
		log.Fatalf("❌ GPT2 Meow %s link proof failed: %v", name, err)
	}
	return meowLinkProof{
		name:            name,
		commitIndex:     idx,
		externalCommits: externalCommits,
		externalCK:      externalCK,
		proof:           proof,
	}, crypto.AmComEqProofSizeBytes(proof)
}

func verifyMeowLinks(proofs []meowLinkProof, cmVec2 []bn254.G1Affine, verifierCKs []crypto.CommitKey) {
	for _, p := range proofs {
		if !crypto.VerifyAmComEq(cmVec2[p.commitIndex], p.externalCommits, p.proof, verifierCKs[p.commitIndex], p.externalCK) {
			log.Fatalf("❌ GPT2 Meow %s link verification failed", p.name)
		}
	}
}

func verifyMeowLayerTranscript(data meowLayerData, L int) {
	for _, d := range meowMatmulsInOrder(&data) {
		cmABC := crypto.HashElementsMiMC(data.Groups[d.layout.rowsGroup].root, data.Groups[d.layout.innerGroup].root, data.Groups[d.layout.rowsGroup].root)
		requireElementEqual(d.claim.Name+".cmABC", d.cmABC, cmABC)
		requireElementEqual(d.claim.Name+".challengeR", d.challengeR, meowTranscriptSeed(cmABC, d.opIndex, 1))

		cmXYZ := crypto.HashElementsMiMC(data.Groups[d.layout.scalarGroup].root, data.Groups[d.layout.scalarGroup].root)
		requireElementEqual(d.claim.Name+".cmXYZ", d.cmXYZ, cmXYZ)

		seedX := meowTranscriptSeed(cmXYZ, d.opIndex, 101)
		seedY := meowTranscriptSeed(cmXYZ, d.opIndex, 202)
		indicesX, err := crypto.GenerateUniqueIndices(seedX, d.nx, L)
		if err != nil {
			log.Fatalf("❌ GPT2 Meow transcript %s x indices failed: %v", d.claim.Name, err)
		}
		indicesY, err := crypto.GenerateUniqueIndices(seedY, d.ny, L)
		if err != nil {
			log.Fatalf("❌ GPT2 Meow transcript %s y indices failed: %v", d.claim.Name, err)
		}
		requireIntSliceEqual(d.claim.Name+".indicesX", d.indicesX, indicesX)
		requireIntSliceEqual(d.claim.Name+".indicesY", d.indicesY, indicesY)

		rsPointX, _, err := protocol.GenerateRSEvaluationPoints(seedX, d.nx)
		if err != nil {
			log.Fatalf("❌ GPT2 Meow transcript %s x RS point failed: %v", d.claim.Name, err)
		}
		_, rsPointYZ, err := protocol.GenerateRSEvaluationPoints(seedY, d.ny)
		if err != nil {
			log.Fatalf("❌ GPT2 Meow transcript %s yz RS point failed: %v", d.claim.Name, err)
		}
		requireElementEqual(d.claim.Name+".rsPointX", d.rsPointX, rsPointX)
		requireElementEqual(d.claim.Name+".rsPointYZ", d.rsPointYZ, rsPointYZ)
	}
}

func requireElementEqual(name string, got, want fr.Element) {
	if !got.Equal(&want) {
		log.Fatalf("❌ GPT2 Meow transcript mismatch: %s", name)
	}
}

func requireIntSliceEqual(name string, got, want []int) {
	if len(got) != len(want) {
		log.Fatalf("❌ GPT2 Meow transcript length mismatch: %s", name)
	}
	for i := range got {
		if got[i] != want[i] {
			log.Fatalf("❌ GPT2 Meow transcript mismatch: %s[%d]", name, i)
		}
	}
}

func verifyMeowLayerMerkle(data meowLayerData) {
	verifier := protocol.NewVerifier(nil, crypto.CommitKey{}, nil)
	for groupIndex := range data.Groups {
		group := data.Groups[groupIndex]
		for _, pos := range meowLayerMerklePositions(&data, groupIndex) {
			if !verifier.VerifyMembership(group.root, group.leaves[pos], crypto.GetMerkleProof(group.tree, pos, group.depth), pos, group.depth) {
				log.Fatalf("❌ GPT2 Meow Merkle %s failed at leaf %d", meowGroupName(group), pos)
			}
		}
	}
}

func meowLayerMerkleProofBytes(data meowLayerData, _ int) int {
	total := 0
	for groupIndex := range data.Groups {
		total += len(meowLayerMerklePositions(&data, groupIndex)) * data.Groups[groupIndex].depth * 32
	}
	return total
}

func meowLayerLinkInputs(data *meowLayerData, groupIndex int) ([][]fr.Element, []bn254.G1Affine, []fr.Element) {
	positions := meowLayerLinkPositions(data, groupIndex)
	return groupBlocks(data.Groups[groupIndex], positions), groupCommitments(data.Groups[groupIndex], positions), groupBlindings(data.Groups[groupIndex], positions)
}

func meowLayerLinkPositions(data *meowLayerData, groupIndex int) []int {
	var positions []int
	for _, d := range meowMatmulsInOrder(data) {
		if d.layout.rowsGroup == groupIndex {
			for _, idx := range d.indicesX {
				positions = append(positions, d.layout.aBase+idx)
			}
		}
		if d.layout.innerGroup == groupIndex {
			for _, idx := range d.indicesY {
				positions = append(positions, d.layout.bBase+idx)
			}
		}
		if d.layout.rowsGroup == groupIndex {
			for _, idx := range d.indicesY {
				positions = append(positions, d.layout.cBase+idx)
			}
		}
		if d.layout.scalarGroup == groupIndex {
			for _, idx := range d.indicesX {
				positions = append(positions, d.layout.xBase+idx)
			}
			for _, idx := range d.indicesY {
				positions = append(positions, d.layout.yzBase+idx)
			}
		}
	}
	return positions
}

func meowLayerMerklePositions(data *meowLayerData, groupIndex int) []int {
	return meowLayerLinkPositions(data, groupIndex)
}

func groupBlocks(group meowGroupData, positions []int) [][]fr.Element {
	out := make([][]fr.Element, len(positions))
	for i, pos := range positions {
		out[i] = group.blocks[pos]
	}
	return out
}

func groupCommitments(group meowGroupData, positions []int) []bn254.G1Affine {
	out := make([]bn254.G1Affine, len(positions))
	for i, pos := range positions {
		out[i] = group.leaves[pos]
	}
	return out
}

func groupBlindings(group meowGroupData, positions []int) []fr.Element {
	out := make([]fr.Element, len(positions))
	for i, pos := range positions {
		out[i] = group.blindings[pos]
	}
	return out
}

func meowGroupName(group meowGroupData) string {
	if group.kind == circuit.GPT2MeowGroupScalar {
		return "group.scalar"
	}
	return fmt.Sprintf("group.matrix.width_%d", group.width)
}

func encodeRows(rows [][]fr.Element, k, n int) [][]fr.Element {
	encoder := crypto.NewEncoder(k, n)
	encoded := make([][]fr.Element, len(rows))
	for i := range rows {
		_, enc, err := encoder.Encode(rows[i])
		if err != nil {
			log.Fatalf("failed to encode row %d: %v", i, err)
		}
		encoded[i] = enc
	}
	return encoded
}

func padVector(values []fr.Element, length int) []fr.Element {
	out := make([]fr.Element, length)
	copy(out, values)
	return out
}

func makeTensor(rows, cols int) []frontend.Variable {
	return make([]frontend.Variable, rows*cols)
}

func assignTensor(dst []frontend.Variable, values [][]fr.Element) {
	pos := 0
	for i := range values {
		for j := range values[i] {
			dst[pos] = values[i][j]
			pos++
		}
	}
}

func domainRootsAndWeights(size int) ([]fr.Element, []fr.Element) {
	domain := fft.NewDomain(uint64(size))
	roots := crypto.GetDomainRoots(domain, size)
	weights := crypto.PrecomputeBarycentricWeights(roots)
	return roots, weights
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func codewordSize(k int, rho string) int {
	if rho == "1/4" {
		return k << 2
	}
	return k << 1
}

func writeResult(spec gpt2.LayerSpec, row resultRow) {
	baseDir := config.OutputDir("GPT2_OUTPUT_DIR", filepath.Join("benchmark", "gpt2"))
	dir := filepath.Join(baseDir, spec.Model.Name, row.Protocol)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		log.Fatalf("failed to create result directory: %v", err)
	}
	path := filepath.Join(dir, "summary.csv")

	fileExists := false
	if _, err := os.Stat(path); err == nil {
		fileExists = true
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("failed to open result csv: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if !fileExists {
		if err := writer.Write([]string{"protocol", "model", "seq_len", "l", "constraints", "setup_s", "prove_s", "verify_s", "proof_bytes"}); err != nil {
			log.Fatalf("failed to write result header: %v", err)
		}
	}
	if err := writer.Write([]string{
		row.Protocol,
		row.Model,
		fmt.Sprint(row.SeqLen),
		fmt.Sprint(row.L),
		fmt.Sprint(row.Constraints),
		fmt.Sprintf("%.6f", row.SetupS),
		fmt.Sprintf("%.6f", row.ProveS),
		fmt.Sprintf("%.6f", row.VerifyS),
		fmt.Sprint(row.ProofBytes),
	}); err != nil {
		log.Fatalf("failed to write result row: %v", err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		log.Fatalf("failed to flush result csv: %v", err)
	}
	fmt.Printf("💾 GPT2 result saved to %s\n", path)
}
