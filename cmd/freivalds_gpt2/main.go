package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/Han-16/lamp/benchmark"
	"github.com/Han-16/lamp/circuit"
	"github.com/Han-16/lamp/config"
	"github.com/Han-16/lamp/matrix"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

type tensor struct {
	id   int
	name string
	rows int
	cols int
	data [][]fr.Element
}

type claimSpec struct {
	id   int
	name string
	A    *tensor
	B    *tensor
	C    *tensor
}

type transposeSpec struct {
	left  *tensor
	right *tensor
}

type sliceSpec struct {
	left           *tensor
	right          *tensor
	rightColOffset int
}

type sumSpec struct {
	output *tensor
	terms  []*tensor
}

type graphSpec struct {
	input      *tensor
	output     *tensor
	tensors    []*tensor
	claims     []claimSpec
	slices     []sliceSpec
	transposes []transposeSpec
	sums       []sumSpec
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	seqFlag := flag.Int("seq", config.GetInt("FREIVALDS_GPT2_SEQ", 1), "Log2 sequence length")
	allFlag := flag.Bool("all", config.GetBool("FREIVALDS_GPT2_ALL", false), "Run benchmark range")
	rangeFlag := flag.Bool("range", false, "Alias for -all")
	fromFlag := flag.Int("from", config.GetInt("FREIVALDS_GPT2_SEQ_FROM", 0), "First log2 sequence length when range mode is enabled")
	toFlag := flag.Int("to", config.GetInt("FREIVALDS_GPT2_SEQ_TO", 4), "Last log2 sequence length when range mode is enabled")
	compileFlag := flag.Bool("compile", config.GetBool("FREIVALDS_GPT2_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("FREIVALDS_GPT2_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	outputDir := config.OutputDir("FREIVALDS_GPT2_OUTPUT_DIR", filepath.Join("benchmark", "freivalds_gpt2"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "freivalds_gpt2_benchmark_results.csv")
	file, writer := benchmark.InitFreivaldsGPT2CSV(csvPath)
	defer file.Close()

	onlyCompile := *compileFlag || *onlyCompileFlag
	if *allFlag || *rangeFlag {
		if *fromFlag > *toFlag {
			log.Fatalf("invalid seq range: from=%d, to=%d", *fromFlag, *toFlag)
		}
		fmt.Printf("Running Freivalds GPT-2 range: seq=%d..%d\n", *fromFlag, *toFlag)
		for seqLog := *fromFlag; seqLog <= *toFlag; seqLog++ {
			res := runExperiment(seqLog, onlyCompile)
			benchmark.AppendFreivaldsGPT2ResultToCSV(writer, res)
			fmt.Println("----------------------------------------------------------------")
		}
		return
	}

	res := runExperiment(*seqFlag, onlyCompile)
	benchmark.AppendFreivaldsGPT2ResultToCSV(writer, res)
}

func runExperiment(seqLog int, onlyCompile bool) benchmark.FreivaldsGPT2Result {
	if seqLog < 0 {
		log.Fatalf("invalid seq=%d", seqLog)
	}
	seqLen := 1 << seqLog
	field := ecc.BN254.ScalarField()
	fmt.Printf("Freivalds GPT-2 medium packed-QKV layer: seq=2^%d=%d\n", seqLog, seqLen)

	if onlyCompile {
		graph := buildGPT2MediumShapes(seqLen)
		emptyCircuit := buildCircuit(graph, false)

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("Freivalds GPT-2 compilation failed: %v", err)
		}
		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("Freivalds GPT-2 circuit compiled. Constraints: %d\n", nbConstraints)

		return benchmark.FreivaldsGPT2Result{
			SeqLog:      seqLog,
			SeqLen:      seqLen,
			NumClaims:   len(graph.claims),
			Constraints: nbConstraints,
		}
	}

	graph, matrixComputeTime := buildGPT2MediumData(seqLen)
	fmt.Printf("   ✅ Matrix Compute Time: %.2f s\n", matrixComputeTime)

	emptyCircuit := buildCircuit(graph, false)
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("Freivalds GPT-2 compilation failed: %v", err)
	}
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("Freivalds GPT-2 setup failed: %v", err)
	}
	setupTime := time.Since(startSetup).Seconds()
	nbConstraints := r1csSystem.GetNbConstraints()

	assignment := buildCircuit(graph, true)

	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("failed to build witness for proving: %v", err)
	}
	startProve := time.Now()
	proof, err := groth16.Prove(r1csSystem, pk, witness)
	if err != nil {
		log.Fatalf("Freivalds GPT-2 proof failed: %v", err)
	}
	proveTime := time.Since(startProve).Seconds()

	var proofBuf bytes.Buffer
	if _, err := proof.WriteTo(&proofBuf); err != nil {
		log.Fatalf("Freivalds GPT-2 proof serialization failed: %v", err)
	}
	proofSize := proofBuf.Len()
	fmt.Printf("Freivalds GPT-2 proof size: %d B\n", proofSize)

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("failed to build public witness: %v", err)
	}

	startVerify := time.Now()
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatalf("Freivalds GPT-2 verification failed: %v", err)
	}
	verifyTime := time.Since(startVerify).Seconds()
	fmt.Println("Freivalds GPT-2 proof verified successfully")

	return benchmark.FreivaldsGPT2Result{
		SeqLog:            seqLog,
		SeqLen:            seqLen,
		NumClaims:         len(graph.claims),
		Constraints:       nbConstraints,
		MatrixComputeTime: matrixComputeTime,
		SetupTime:         setupTime,
		ProveTime:         proveTime,
		VerifyTime:        verifyTime,
		ProofSize:         proofSize,
	}
}

func buildGPT2MediumData(seqLen int) (graphSpec, float64) {
	nextID := 0
	graph := graphSpec{}
	var matrixComputeTime time.Duration
	newTensor := func(name string, data [][]fr.Element) *tensor {
		t := &tensor{id: nextID, name: name, rows: len(data), cols: len(data[0]), data: data}
		nextID++
		graph.tensors = append(graph.tensors, t)
		return t
	}
	addClaim := func(name string, A, B, C *tensor) {
		graph.claims = append(graph.claims, claimSpec{id: len(graph.claims), name: name, A: A, B: B, C: C})
	}
	matMulRect := func(A, B [][]fr.Element, rows, inner, cols int) [][]fr.Element {
		start := time.Now()
		out := matrix.MatMulRect(A, B, rows, inner, cols)
		matrixComputeTime += time.Since(start)
		return out
	}

	X := newTensor("X", matrix.GenerateRandomMatrix(seqLen, gpt2D))
	graph.input = X

	WQKV := newTensor("WQKV", generatePaddedQKVWeights())
	QKV := newTensor("QKV", matMulRect(X.data, WQKV.data, seqLen, gpt2D, gpt2PackedQKVCols))
	addClaim("qkv_proj", X, WQKV, QKV)

	Ctxs := make([]*tensor, gpt2Heads)
	for h := 0; h < gpt2Heads; h++ {
		Q := newTensor(fmt.Sprintf("Q_%02d", h), sliceColumns(QKV.data, h*gpt2Dh, gpt2Dh))
		K := newTensor(fmt.Sprintf("K_%02d", h), sliceColumns(QKV.data, gpt2D+h*gpt2Dh, gpt2Dh))
		V := newTensor(fmt.Sprintf("V_%02d", h), sliceColumns(QKV.data, 2*gpt2D+h*gpt2Dh, gpt2Dh))
		KT := newTensor(fmt.Sprintf("KT_%02d", h), matrix.Transpose(K.data, seqLen, gpt2Dh))
		Score := newTensor(fmt.Sprintf("Score_%02d", h), matMulRect(Q.data, KT.data, seqLen, gpt2Dh, seqLen))
		Ctx := newTensor(fmt.Sprintf("Ctx_%02d", h), matMulRect(Score.data, V.data, seqLen, seqLen, gpt2Dh))
		Ctxs[h] = Ctx

		graph.slices = append(graph.slices,
			sliceSpec{left: Q, right: QKV, rightColOffset: h * gpt2Dh},
			sliceSpec{left: K, right: QKV, rightColOffset: gpt2D + h*gpt2Dh},
			sliceSpec{left: V, right: QKV, rightColOffset: 2*gpt2D + h*gpt2Dh},
		)
		addClaim(fmt.Sprintf("score_%02d", h), Q, KT, Score)
		addClaim(fmt.Sprintf("value_%02d", h), Score, V, Ctx)
		graph.transposes = append(graph.transposes, transposeSpec{left: K, right: KT})
	}

	Context := newTensor("Context", concatHeadColumns(Ctxs, seqLen))
	for h := 0; h < gpt2Heads; h++ {
		graph.slices = append(graph.slices, sliceSpec{left: Ctxs[h], right: Context, rightColOffset: h * gpt2Dh})
	}

	Wout := newTensor("Wout", matrix.GenerateRandomMatrix(gpt2D, gpt2D))
	AttnOut := newTensor("AttnOut", matMulRect(Context.data, Wout.data, seqLen, gpt2D, gpt2D))
	Wup := newTensor("Wup", matrix.GenerateRandomMatrix(gpt2D, gpt2M))
	Hidden := newTensor("Hidden", matMulRect(AttnOut.data, Wup.data, seqLen, gpt2D, gpt2M))
	Wdown := newTensor("Wdown", matrix.GenerateRandomMatrix(gpt2M, gpt2D))
	Out := newTensor("Out", matMulRect(Hidden.data, Wdown.data, seqLen, gpt2M, gpt2D))
	graph.output = Out

	addClaim("attn_out", Context, Wout, AttnOut)
	addClaim("mlp_up", AttnOut, Wup, Hidden)
	addClaim("mlp_down", Hidden, Wdown, Out)

	return graph, matrixComputeTime.Seconds()
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

func buildGPT2MediumShapes(seqLen int) graphSpec {
	nextID := 0
	graph := graphSpec{}
	newTensor := func(name string, rows, cols int) *tensor {
		t := &tensor{id: nextID, name: name, rows: rows, cols: cols}
		nextID++
		graph.tensors = append(graph.tensors, t)
		return t
	}
	addClaim := func(name string, A, B, C *tensor) {
		graph.claims = append(graph.claims, claimSpec{id: len(graph.claims), name: name, A: A, B: B, C: C})
	}

	X := newTensor("X", seqLen, gpt2D)
	graph.input = X
	WQKV := newTensor("WQKV", gpt2D, gpt2PackedQKVCols)
	QKV := newTensor("QKV", seqLen, gpt2PackedQKVCols)
	addClaim("qkv_proj", X, WQKV, QKV)

	Ctxs := make([]*tensor, gpt2Heads)
	for h := 0; h < gpt2Heads; h++ {
		Q := newTensor(fmt.Sprintf("Q_%02d", h), seqLen, gpt2Dh)
		K := newTensor(fmt.Sprintf("K_%02d", h), seqLen, gpt2Dh)
		V := newTensor(fmt.Sprintf("V_%02d", h), seqLen, gpt2Dh)
		KT := newTensor(fmt.Sprintf("KT_%02d", h), gpt2Dh, seqLen)
		Score := newTensor(fmt.Sprintf("Score_%02d", h), seqLen, seqLen)
		Ctx := newTensor(fmt.Sprintf("Ctx_%02d", h), seqLen, gpt2Dh)
		Ctxs[h] = Ctx

		graph.slices = append(graph.slices,
			sliceSpec{left: Q, right: QKV, rightColOffset: h * gpt2Dh},
			sliceSpec{left: K, right: QKV, rightColOffset: gpt2D + h*gpt2Dh},
			sliceSpec{left: V, right: QKV, rightColOffset: 2*gpt2D + h*gpt2Dh},
		)
		addClaim(fmt.Sprintf("score_%02d", h), Q, KT, Score)
		addClaim(fmt.Sprintf("value_%02d", h), Score, V, Ctx)
		graph.transposes = append(graph.transposes, transposeSpec{left: K, right: KT})
	}

	Context := newTensor("Context", seqLen, gpt2D)
	for h := 0; h < gpt2Heads; h++ {
		graph.slices = append(graph.slices, sliceSpec{left: Ctxs[h], right: Context, rightColOffset: h * gpt2Dh})
	}

	Wout := newTensor("Wout", gpt2D, gpt2D)
	AttnOut := newTensor("AttnOut", seqLen, gpt2D)
	Wup := newTensor("Wup", gpt2D, gpt2M)
	Hidden := newTensor("Hidden", seqLen, gpt2M)
	Wdown := newTensor("Wdown", gpt2M, gpt2D)
	Out := newTensor("Out", seqLen, gpt2D)
	graph.output = Out

	addClaim("attn_out", Context, Wout, AttnOut)
	addClaim("mlp_up", AttnOut, Wup, Hidden)
	addClaim("mlp_down", Hidden, Wdown, Out)

	return graph
}

func buildCircuit(graph graphSpec, assignment bool) *circuit.FreivaldsGPT2Circuit {
	c := &circuit.FreivaldsGPT2Circuit{
		Input:           make([]frontend.Variable, graph.input.rows*graph.input.cols),
		Output:          make([]frontend.Variable, graph.output.rows*graph.output.cols),
		Tensors:         make([]circuit.FreivaldsGPT2Tensor, len(graph.tensors)),
		Claims:          make([]circuit.FreivaldsGPT2Claim, len(graph.claims)),
		SliceChecks:     make([]circuit.FreivaldsGPT2SliceCheck, len(graph.slices)),
		TransposeChecks: make([]circuit.FreivaldsGPT2TransposeCheck, len(graph.transposes)),
		SumChecks:       make([]circuit.FreivaldsGPT2SumCheck, len(graph.sums)),
		InputTensor:     graph.input.id,
		OutputTensor:    graph.output.id,
	}

	if assignment {
		assignFlat(c.Input, graph.input.data)
		assignFlat(c.Output, graph.output.data)
	}

	for i, t := range graph.tensors {
		c.Tensors[i] = circuit.FreivaldsGPT2Tensor{
			Rows:   t.rows,
			Cols:   t.cols,
			Values: make([][]frontend.Variable, t.rows),
		}
		for row := 0; row < t.rows; row++ {
			c.Tensors[i].Values[row] = make([]frontend.Variable, t.cols)
			if assignment {
				for col := 0; col < t.cols; col++ {
					c.Tensors[i].Values[row][col] = t.data[row][col]
				}
			}
		}
	}

	for i, claim := range graph.claims {
		c.Claims[i] = circuit.FreivaldsGPT2Claim{
			ID: claim.id,
			A:  claim.A.id,
			B:  claim.B.id,
			C:  claim.C.id,
		}
	}
	for i, check := range graph.slices {
		c.SliceChecks[i] = circuit.FreivaldsGPT2SliceCheck{
			Left:           check.left.id,
			Right:          check.right.id,
			RightColOffset: check.rightColOffset,
		}
	}
	for i, check := range graph.transposes {
		c.TransposeChecks[i] = circuit.FreivaldsGPT2TransposeCheck{
			Left:  check.left.id,
			Right: check.right.id,
		}
	}
	for i, check := range graph.sums {
		c.SumChecks[i] = circuit.FreivaldsGPT2SumCheck{
			Output: check.output.id,
			Terms:  make([]int, len(check.terms)),
		}
		for j, term := range check.terms {
			c.SumChecks[i].Terms[j] = term.id
		}
	}

	return c
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
