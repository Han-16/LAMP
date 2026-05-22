package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"math/bits"
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
	rectCommitA = iota
	rectCommitB
	rectCommitC
	rectCommitScalar
)

const (
	labelIndicesIn  uint64 = 11
	labelIndicesOut uint64 = 12
	labelRSPointX   uint64 = 13
	labelRSPointYZ  uint64 = 14
)

type rectDomains struct {
	domainKIn  []fr.Element
	weightsKIn []fr.Element
	domainNIn  []fr.Element
	weightsNIn []fr.Element

	domainKOut  []fr.Element
	weightsKOut []fr.Element
	domainNOut  []fr.Element
	weightsNOut []fr.Element
}

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatalf("failed to load .env: %v", err)
	}

	rowsFlag := flag.Int("rows", config.GetInt("RECTMEOW_ROWS", 2), "Log2 rows in A and C; --rows 3 means 8 rows")
	innerFlag := flag.Int("inner", config.GetInt("RECTMEOW_INNER", 2), "Log2 shared dimension; --inner 4 means inner dimension 16")
	colsFlag := flag.Int("cols", config.GetInt("RECTMEOW_COLS", 2), "Log2 columns in B and C; --cols 2 means 4 columns")
	rhoFlag := flag.String("rho", config.GetString("RECTMEOW_RHO", "1/2"), "Code rate, 1/2 or 1/4")
	LFlag := flag.Int("L", config.GetInt("RECTMEOW_L", 2), "Number of unique query indices per domain")
	compileFlag := flag.Bool("compile", config.GetBool("RECTMEOW_ONLY_COMPILE", false), "Only compile the circuit to get constraints")
	onlyCompileFlag := flag.Bool("OnlyCompile", config.GetBool("RECTMEOW_ONLY_COMPILE", false), "Alias for -compile")
	flag.Parse()

	onlyCompile := *compileFlag || *onlyCompileFlag
	outputDir := config.OutputDir("RECTMEOW_OUTPUT_DIR", filepath.Join("benchmark", "rectmeow"))
	if err := benchmark.EnsureDir(outputDir); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}
	csvPath := filepath.Join(outputDir, "rectmeow_benchmark_results.csv")
	file, writer := benchmark.InitRectMeowCSV(csvPath)
	defer file.Close()

	res := runExperiment(*rowsFlag, *innerFlag, *colsFlag, *rhoFlag, *LFlag, onlyCompile)
	benchmark.AppendRectMeowResultToCSV(writer, res)
	fmt.Println("RectMeow task finished")
}

func runExperiment(logRows, logInner, logCols int, rhoStr string, L int, onlyCompile bool) benchmark.RectMeowResult {
	validateParams(logRows, logInner, logCols, L)

	rows := dimensionFromLog("rows", logRows)
	inner := dimensionFromLog("inner", logInner)
	cols := dimensionFromLog("cols", logCols)

	NIn := codewordLength(inner, rhoStr)
	NOut := codewordLength(cols, rhoStr)
	if L > NIn || L > NOut {
		log.Fatalf("L must fit both encoded domains: L=%d NIn=%d NOut=%d", L, NIn, NOut)
	}
	depthIn := log2PowerOfTwo(NIn)
	depthOut := log2PowerOfTwo(NOut)
	field := ecc.BN254.ScalarField()

	fmt.Printf("RectMeow protocol: logRows=%d, logInner=%d, logCols=%d => rows=%d, inner=%d, cols=%d, NIn=%d, NOut=%d, L=%d\n", logRows, logInner, logCols, rows, inner, cols, NIn, NOut, L)

	var setupTime float64
	startDomainSetup := time.Now()
	domains := buildRectDomains(inner, NIn, cols, NOut)
	setupTime += time.Since(startDomainSetup).Seconds()

	if onlyCompile {
		fmt.Println("Compiling RectMeow circuit for constraints")
		emptyCircuit := newRectCircuit(rows, inner, cols, NIn, NOut, depthIn, depthOut, L, domains)

		r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
		if err != nil {
			log.Fatalf("rectmeow compilation failed: %v", err)
		}

		nbConstraints := r1csSystem.GetNbConstraints()
		fmt.Printf("RectMeow circuit compiled. Constraints: %d\n", nbConstraints)

		return benchmark.RectMeowResult{
			LogRows:     logRows,
			LogInner:    logInner,
			LogCols:     logCols,
			Rows:        rows,
			Inner:       inner,
			Cols:        cols,
			Rho:         rhoStr,
			NIn:         NIn,
			NOut:        NOut,
			NumQueries:  L,
			Constraints: nbConstraints,
		}
	}

	startProtocolSetup := time.Now()
	ckRows := crypto.SetupCommitKey(rows)
	ckInner := crypto.SetupCommitKey(inner)
	ckScalar := crypto.SetupCommitKey(1)

	encoderIn := crypto.NewEncoder(inner, NIn)
	encoderOut := crypto.NewEncoder(cols, NOut)
	prover := protocol.NewProver(nil, ckRows, encoderIn)
	setupTime += time.Since(startProtocolSetup).Seconds()

	startCompute := time.Now()
	matA := matrix.GenerateRandomMatrix(rows, inner)
	matB := matrix.GenerateRandomMatrix(inner, cols)
	matC := matrix.MatMulRect(matA, matB, rows, inner, cols)
	matrixComputeTime := time.Since(startCompute).Seconds()

	startMatCommit := time.Now()

	_, encA, err := encoderIn.EncodeRows(matA)
	if err != nil {
		log.Fatalf("failed to encode A: %v", err)
	}
	colsEncA := matrix.Transpose(encA, rows, NIn)
	treeA, cmA, leavesA, blA := prover.CommitMatrixBlindedWithKey(colsEncA, depthIn, ckRows)

	_, encB, err := encoderOut.EncodeRows(matB)
	if err != nil {
		log.Fatalf("failed to encode B: %v", err)
	}
	colsEncB := matrix.Transpose(encB, inner, NOut)
	treeB, cmB, leavesB, blB := prover.CommitMatrixBlindedWithKey(colsEncB, depthOut, ckInner)

	_, encC, err := encoderOut.EncodeRows(matC)
	if err != nil {
		log.Fatalf("failed to encode C: %v", err)
	}
	colsEncC := matrix.Transpose(encC, rows, NOut)
	treeC, cmC, leavesC, blC := prover.CommitMatrixBlindedWithKey(colsEncC, depthOut, ckRows)

	CmABC := crypto.HashElementsMiMC(cmA, cmB, cmC)
	ChallengeR := crypto.HashElements(CmABC)
	ChallengeRPowers := matrix.Powers(ChallengeR, rows)
	matCommitTime := time.Since(startMatCommit).Seconds()

	startVecCommit := time.Now()
	vecX := matrix.VecMatMulRect(ChallengeRPowers, matA, rows, inner)
	vecYZ := matrix.VecMatMulRect(vecX, matB, inner, cols)

	_, encX, err := encoderIn.Encode(vecX)
	if err != nil {
		log.Fatalf("failed to encode X: %v", err)
	}
	_, encYZ, err := encoderOut.Encode(vecYZ)
	if err != nil {
		log.Fatalf("failed to encode YZ: %v", err)
	}

	treeX, cmX, leavesX, blX := prover.CommitScalarsBlinded(encX, depthIn, ckScalar)
	treeYZ, cmYZ, leavesYZ, blYZ := prover.CommitScalarsBlinded(encYZ, depthOut, ckScalar)

	CmXYZ := crypto.HashElementsMiMC(cmX, cmYZ)
	indicesIn, err := protocol.GenerateUniqueIndicesWithLabel(CmXYZ, labelIndicesIn, NIn, L)
	if err != nil {
		log.Fatalf("failed to sample input-domain indices: %v", err)
	}
	indicesOut, err := protocol.GenerateUniqueIndicesWithLabel(CmXYZ, labelIndicesOut, NOut, L)
	if err != nil {
		log.Fatalf("failed to sample output-domain indices: %v", err)
	}
	rsPointX, err := protocol.GenerateRSEvaluationPointWithLabel(CmXYZ, labelRSPointX, NIn, nil)
	if err != nil {
		log.Fatalf("failed to sample X RS point: %v", err)
	}
	rsPointYZ, err := protocol.GenerateRSEvaluationPointWithLabel(CmXYZ, labelRSPointYZ, NOut, &rsPointX)
	if err != nil {
		log.Fatalf("failed to sample YZ RS point: %v", err)
	}
	vecCommitTime := time.Since(startVecCommit).Seconds()

	fmt.Println("Compiling and setting up RectMeow circuit")
	emptyCircuit := newRectCircuit(rows, inner, cols, NIn, NOut, depthIn, depthOut, L, domains)
	r1csSystem, err := frontend.Compile(field, r1cs.NewBuilder, emptyCircuit)
	if err != nil {
		log.Fatalf("rectmeow compilation failed: %v", err)
	}
	nbConstraints := r1csSystem.GetNbConstraints()

	startSetup := time.Now()
	pk, vk, err := groth16.Setup(r1csSystem)
	if err != nil {
		log.Fatalf("rectmeow setup failed: %v", err)
	}
	setupTime += time.Since(startSetup).Seconds()

	assignment := newRectCircuit(rows, inner, cols, NIn, NOut, depthIn, depthOut, L, domains)
	assignment.Roots = [5]frontend.Variable{cmA, cmB, cmC, cmX, cmYZ}
	assignment.CmABC = CmABC
	assignment.CmXYZ = CmXYZ
	assignment.ChallengeR = ChallengeR
	assignment.RSPointX = rsPointX
	assignment.RSPointYZ = rsPointYZ

	for i := 0; i < inner; i++ {
		assignment.VecX[i] = vecX[i]
	}
	for i := 0; i < cols; i++ {
		assignment.VecYZ[i] = vecYZ[i]
	}
	for i := 0; i < NIn; i++ {
		assignment.EncX[i] = encX[i]
	}
	for i := 0; i < NOut; i++ {
		assignment.EncYZ[i] = encYZ[i]
	}

	for i, idx := range indicesIn {
		assignment.IndicesIn[i] = idx
		assignment.TargetEncX[i] = encX[idx]
		for j := 0; j < rows; j++ {
			assignment.ColsEncA[i][j] = colsEncA[idx][j]
		}
	}
	for i, idx := range indicesOut {
		assignment.IndicesOut[i] = idx
		assignment.TargetEncYZ[i] = encYZ[idx]
		for j := 0; j < inner; j++ {
			assignment.ColsEncB[i][j] = colsEncB[idx][j]
		}
		for j := 0; j < rows; j++ {
			assignment.ColsEncC[i][j] = colsEncC[idx][j]
		}
	}

	startProtocolBindSetup := time.Now()
	proverWithPK := protocol.NewProver(pk, ckRows, encoderIn)
	verifier := protocol.NewVerifier(vk, ckRows, proverWithPK.CK2)
	setupTime += time.Since(startProtocolBindSetup).Seconds()

	proofWitness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("failed to create rectmeow witness for proving: %v", err)
	}
	startCircuitProve := time.Now()
	circuitProof, err := groth16.Prove(r1csSystem, pk, proofWitness)
	if err != nil {
		log.Fatalf("rectmeow circuit proof failed: %v", err)
	}
	circuitProveTime := time.Since(startCircuitProve).Seconds()
	cmVec2, blindingsIn := protocol.ExtractGroth16CommitmentsAndBlindings(circuitProof)
	if len(cmVec2) < 4 || len(blindingsIn) < 4 || len(proverWithPK.CK2) < 4 {
		log.Fatalf("expected at least 4 Groth16 committed-variable groups, got commitments=%d blindings=%d keys=%d", len(cmVec2), len(blindingsIn), len(proverWithPK.CK2))
	}

	fmt.Println("Generating RectMeow Merkle and CPLink proofs")
	startOfflineProve := time.Now()

	mpA := make([][]fr.Element, L)
	mpX := make([][]fr.Element, L)
	for i, idx := range indicesIn {
		mpA[i] = proverWithPK.GenerateMembershipProof(treeA, idx, depthIn)
		mpX[i] = proverWithPK.GenerateMembershipProof(treeX, idx, depthIn)
	}

	mpB := make([][]fr.Element, L)
	mpC := make([][]fr.Element, L)
	mpYZ := make([][]fr.Element, L)
	for i, idx := range indicesOut {
		mpB[i] = proverWithPK.GenerateMembershipProof(treeB, idx, depthOut)
		mpC[i] = proverWithPK.GenerateMembershipProof(treeC, idx, depthOut)
		mpYZ[i] = proverWithPK.GenerateMembershipProof(treeYZ, idx, depthOut)
	}

	aBlocks, aCommits, aBlindings := collectColumnBlocks(indicesIn, colsEncA, leavesA, blA)
	bBlocks, bCommits, bBlindings := collectColumnBlocks(indicesOut, colsEncB, leavesB, blB)
	cBlocks, cCommits, cBlindings := collectColumnBlocks(indicesOut, colsEncC, leavesC, blC)

	scalarBlocks := make([][]fr.Element, 0, 2*L)
	scalarCommits := make([]bn254.G1Affine, 0, 2*L)
	scalarBlindings := make([]fr.Element, 0, 2*L)
	for _, idx := range indicesIn {
		scalarBlocks = append(scalarBlocks, []fr.Element{encX[idx]})
		scalarCommits = append(scalarCommits, leavesX[idx])
		scalarBlindings = append(scalarBlindings, blX[idx])
	}
	for _, idx := range indicesOut {
		scalarBlocks = append(scalarBlocks, []fr.Element{encYZ[idx]})
		scalarCommits = append(scalarCommits, leavesYZ[idx])
		scalarBlindings = append(scalarBlindings, blYZ[idx])
	}

	aLinkProof, err := crypto.ProveAmComEq(aBlocks, blindingsIn[rectCommitA], aBlindings, proverWithPK.CK2[rectCommitA], ckRows, cmVec2[rectCommitA], aCommits)
	if err != nil {
		log.Fatalf("A CPLink proof failed: %v", err)
	}
	bLinkProof, err := crypto.ProveAmComEq(bBlocks, blindingsIn[rectCommitB], bBlindings, proverWithPK.CK2[rectCommitB], ckInner, cmVec2[rectCommitB], bCommits)
	if err != nil {
		log.Fatalf("B CPLink proof failed: %v", err)
	}
	cLinkProof, err := crypto.ProveAmComEq(cBlocks, blindingsIn[rectCommitC], cBlindings, proverWithPK.CK2[rectCommitC], ckRows, cmVec2[rectCommitC], cCommits)
	if err != nil {
		log.Fatalf("C CPLink proof failed: %v", err)
	}
	scalarLinkProof, err := crypto.ProveAmComEq(scalarBlocks, blindingsIn[rectCommitScalar], scalarBlindings, proverWithPK.CK2[rectCommitScalar], ckScalar, cmVec2[rectCommitScalar], scalarCommits)
	if err != nil {
		log.Fatalf("scalar CPLink proof failed: %v", err)
	}
	offlineProveTime := time.Since(startOfflineProve).Seconds()

	publicWitness, err := proofWitness.Public()
	if err != nil {
		log.Fatalf("failed to create rectmeow public witness: %v", err)
	}

	fmt.Println("Verifying RectMeow proofs")
	startVerify := time.Now()
	expectedCmABC := crypto.HashElementsMiMC(cmA, cmB, cmC)
	expectedChallengeR := crypto.HashElements(expectedCmABC)
	expectedCmXYZ := crypto.HashElementsMiMC(cmX, cmYZ)
	expectedIndicesIn, _ := protocol.GenerateUniqueIndicesWithLabel(expectedCmXYZ, labelIndicesIn, NIn, L)
	expectedIndicesOut, _ := protocol.GenerateUniqueIndicesWithLabel(expectedCmXYZ, labelIndicesOut, NOut, L)
	expectedRSPointX, _ := protocol.GenerateRSEvaluationPointWithLabel(expectedCmXYZ, labelRSPointX, NIn, nil)
	expectedRSPointYZ, _ := protocol.GenerateRSEvaluationPointWithLabel(expectedCmXYZ, labelRSPointYZ, NOut, &expectedRSPointX)
	if !CmABC.Equal(&expectedCmABC) || !ChallengeR.Equal(&expectedChallengeR) || !CmXYZ.Equal(&expectedCmXYZ) || !rsPointX.Equal(&expectedRSPointX) || !rsPointYZ.Equal(&expectedRSPointYZ) {
		log.Fatal("rectmeow transcript derivation failed")
	}
	assertSameIndices("input-domain", indicesIn, expectedIndicesIn)
	assertSameIndices("output-domain", indicesOut, expectedIndicesOut)

	startCircuitVerify := time.Now()
	if err := groth16.Verify(circuitProof, vk, publicWitness); err != nil {
		log.Fatalf("rectmeow Groth16 verification failed: %v", err)
	}
	circuitVerifyTime := time.Since(startCircuitVerify).Seconds()

	var merkleVerifyTime float64
	for i, idx := range indicesIn {
		startMerkle := time.Now()
		if !verifier.VerifyMembership(cmA, leavesA[idx], mpA[i], idx, depthIn) {
			log.Fatal("rectmeow A Merkle proof failed")
		}
		if !verifier.VerifyMembership(cmX, leavesX[idx], mpX[i], idx, depthIn) {
			log.Fatal("rectmeow X Merkle proof failed")
		}
		merkleVerifyTime += time.Since(startMerkle).Seconds()
	}
	for i, idx := range indicesOut {
		startMerkle := time.Now()
		if !verifier.VerifyMembership(cmB, leavesB[idx], mpB[i], idx, depthOut) {
			log.Fatal("rectmeow B Merkle proof failed")
		}
		if !verifier.VerifyMembership(cmC, leavesC[idx], mpC[i], idx, depthOut) {
			log.Fatal("rectmeow C Merkle proof failed")
		}
		if !verifier.VerifyMembership(cmYZ, leavesYZ[idx], mpYZ[i], idx, depthOut) {
			log.Fatal("rectmeow YZ Merkle proof failed")
		}
		merkleVerifyTime += time.Since(startMerkle).Seconds()
	}

	startCpLink := time.Now()
	if !crypto.VerifyAmComEq(cmVec2[rectCommitA], aCommits, aLinkProof, verifier.CK2[rectCommitA], ckRows) {
		log.Fatal("rectmeow A CPLink verification failed")
	}
	if !crypto.VerifyAmComEq(cmVec2[rectCommitB], bCommits, bLinkProof, verifier.CK2[rectCommitB], ckInner) {
		log.Fatal("rectmeow B CPLink verification failed")
	}
	if !crypto.VerifyAmComEq(cmVec2[rectCommitC], cCommits, cLinkProof, verifier.CK2[rectCommitC], ckRows) {
		log.Fatal("rectmeow C CPLink verification failed")
	}
	if !crypto.VerifyAmComEq(cmVec2[rectCommitScalar], scalarCommits, scalarLinkProof, verifier.CK2[rectCommitScalar], ckScalar) {
		log.Fatal("rectmeow scalar CPLink verification failed")
	}
	cpLinkVerifyTime := time.Since(startCpLink).Seconds()

	totalVerifyTime := time.Since(startVerify).Seconds()
	fmt.Println("RectMeow proof verified successfully")

	totalProveTime := matCommitTime + vecCommitTime + circuitProveTime + offlineProveTime

	var buf bytes.Buffer
	circuitProof.WriteTo(&buf)
	groth16ProofSize := buf.Len()
	merkleProofSize := (2*L*depthIn+3*L*depthOut)*crypto.MerkleHashSizeBytes + 5*L*crypto.G1AffineSizeBytes
	cpLinkProofSize := crypto.AmComEqProofSizeBytes(aLinkProof) +
		crypto.AmComEqProofSizeBytes(bLinkProof) +
		crypto.AmComEqProofSizeBytes(cLinkProof) +
		crypto.AmComEqProofSizeBytes(scalarLinkProof)
	totalProofSize := groth16ProofSize + merkleProofSize + cpLinkProofSize

	fmt.Printf("Proof sizes: Groth16=%d B, Merkle=%d B, CPLink=%d B, Total=%d B\n", groth16ProofSize, merkleProofSize, cpLinkProofSize, totalProofSize)

	return benchmark.RectMeowResult{
		LogRows:           logRows,
		LogInner:          logInner,
		LogCols:           logCols,
		Rows:              rows,
		Inner:             inner,
		Cols:              cols,
		Rho:               rhoStr,
		NIn:               NIn,
		NOut:              NOut,
		NumQueries:        L,
		Constraints:       nbConstraints,
		MatrixComputeTime: matrixComputeTime,
		SetupTime:         setupTime,
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

func validateParams(logRows, logInner, logCols, L int) {
	if logRows < 0 || logInner < 0 || logCols < 0 {
		log.Fatalf("rows, inner, and cols are log2 exponents and must be non-negative: rows=%d inner=%d cols=%d", logRows, logInner, logCols)
	}
	if L <= 0 {
		log.Fatalf("L must be positive: %d", L)
	}
}

func dimensionFromLog(name string, exponent int) int {
	if exponent < 0 || exponent >= bits.UintSize-1 {
		log.Fatalf("%s exponent out of range: %d", name, exponent)
	}
	return 1 << exponent
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

func isPowerOfTwo(v int) bool {
	return v > 0 && v&(v-1) == 0
}

func log2PowerOfTwo(v int) int {
	if !isPowerOfTwo(v) {
		log.Fatalf("expected power-of-two value, got %d", v)
	}
	return bits.Len(uint(v)) - 1
}

func buildRectDomains(kIn, nIn, kOut, nOut int) rectDomains {
	domainKIn, weightsKIn := domainAndWeights(kIn)
	domainNIn, weightsNIn := domainAndWeights(nIn)
	domainKOut, weightsKOut := domainAndWeights(kOut)
	domainNOut, weightsNOut := domainAndWeights(nOut)

	return rectDomains{
		domainKIn:  domainKIn,
		weightsKIn: weightsKIn,
		domainNIn:  domainNIn,
		weightsNIn: weightsNIn,

		domainKOut:  domainKOut,
		weightsKOut: weightsKOut,
		domainNOut:  domainNOut,
		weightsNOut: weightsNOut,
	}
}

func domainAndWeights(size int) ([]fr.Element, []fr.Element) {
	domain := fft.NewDomain(uint64(size))
	roots := crypto.GetDomainRoots(domain, size)
	weights := crypto.PrecomputeBarycentricWeights(roots)
	return roots, weights
}

func newRectCircuit(rows, inner, cols, nIn, nOut, depthIn, depthOut, L int, domains rectDomains) *circuit.RectMeowCircuit {
	c := &circuit.RectMeowCircuit{
		M: rows, KIn: inner, KOut: cols,
		NIn: nIn, NOut: nOut,
		DepthIn: depthIn, DepthOut: depthOut,
		DomainKIn: domains.domainKIn, WeightsKIn: domains.weightsKIn,
		DomainNIn: domains.domainNIn, WeightsNIn: domains.weightsNIn,
		DomainKOut: domains.domainKOut, WeightsKOut: domains.weightsKOut,
		DomainNOut: domains.domainNOut, WeightsNOut: domains.weightsNOut,
		IndicesIn: make([]frontend.Variable, L), IndicesOut: make([]frontend.Variable, L),
		ColsEncA: make([][]frontend.Variable, L),
		ColsEncB: make([][]frontend.Variable, L),
		ColsEncC: make([][]frontend.Variable, L),
		VecX:     make([]frontend.Variable, inner), VecYZ: make([]frontend.Variable, cols),
		EncX: make([]frontend.Variable, nIn), EncYZ: make([]frontend.Variable, nOut),
		TargetEncX: make([]frontend.Variable, L), TargetEncYZ: make([]frontend.Variable, L),
	}
	for i := 0; i < L; i++ {
		c.ColsEncA[i] = make([]frontend.Variable, rows)
		c.ColsEncB[i] = make([]frontend.Variable, inner)
		c.ColsEncC[i] = make([]frontend.Variable, rows)
	}
	return c
}

func collectColumnBlocks(indices []int, columns [][]fr.Element, commits []bn254.G1Affine, blindings []fr.Element) ([][]fr.Element, []bn254.G1Affine, []fr.Element) {
	blocks := make([][]fr.Element, 0, len(indices))
	selectedCommits := make([]bn254.G1Affine, 0, len(indices))
	selectedBlindings := make([]fr.Element, 0, len(indices))
	for _, idx := range indices {
		blocks = append(blocks, columns[idx])
		selectedCommits = append(selectedCommits, commits[idx])
		selectedBlindings = append(selectedBlindings, blindings[idx])
	}
	return blocks, selectedCommits, selectedBlindings
}

func assertSameIndices(name string, actual, expected []int) {
	if len(actual) != len(expected) {
		log.Fatalf("%s index length mismatch: got %d expected %d", name, len(actual), len(expected))
	}
	for i := range actual {
		if actual[i] != expected[i] {
			log.Fatalf("%s index mismatch at %d: got %d expected %d", name, i, actual[i], expected[i])
		}
	}
}
