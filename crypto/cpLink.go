package crypto

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type QALinkProvingKey struct {
	P          []bls12381.G1Affine
	BlockCount int
	BlockLen   int
}

type QALinkVerifyingKey struct {
	C          []bls12381.G2Affine
	A          bls12381.G2Affine
	BlockCount int
	BlockLen   int
}

type QALinkProof struct {
	Pi bls12381.G1Affine
}

type QABatchLinkProvingKey struct {
	SnarkG     []bls12381.G1Affine
	SnarkH     bls12381.G1Affine
	ExternalG  []bls12381.G1Affine
	ExternalH  bls12381.G1Affine
	BlockCount int
	BlockLen   int
}

type QABatchLinkVerifyingKey struct {
	C0         bls12381.G2Affine
	C1         bls12381.G2Affine
	A          bls12381.G2Affine
	BlockCount int
	BlockLen   int
}

type QABatchLinkProof struct {
	Pi bls12381.G1Affine
}

const G1AffineSizeBytes = bls12381.SizeOfG1AffineUncompressed

func SetupQALink(blockCount, blockLen int, snarkCK CommitKey, externalCK CommitKey) (QALinkProvingKey, QALinkVerifyingKey, error) {
	if blockCount <= 0 || blockLen <= 0 {
		return QALinkProvingKey{}, QALinkVerifyingKey{}, fmt.Errorf("qa-link requires positive block count and block length")
	}
	if len(snarkCK.G) != blockCount*blockLen {
		return QALinkProvingKey{}, QALinkVerifyingKey{}, fmt.Errorf("snark commitment key length must match flattened blocks")
	}
	if len(externalCK.G) != blockLen {
		return QALinkProvingKey{}, QALinkVerifyingKey{}, fmt.Errorf("external commitment key length must match block length")
	}

	trapdoor := make([]fr.Element, blockCount+1)
	for i := range trapdoor {
		trapdoor[i] = randomNonZeroElement()
	}
	a := randomNonZeroElement()

	p := make([]bls12381.G1Affine, blockCount*blockLen+1+blockCount)
	k0 := elementBigInt(trapdoor[0])
	kBig := make([]big.Int, blockCount)
	for i := 0; i < blockCount; i++ {
		kBig[i] = elementBigInt(trapdoor[i+1])
	}

	numWorkers := runtime.NumCPU()
	totalValues := blockCount * blockLen
	chunkSize := (totalValues + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup
	for worker := 0; worker < numWorkers; worker++ {
		start := worker * chunkSize
		end := start + chunkSize
		if end > totalValues {
			end = totalValues
		}
		if start >= end {
			break
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for flatIndex := start; flatIndex < end; flatIndex++ {
				block := flatIndex / blockLen
				offset := flatIndex % blockLen
				var point bls12381.G1Jac
				point.JointScalarMultiplication(&snarkCK.G[flatIndex], &externalCK.G[offset], &k0, &kBig[block])
				p[flatIndex].FromJacobian(&point)
			}
		}(start, end)
	}
	wg.Wait()

	var alphaPoint bls12381.G1Affine
	alphaPoint.ScalarMultiplication(&snarkCK.H, &k0)
	p[totalValues] = alphaPoint

	for block := 0; block < blockCount; block++ {
		var betaPoint bls12381.G1Affine
		betaPoint.ScalarMultiplication(&externalCK.H, &kBig[block])
		p[totalValues+1+block] = betaPoint
	}

	aTrapdoor := make([]fr.Element, len(trapdoor))
	for i := range trapdoor {
		aTrapdoor[i].Mul(&a, &trapdoor[i])
	}
	_, _, _, g2 := bls12381.Generators()
	c := bls12381.BatchScalarMultiplicationG2(&g2, aTrapdoor)
	var aBig big.Int
	a.BigInt(&aBig)
	var aG2 bls12381.G2Affine
	aG2.ScalarMultiplication(&g2, &aBig)

	pk := QALinkProvingKey{
		P:          p,
		BlockCount: blockCount,
		BlockLen:   blockLen,
	}
	vk := QALinkVerifyingKey{
		C:          c,
		A:          aG2,
		BlockCount: blockCount,
		BlockLen:   blockLen,
	}
	return pk, vk, nil
}

func SetupQABatchLink(blockCount, blockLen int, snarkCK CommitKey, externalCK CommitKey) (QABatchLinkProvingKey, QABatchLinkVerifyingKey, error) {
	if blockCount <= 0 || blockLen <= 0 {
		return QABatchLinkProvingKey{}, QABatchLinkVerifyingKey{}, fmt.Errorf("qa-batch-link requires positive block count and block length")
	}
	if len(snarkCK.G) != blockCount*blockLen {
		return QABatchLinkProvingKey{}, QABatchLinkVerifyingKey{}, fmt.Errorf("snark commitment key length must match flattened blocks")
	}
	if len(externalCK.G) != blockLen {
		return QABatchLinkProvingKey{}, QABatchLinkVerifyingKey{}, fmt.Errorf("external commitment key length must match block length")
	}

	k0 := randomNonZeroElement()
	k1 := randomNonZeroElement()
	a := randomNonZeroElement()
	k0Big := elementBigInt(k0)
	k1Big := elementBigInt(k1)

	snarkG := scaleG1Points(snarkCK.G, k0Big)
	externalG := scaleG1Points(externalCK.G, k1Big)

	var snarkH bls12381.G1Affine
	snarkH.ScalarMultiplication(&snarkCK.H, &k0Big)
	var externalH bls12381.G1Affine
	externalH.ScalarMultiplication(&externalCK.H, &k1Big)

	var ak0, ak1 fr.Element
	ak0.Mul(&a, &k0)
	ak1.Mul(&a, &k1)

	_, _, _, g2 := bls12381.Generators()
	var ak0Big, ak1Big, aBig big.Int
	ak0.BigInt(&ak0Big)
	ak1.BigInt(&ak1Big)
	a.BigInt(&aBig)

	var c0, c1, aG2 bls12381.G2Affine
	c0.ScalarMultiplication(&g2, &ak0Big)
	c1.ScalarMultiplication(&g2, &ak1Big)
	aG2.ScalarMultiplication(&g2, &aBig)

	return QABatchLinkProvingKey{
			SnarkG:     snarkG,
			SnarkH:     snarkH,
			ExternalG:  externalG,
			ExternalH:  externalH,
			BlockCount: blockCount,
			BlockLen:   blockLen,
		}, QABatchLinkVerifyingKey{
			C0:         c0,
			C1:         c1,
			A:          aG2,
			BlockCount: blockCount,
			BlockLen:   blockLen,
		}, nil
}

func ProveQALink(blocks [][]fr.Element, alpha fr.Element, betas []fr.Element, pk QALinkProvingKey) (QALinkProof, error) {
	if err := validateQALinkWitnessShape(blocks, betas, pk.BlockCount, pk.BlockLen); err != nil {
		return QALinkProof{}, err
	}
	if len(pk.P) != pk.BlockCount*pk.BlockLen+1+pk.BlockCount {
		return QALinkProof{}, fmt.Errorf("qa-link proving key length mismatch")
	}

	scalars := make([]fr.Element, 0, len(pk.P))
	for i := range blocks {
		scalars = append(scalars, blocks[i]...)
	}
	scalars = append(scalars, alpha)
	scalars = append(scalars, betas...)

	var proof bls12381.G1Affine
	if _, err := proof.MultiExp(pk.P, scalars, ecc.MultiExpConfig{}); err != nil {
		return QALinkProof{}, err
	}

	return QALinkProof{Pi: proof}, nil
}

func ProveQABatchLink(
	blocks [][]fr.Element,
	alpha fr.Element,
	betas []fr.Element,
	pk QABatchLinkProvingKey,
	snarkCommit bls12381.G1Affine,
	externalCommits []bls12381.G1Affine,
	context ...fr.Element,
) (QABatchLinkProof, error) {
	if err := validateQALinkWitnessShape(blocks, betas, pk.BlockCount, pk.BlockLen); err != nil {
		return QABatchLinkProof{}, err
	}
	if len(externalCommits) != pk.BlockCount {
		return QABatchLinkProof{}, fmt.Errorf("external commitment count must match qa-batch-link setup")
	}
	if len(pk.SnarkG) != pk.BlockCount*pk.BlockLen || len(pk.ExternalG) != pk.BlockLen {
		return QABatchLinkProof{}, fmt.Errorf("qa-batch-link proving key length mismatch")
	}

	weights := deriveQABatchWeights(snarkCommit, externalCommits, pk.BlockCount, pk.BlockLen, context)

	snarkCommitKey := CommitKey{G: pk.SnarkG, H: pk.SnarkH}
	snarkPart := PedersenCommitBlinded(flattenBlocks(blocks), alpha, snarkCommitKey)

	aggBlock, aggBeta := aggregateQABatchWitness(blocks, betas, weights, pk.BlockLen)
	externalCommitKey := CommitKey{G: pk.ExternalG, H: pk.ExternalH}
	externalPart := PedersenCommitBlinded(aggBlock, aggBeta, externalCommitKey)

	var pi bls12381.G1Affine
	pi.Add(&snarkPart, &externalPart)
	return QABatchLinkProof{Pi: pi}, nil
}

func VerifyQALink(snarkCommit bls12381.G1Affine, externalCommits []bls12381.G1Affine, proof QALinkProof, vk QALinkVerifyingKey) bool {
	if len(externalCommits) != vk.BlockCount || len(vk.C) != vk.BlockCount+1 {
		return false
	}

	g1s := make([]bls12381.G1Affine, 0, vk.BlockCount+2)
	g2s := make([]bls12381.G2Affine, 0, vk.BlockCount+2)

	g1s = append(g1s, snarkCommit)
	g2s = append(g2s, vk.C[0])
	for i := range externalCommits {
		g1s = append(g1s, externalCommits[i])
		g2s = append(g2s, vk.C[i+1])
	}

	var negA bls12381.G2Affine
	negA.Neg(&vk.A)
	g1s = append(g1s, proof.Pi)
	g2s = append(g2s, negA)

	ok, err := bls12381.PairingCheck(g1s, g2s)
	return err == nil && ok
}

func VerifyQABatchLink(
	snarkCommit bls12381.G1Affine,
	externalCommits []bls12381.G1Affine,
	proof QABatchLinkProof,
	vk QABatchLinkVerifyingKey,
	context ...fr.Element,
) bool {
	if len(externalCommits) != vk.BlockCount || vk.BlockCount <= 0 || vk.BlockLen <= 0 {
		return false
	}

	weights := deriveQABatchWeights(snarkCommit, externalCommits, vk.BlockCount, vk.BlockLen, context)
	var aggregatedExternalCommit bls12381.G1Affine
	if _, err := aggregatedExternalCommit.MultiExp(externalCommits, weights, ecc.MultiExpConfig{}); err != nil {
		return false
	}

	var negA bls12381.G2Affine
	negA.Neg(&vk.A)
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{snarkCommit, aggregatedExternalCommit, proof.Pi},
		[]bls12381.G2Affine{vk.C0, vk.C1, negA},
	)
	return err == nil && ok
}

func QALinkProofSizeBytes(QALinkProof) int {
	return G1AffineSizeBytes
}

func QABatchLinkProofSizeBytes(QABatchLinkProof) int {
	return G1AffineSizeBytes
}

func validateQALinkWitnessShape(blocks [][]fr.Element, betas []fr.Element, blockCount, blockLen int) error {
	if blockCount <= 0 || blockLen <= 0 {
		return fmt.Errorf("qa-link requires positive block count and block length")
	}
	if len(blocks) != blockCount || len(betas) != blockCount {
		return fmt.Errorf("block and blinding counts must match qa-link setup")
	}
	for i := range blocks {
		if len(blocks[i]) != blockLen {
			return fmt.Errorf("block length must match qa-link setup")
		}
	}
	return nil
}

func deriveQABatchWeights(snarkCommit bls12381.G1Affine, externalCommits []bls12381.G1Affine, blockCount, blockLen int, context []fr.Element) []fr.Element {
	elements := make([]fr.Element, 0, 4+len(context)+1+len(externalCommits))
	var domain, countElement, lenElement fr.Element
	domain.SetUint64(0x51414241544348) // "QABATCH"
	countElement.SetUint64(uint64(blockCount))
	lenElement.SetUint64(uint64(blockLen))
	elements = append(elements, domain, countElement, lenElement)
	elements = append(elements, context...)
	elements = append(elements, HashPoint(snarkCommit))
	for i := range externalCommits {
		elements = append(elements, HashPoint(externalCommits[i]))
	}
	seed := HashElements(elements...)

	weights := make([]fr.Element, blockCount)
	for i := range weights {
		var idx fr.Element
		idx.SetUint64(uint64(i))
		weights[i] = HashElements(seed, idx)
		for retry := uint64(1); weights[i].IsZero(); retry++ {
			var retryElement fr.Element
			retryElement.SetUint64(retry)
			weights[i] = HashElements(seed, idx, retryElement)
		}
	}
	return weights
}

func aggregateQABatchWitness(blocks [][]fr.Element, betas []fr.Element, weights []fr.Element, blockLen int) ([]fr.Element, fr.Element) {
	aggBlock := make([]fr.Element, blockLen)
	var aggBeta fr.Element
	for i := range blocks {
		for j := 0; j < blockLen; j++ {
			var term fr.Element
			term.Mul(&weights[i], &blocks[i][j])
			aggBlock[j].Add(&aggBlock[j], &term)
		}

		var betaTerm fr.Element
		betaTerm.Mul(&weights[i], &betas[i])
		aggBeta.Add(&aggBeta, &betaTerm)
	}
	return aggBlock, aggBeta
}

func flattenBlocks(blocks [][]fr.Element) []fr.Element {
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

func scaleG1Points(points []bls12381.G1Affine, scalar big.Int) []bls12381.G1Affine {
	out := make([]bls12381.G1Affine, len(points))
	if len(points) == 0 {
		return out
	}

	numWorkers := runtime.NumCPU()
	chunkSize := (len(points) + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup
	for worker := 0; worker < numWorkers; worker++ {
		start := worker * chunkSize
		end := start + chunkSize
		if end > len(points) {
			end = len(points)
		}
		if start >= end {
			break
		}
		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				out[i].ScalarMultiplication(&points[i], &scalar)
			}
		}(start, end)
	}
	wg.Wait()
	return out
}

func elementBigInt(v fr.Element) big.Int {
	var out big.Int
	v.BigInt(&out)
	return out
}

func randomNonZeroElement() fr.Element {
	var out fr.Element
	for out.IsZero() {
		out.SetRandom()
	}
	return out
}
