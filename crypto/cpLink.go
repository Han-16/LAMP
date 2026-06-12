package crypto

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type QALinkProvingKey struct {
	P          []bn254.G1Affine
	BlockCount int
	BlockLen   int
}

type QALinkVerifyingKey struct {
	C          []bn254.G2Affine
	A          bn254.G2Affine
	BlockCount int
	BlockLen   int
}

type QALinkProof struct {
	Pi bn254.G1Affine
}

type QALinkVerification struct {
	SnarkCommit     bn254.G1Affine
	ExternalCommits []bn254.G1Affine
	Proof           QALinkProof
	VK              QALinkVerifyingKey
}

const G1AffineSizeBytes = 64

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

	p := make([]bn254.G1Affine, blockCount*blockLen+1+blockCount)
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
				var point bn254.G1Jac
				point.JointScalarMultiplication(&snarkCK.G[flatIndex], &externalCK.G[offset], &k0, &kBig[block])
				p[flatIndex].FromJacobian(&point)
			}
		}(start, end)
	}
	wg.Wait()

	var alphaPoint bn254.G1Affine
	alphaPoint.ScalarMultiplication(&snarkCK.H, &k0)
	p[totalValues] = alphaPoint

	for block := 0; block < blockCount; block++ {
		var betaPoint bn254.G1Affine
		betaPoint.ScalarMultiplication(&externalCK.H, &kBig[block])
		p[totalValues+1+block] = betaPoint
	}

	aTrapdoor := make([]fr.Element, len(trapdoor))
	for i := range trapdoor {
		aTrapdoor[i].Mul(&a, &trapdoor[i])
	}
	_, _, _, g2 := bn254.Generators()
	c := bn254.BatchScalarMultiplicationG2(&g2, aTrapdoor)
	var aBig big.Int
	a.BigInt(&aBig)
	var aG2 bn254.G2Affine
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

	var proof bn254.G1Affine
	if _, err := proof.MultiExp(pk.P, scalars, ecc.MultiExpConfig{}); err != nil {
		return QALinkProof{}, err
	}

	return QALinkProof{Pi: proof}, nil
}

func VerifyQALink(snarkCommit bn254.G1Affine, externalCommits []bn254.G1Affine, proof QALinkProof, vk QALinkVerifyingKey) bool {
	if len(externalCommits) != vk.BlockCount || len(vk.C) != vk.BlockCount+1 {
		return false
	}

	g1s := make([]bn254.G1Affine, 0, vk.BlockCount+2)
	g2s := make([]bn254.G2Affine, 0, vk.BlockCount+2)

	g1s = append(g1s, snarkCommit)
	g2s = append(g2s, vk.C[0])
	for i := range externalCommits {
		g1s = append(g1s, externalCommits[i])
		g2s = append(g2s, vk.C[i+1])
	}

	var negA bn254.G2Affine
	negA.Neg(&vk.A)
	g1s = append(g1s, proof.Pi)
	g2s = append(g2s, negA)

	ok, err := bn254.PairingCheck(g1s, g2s)
	return err == nil && ok
}

func VerifyQALinksBatched(verifications []QALinkVerification, context ...fr.Element) bool {
	if len(verifications) == 0 {
		return false
	}

	totalTerms := 0
	for i := range verifications {
		if !validateQALinkVerification(verifications[i]) {
			return false
		}
		totalTerms += verifications[i].VK.BlockCount + 2
	}

	weights := deriveQALinkBatchWeights(verifications, context)
	g1s := make([]bn254.G1Affine, 0, totalTerms)
	g2s := make([]bn254.G2Affine, 0, totalTerms)

	for i, verification := range verifications {
		weightBig := elementBigInt(weights[i])
		appendWeightedPairingTerm := func(point bn254.G1Affine, target bn254.G2Affine) {
			var weightedPoint bn254.G1Affine
			weightedPoint.ScalarMultiplication(&point, &weightBig)
			g1s = append(g1s, weightedPoint)
			g2s = append(g2s, target)
		}

		appendWeightedPairingTerm(verification.SnarkCommit, verification.VK.C[0])
		for j := range verification.ExternalCommits {
			appendWeightedPairingTerm(verification.ExternalCommits[j], verification.VK.C[j+1])
		}

		var negA bn254.G2Affine
		negA.Neg(&verification.VK.A)
		appendWeightedPairingTerm(verification.Proof.Pi, negA)
	}

	ok, err := bn254.PairingCheck(g1s, g2s)
	return err == nil && ok
}

func QALinkProofSizeBytes(QALinkProof) int {
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

func validateQALinkVerification(v QALinkVerification) bool {
	return v.VK.BlockCount > 0 &&
		v.VK.BlockLen > 0 &&
		len(v.ExternalCommits) == v.VK.BlockCount &&
		len(v.VK.C) == v.VK.BlockCount+1
}

func deriveQALinkBatchWeights(verifications []QALinkVerification, context []fr.Element) []fr.Element {
	elements := make([]fr.Element, 0, 2+len(context)+len(verifications)*8)
	elements = append(elements, fieldElementFromUint64(0x51414c494e4b4241)) // "QALINKBA"
	elements = append(elements, fieldElementFromUint64(uint64(len(verifications))))
	elements = append(elements, context...)
	for i, verification := range verifications {
		elements = append(elements,
			fieldElementFromUint64(uint64(i)),
			fieldElementFromUint64(uint64(verification.VK.BlockCount)),
			fieldElementFromUint64(uint64(verification.VK.BlockLen)),
			HashPoint(verification.SnarkCommit),
			HashPoint(verification.Proof.Pi),
			hashG2Point(verification.VK.A),
		)
		for j := range verification.VK.C {
			elements = append(elements, fieldElementFromUint64(uint64(j)), hashG2Point(verification.VK.C[j]))
		}
		for j := range verification.ExternalCommits {
			elements = append(elements, fieldElementFromUint64(uint64(j)), HashPoint(verification.ExternalCommits[j]))
		}
	}
	seed := HashElements(elements...)

	weights := make([]fr.Element, len(verifications))
	for i := range weights {
		idx := fieldElementFromUint64(uint64(i))
		weights[i] = HashElements(seed, idx)
		for retry := uint64(1); weights[i].IsZero(); retry++ {
			weights[i] = HashElements(seed, idx, fieldElementFromUint64(retry))
		}
	}
	return weights
}

func hashG2Point(p bn254.G2Affine) fr.Element {
	return HashElements(
		FpToFr(p.X.A0),
		FpToFr(p.X.A1),
		FpToFr(p.Y.A0),
		FpToFr(p.Y.A1),
	)
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

func elementBigInt(v fr.Element) big.Int {
	var out big.Int
	v.BigInt(&out)
	return out
}

func fieldElementFromUint64(value uint64) fr.Element {
	var out fr.Element
	out.SetUint64(value)
	return out
}

func randomNonZeroElement() fr.Element {
	var out fr.Element
	for out.IsZero() {
		out.SetRandom()
	}
	return out
}
