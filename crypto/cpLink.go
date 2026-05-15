package crypto

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type AmComEqProof struct {
	R    bn254.G1Affine
	RHat []bn254.G1Affine
	Z    [][]fr.Element
	T    fr.Element
	THat []fr.Element
}

func ProveAmComEq(
	blocks [][]fr.Element,
	alpha fr.Element,
	betas []fr.Element,
	snarkCK CommitKey,
	externalCK CommitKey,
	snarkCommit bn254.G1Affine,
	externalCommits []bn254.G1Affine,
) (AmComEqProof, error) {
	if len(blocks) == 0 {
		return AmComEqProof{}, fmt.Errorf("am-com-eq requires at least one block")
	}
	if len(blocks) != len(betas) || len(blocks) != len(externalCommits) {
		return AmComEqProof{}, fmt.Errorf("block, blinding, and commitment counts must match")
	}
	blockLen := len(blocks[0])
	if blockLen != len(externalCK.G) {
		return AmComEqProof{}, fmt.Errorf("block length must match external commitment key")
	}
	for i := range blocks {
		if len(blocks[i]) != blockLen {
			return AmComEqProof{}, fmt.Errorf("all blocks must have the same length")
		}
	}
	if len(snarkCK.G) != len(blocks)*blockLen {
		return AmComEqProof{}, fmt.Errorf("snark commitment key length must match flattened blocks")
	}

	randomBlocks := make([][]fr.Element, len(blocks))
	flatRandom := make([]fr.Element, 0, len(snarkCK.G))
	for i := range randomBlocks {
		randomBlocks[i] = make([]fr.Element, blockLen)
		for j := range randomBlocks[i] {
			randomBlocks[i][j].SetRandom()
		}
		flatRandom = append(flatRandom, randomBlocks[i]...)
	}

	var sAlpha fr.Element
	sAlpha.SetRandom()
	r := PedersenCommitBlinded(flatRandom, sAlpha, snarkCK)

	rHat := make([]bn254.G1Affine, len(blocks))
	sBeta := make([]fr.Element, len(blocks))
	for i := range blocks {
		sBeta[i].SetRandom()
		rHat[i] = PedersenCommitBlinded(randomBlocks[i], sBeta[i], externalCK)
	}

	challenge := computeAmComEqChallenge(snarkCommit, externalCommits, r, rHat)

	z := make([][]fr.Element, len(blocks))
	for i := range blocks {
		z[i] = make([]fr.Element, blockLen)
		for j := range blocks[i] {
			var term fr.Element
			term.Mul(&challenge, &blocks[i][j])
			z[i][j].Add(&randomBlocks[i][j], &term)
		}
	}

	var challengeAlpha fr.Element
	challengeAlpha.Mul(&challenge, &alpha)

	var t fr.Element
	t.Add(&sAlpha, &challengeAlpha)

	tHat := make([]fr.Element, len(blocks))
	for i := range blocks {
		var challengeBeta fr.Element
		challengeBeta.Mul(&challenge, &betas[i])
		tHat[i].Add(&sBeta[i], &challengeBeta)
	}

	return AmComEqProof{
		R:    r,
		RHat: rHat,
		Z:    z,
		T:    t,
		THat: tHat,
	}, nil
}

func VerifyAmComEq(
	snarkCommit bn254.G1Affine,
	externalCommits []bn254.G1Affine,
	proof AmComEqProof,
	snarkCK CommitKey,
	externalCK CommitKey,
) bool {
	if len(proof.Z) == 0 || len(proof.Z) != len(externalCommits) || len(proof.Z) != len(proof.RHat) || len(proof.Z) != len(proof.THat) {
		return false
	}
	blockLen := len(proof.Z[0])
	if blockLen != len(externalCK.G) || len(snarkCK.G) != len(proof.Z)*blockLen {
		return false
	}
	for i := range proof.Z {
		if len(proof.Z[i]) != blockLen {
			return false
		}
	}

	challenge := computeAmComEqChallenge(snarkCommit, externalCommits, proof.R, proof.RHat)

	flatZ := flattenBlocks(proof.Z)
	lhs := PedersenCommitBlinded(flatZ, proof.T, snarkCK)
	rhs := addScaledPoint(proof.R, snarkCommit, challenge)
	if !lhs.Equal(&rhs) {
		return false
	}

	for i := range proof.Z {
		lhsHat := PedersenCommitBlinded(proof.Z[i], proof.THat[i], externalCK)
		rhsHat := addScaledPoint(proof.RHat[i], externalCommits[i], challenge)
		if !lhsHat.Equal(&rhsHat) {
			return false
		}
	}

	return true
}

func AmComEqProofSizeBytes(proof AmComEqProof) int {
	size := 64 + 32
	size += len(proof.RHat) * 64
	size += len(proof.THat) * 32
	for i := range proof.Z {
		size += len(proof.Z[i]) * 32
	}
	return size
}

func computeAmComEqChallenge(C bn254.G1Affine, cHat []bn254.G1Affine, R bn254.G1Affine, rHat []bn254.G1Affine) fr.Element {
	elements := make([]fr.Element, 0, 2+len(cHat)+len(rHat))
	elements = append(elements, HashPoint(C))
	for i := range cHat {
		elements = append(elements, HashPoint(cHat[i]))
	}
	elements = append(elements, HashPoint(R))
	for i := range rHat {
		elements = append(elements, HashPoint(rHat[i]))
	}
	return HashElements(elements...)
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

func addScaledPoint(base, point bn254.G1Affine, scalar fr.Element) bn254.G1Affine {
	var scalarBigInt big.Int
	scalar.BigInt(&scalarBigInt)

	var scaled bn254.G1Affine
	scaled.ScalarMultiplication(&point, &scalarBigInt)

	var out bn254.G1Affine
	out.Add(&base, &scaled)
	return out
}
