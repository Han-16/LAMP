package crypto

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func HashElements(elements ...fr.Element) fr.Element {
	h := sha256.New()
	for _, e := range elements {
		b := e.Bytes()
		h.Write(b[:])
	}
	var res fr.Element
	res.SetBytes(h.Sum(nil))
	return res
}

func HashElementsMiMC(elements ...fr.Element) fr.Element {
	h := mimc.NewMiMC()
	for _, e := range elements {
		b := e.Bytes()
		h.Write(b[:])
	}
	var res fr.Element
	res.SetBytes(h.Sum(nil))
	return res
}

// HashPoint hashes the canonical compressed point for external transcripts.
func HashPoint(p bn254.G1Affine) fr.Element {
	encoded := p.Bytes()
	digest := sha256.Sum256(encoded[:])
	var result fr.Element
	result.SetBytes(digest[:])
	return result
}

func GenerateIndices(seed fr.Element, N int, L int) ([]int, error) {
	if N <= 0 {
		return nil, fmt.Errorf("domain size must be positive")
	}
	if L < 0 {
		return nil, fmt.Errorf("query count must be non-negative")
	}

	indices := make([]int, L)
	currentSeed := seed

	for i := range indices {
		currentSeed = HashElements(currentSeed)
		var seedInt big.Int
		currentSeed.BigInt(&seedInt)
		indices[i] = int(seedInt.Uint64() % uint64(N))
	}
	return indices, nil
}

func hashG2Point(p bn254.G2Affine) fr.Element {
	encoded := p.Bytes()
	digest := sha256.Sum256(encoded[:])
	var result fr.Element
	result.SetBytes(digest[:])
	return result
}
