package crypto

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"golang.org/x/crypto/sha3"
)

func HashElements(elements ...fr.Element) fr.Element {
	h := sha3.NewLegacyKeccak256()
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

func FpToFr(fpElem fp.Element) fr.Element {
	var frElem fr.Element
	b := fpElem.Bytes()
	frElem.SetBytes(b[:])
	return frElem
}

func HashPoint(p bn254.G1Affine) fr.Element {
	xFr := FpToFr(p.X)
	yFr := FpToFr(p.Y)
	return HashElements(xFr, yFr)
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
