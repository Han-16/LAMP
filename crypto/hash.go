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

func GenerateChallengeVector(seed fr.Element, size int) []fr.Element {
	r := make([]fr.Element, size)
	currentSeed := seed
	for i := 0; i < size; i++ {
		r[i] = HashElements(currentSeed)
		currentSeed = r[i]
	}
	return r
}

func GenerateUniqueIndices(seed fr.Element, N int, L int) ([]int, error) {
	if L > N {
		return nil, fmt.Errorf("cannot extract %d unique indices from a pool of %d", L, N)
	}

	indices := make([]int, 0, L)
	selected := make(map[int]bool)
	currentSeed := seed

	for len(indices) < L {
		currentSeed = HashElements(currentSeed)
		var seedInt big.Int
		currentSeed.BigInt(&seedInt)

		idx := int(seedInt.Uint64() % uint64(N))

		if !selected[idx] {
			selected[idx] = true
			indices = append(indices, idx)
		}
	}
	return indices, nil
}
