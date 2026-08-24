package crypto

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
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

func HashPoint(p bls12381.G1Affine) fr.Element {
	h := sha3.NewLegacyKeccak256()
	h.Write(p.Marshal())
	var res fr.Element
	res.SetBytes(h.Sum(nil))
	return res
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
