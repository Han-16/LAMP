package protocol

import (
	"fmt"
	"math/big"

	"github.com/Han-16/meow/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func GenerateRSEvaluationPoints(seed fr.Element, n int) (fr.Element, fr.Element, error) {
	if n <= 0 {
		return fr.Element{}, fr.Element{}, fmt.Errorf("domain size must be positive")
	}

	var labelX, labelYZ fr.Element
	labelX.SetUint64(1)
	labelYZ.SetUint64(2)

	x := generateRSEvaluationPoint(seed, labelX, n, nil)
	yz := generateRSEvaluationPoint(seed, labelYZ, n, &x)
	return x, yz, nil
}

func GenerateUniqueIndicesWithLabel(seed fr.Element, label uint64, n int, count int) ([]int, error) {
	if n <= 0 {
		return nil, fmt.Errorf("domain size must be positive")
	}
	if count > n {
		return nil, fmt.Errorf("cannot extract %d unique indices from a pool of %d", count, n)
	}

	var labelElement fr.Element
	labelElement.SetUint64(label)

	indices := make([]int, 0, count)
	selected := make(map[int]bool)
	currentSeed := crypto.HashElements(seed, labelElement)

	for len(indices) < count {
		currentSeed = crypto.HashElements(currentSeed, labelElement)
		var seedInt big.Int
		currentSeed.BigInt(&seedInt)

		idx := int(seedInt.Uint64() % uint64(n))
		if !selected[idx] {
			selected[idx] = true
			indices = append(indices, idx)
		}
	}
	return indices, nil
}

func GenerateRSEvaluationPointWithLabel(seed fr.Element, label uint64, n int, exclude *fr.Element) (fr.Element, error) {
	if n <= 0 {
		return fr.Element{}, fmt.Errorf("domain size must be positive")
	}

	var labelElement fr.Element
	labelElement.SetUint64(label)
	return generateRSEvaluationPoint(seed, labelElement, n, exclude), nil
}

func generateRSEvaluationPoint(seed, label fr.Element, n int, exclude *fr.Element) fr.Element {
	point := crypto.HashElements(seed, label)
	for {
		if (exclude == nil || !point.Equal(exclude)) && isOutsideRadix2Domain(point, n) {
			return point
		}
		point = crypto.HashElements(point, label)
	}
}

func isOutsideRadix2Domain(point fr.Element, n int) bool {
	var powered fr.Element
	powered.Exp(point, big.NewInt(int64(n)))

	var one fr.Element
	one.SetOne()
	return !powered.Equal(&one)
}
