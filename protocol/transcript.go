package protocol

import (
	"fmt"
	"math/big"

	"example.com/lamp/crypto"
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

func GenerateIndicesWithLabel(seed fr.Element, label uint64, n int, count int) ([]int, error) {
	if n <= 0 {
		return nil, fmt.Errorf("domain size must be positive")
	}
	if count < 0 {
		return nil, fmt.Errorf("query count must be non-negative")
	}

	var labelElement fr.Element
	labelElement.SetUint64(label)

	indices := make([]int, count)
	currentSeed := crypto.HashElements(seed, labelElement)

	for i := range indices {
		currentSeed = crypto.HashElements(currentSeed, labelElement)
		var seedInt big.Int
		currentSeed.BigInt(&seedInt)
		indices[i] = int(seedInt.Uint64() % uint64(n))
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
