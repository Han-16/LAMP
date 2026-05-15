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
