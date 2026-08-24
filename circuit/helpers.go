package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
)

func SelectTargetIndex(api frontend.API, array []frontend.Variable, indexBits []frontend.Variable) frontend.Variable {
	currentLayer := array

	for d := 0; d < len(indexBits); d++ {
		nextLayer := make([]frontend.Variable, 0, (len(currentLayer)+1)/2)

		for j := 0; j < len(currentLayer); j += 2 {
			left := currentLayer[j]

			right := currentLayer[j]
			if j+1 < len(currentLayer) {
				right = currentLayer[j+1]
			}

			// bit=0 => left, bit=1 => right
			selected := api.Select(indexBits[d], right, left)
			nextLayer = append(nextLayer, selected)
		}
		currentLayer = nextLayer
	}

	return currentLayer[0]
}

func Fold(api frontend.API, lhs, rhs []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	for j := 0; j < len(lhs); j++ {
		acc = api.Add(acc, api.Mul(lhs[j], rhs[j]))
	}
	return acc
}

func Powers(api frontend.API, r frontend.Variable, length int) []frontend.Variable {
	powers := make([]frontend.Variable, length)
	cur := frontend.Variable(1)
	for i := 0; i < length; i++ {
		powers[i] = cur
		cur = api.Mul(cur, r)
	}
	return powers
}

func FlattenRows(matrices ...[][]frontend.Variable) []frontend.Variable {
	total := 0
	for _, matrix := range matrices {
		for _, row := range matrix {
			total += len(row)
		}
	}

	out := make([]frontend.Variable, 0, total)
	for _, matrix := range matrices {
		for _, row := range matrix {
			out = append(out, row...)
		}
	}
	return out
}

func AppendVariables(slices ...[]frontend.Variable) []frontend.Variable {
	total := 0
	for _, slice := range slices {
		total += len(slice)
	}

	out := make([]frontend.Variable, 0, total)
	for _, slice := range slices {
		out = append(out, slice...)
	}
	return out
}

func VerifyRSEncoding(
	api frontend.API,
	k, n int,
	domainK, weightsK []fr.Element,
	domainN, weightsN []fr.Element,
	vecValues []frontend.Variable,
	encValues []frontend.Variable,
	z frontend.Variable,
) {
	// Step 1: Calculate g(z) using Barycentric formula on K domain
	numK := frontend.Variable(0) // numerator for K domain
	denK := frontend.Variable(0) // denominator for K domain

	for i := 0; i < k; i++ {
		zMinusW := api.Sub(z, domainK[i])
		invZMinusW := api.Inverse(zMinusW)

		term := api.Mul(weightsK[i], invZMinusW) // \lambda_{K,i} / (z - w_K^i)
		denK = api.Add(denK, term)

		numTerm := api.Mul(term, vecValues[i])
		numK = api.Add(numK, numTerm)
	}

	// Step 2: Calculate g(z) using Barycentric formula on N domain
	numN := frontend.Variable(0)
	denN := frontend.Variable(0)

	for i := 0; i < n; i++ {
		zMinusW := api.Sub(z, domainN[i])
		invZMinusW := api.Inverse(zMinusW)

		term := api.Mul(weightsN[i], invZMinusW) // \lambda_{N,i} / (z - w_N^i)
		denN = api.Add(denN, term)

		numTerm := api.Mul(term, encValues[i])
		numN = api.Add(numN, numTerm)
	}

	// Step 3: Decision
	// Check (numK / denK) == (numN / denN)
	// => numK * denN == numN * denK
	lhs := api.Mul(numK, denN)
	rhs := api.Mul(numN, denK)

	api.AssertIsEqual(lhs, rhs)
}
