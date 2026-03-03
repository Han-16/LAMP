package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

func VerifyColumnMerkleProof(
	api frontend.API,
	h mimc.MiMC,
	column []frontend.Variable,
	root frontend.Variable,
	merkle_proof []frontend.Variable,
	index frontend.Variable,
) error {
	depth := len(merkle_proof)

	h.Reset()
	h.Write(column...)
	h.Sum()
	leaf := h.Sum()

	proofIndices := api.ToBinary(index, depth)

	hashed := leaf
	for j := 0; j < depth; j++ {
		element := merkle_proof[j]
		bit := proofIndices[j]

		d1 := api.Select(bit, element, hashed)
		d2 := api.Select(bit, hashed, element)

		h.Reset()
		h.Write(d1, d2)
		hashed = h.Sum()
	}

	api.AssertIsEqual(hashed, root)
	return nil
}

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

// VerifyRSEncoding verifies if a single codeword is a valid Reed-Solomon encoding of the given message coefficients.
func VerifyRSEncoding(
	api frontend.API,
	k, n int,
	domainN []fr.Element,
	weightsN []fr.Element,
	messageCoeffs []frontend.Variable,
	codewordValues []frontend.Variable,
	z frontend.Variable,
) {
	// Step 1: Evaluate f(z)
	// Compute v1 = f(z) = \sum_{i=0}^{k-1} a_i z^i using Horner's method
	v1 := messageCoeffs[k-1]
	for i := k - 2; i >= 0; i-- {
		// v1 = v1 * z + a_i
		v1 = api.Add(api.Mul(v1, z), messageCoeffs[i])
	}

	// Step 2: Evaluate g(z) via Barycentric Formula (Rational Form)
	numeratorSum := frontend.Variable(0)   // 분자 합계 누적
	denominatorSum := frontend.Variable(0) // 분모 합계 누적

	for i := 0; i < n; i++ {
		// z - w^i
		zMinusW := api.Sub(z, domainN[i])
		// 1 / (z - w^i)
		invZMinusW := api.Inverse(zMinusW)

		// \lambda_i / (z - w^i)
		term := api.Mul(weightsN[i], invZMinusW)

		// 분모에 누적
		denominatorSum = api.Add(denominatorSum, term)

		// 분자에 누적: (\lambda_i / (z - w^i)) * c_i
		numTerm := api.Mul(term, codewordValues[i])
		numeratorSum = api.Add(numeratorSum, numTerm)
	}

	// Step 3: Decision
	// if v1 == v2 then Accept
	lhs := api.Mul(v1, denominatorSum)
	api.AssertIsEqual(lhs, numeratorSum)
}
