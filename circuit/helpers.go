package circuit

import (
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
