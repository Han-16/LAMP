package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

func VerifyColumnMerkleProof(
	api frontend.API,
	h mimc.MiMC,
	root frontend.Variable,
	column []frontend.Variable,
	merkleIndex frontend.Variable,
	merkleProofs []frontend.Variable,
) {
	// leaf = H(column...)
	h.Reset()
	h.Write(column...)
	leafHash := h.Sum()

	depth := len(merkleProofs)
	indexBits := api.ToBinary(merkleIndex, depth)

	hashed := leafHash
	for i := 0; i < depth; i++ {
		sibling := merkleProofs[i]
		bit := indexBits[i] // 0 => left, 1 => right

		// If bit==0: (hashed, sibling), else: (sibling, hashed)
		left := api.Select(bit, sibling, hashed)
		right := api.Select(bit, hashed, sibling)

		h.Reset()
		h.Write(left, right)
		hashed = h.Sum()
	}

	api.AssertIsEqual(hashed, root)
}

func DynamicSelect(api frontend.API, array []frontend.Variable, indexBits []frontend.Variable) frontend.Variable {
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
