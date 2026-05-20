package crypto

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type MerkleLeafMeta struct {
	GroupID uint64
	ItemID  uint64
	Index   uint64
}

func buildBaseMerkleTree(leaves []fr.Element, depth int) ([][]fr.Element, fr.Element) {
	tree := make([][]fr.Element, depth+1)
	tree[0] = leaves
	for level := 0; level < depth; level++ {
		numNodes := len(tree[level]) / 2
		tree[level+1] = make([]fr.Element, numNodes)
		for i := 0; i < numNodes; i++ {
			tree[level+1][i] = HashElements(tree[level][2*i], tree[level][2*i+1])
		}
	}
	return tree, tree[depth][0]
}

func BuildMerkleTreeFromGroupElements(leaves []bn254.G1Affine, depth int) ([][]fr.Element, fr.Element) {
	frLeaves := make([]fr.Element, len(leaves))
	for i, leaf := range leaves {
		frLeaves[i] = HashPoint(leaf)
	}
	return buildBaseMerkleTree(frLeaves, depth)
}

func HashPointWithMeta(point bn254.G1Affine, meta MerkleLeafMeta) fr.Element {
	var groupID, itemID, index fr.Element
	groupID.SetUint64(meta.GroupID)
	itemID.SetUint64(meta.ItemID)
	index.SetUint64(meta.Index)
	return HashElements(groupID, itemID, index, HashPoint(point))
}

func BuildMerkleTreeFromGroupElementsWithMeta(leaves []bn254.G1Affine, metas []MerkleLeafMeta) ([][]fr.Element, fr.Element, int) {
	if len(leaves) != len(metas) {
		panic("leaf and metadata counts must match")
	}

	paddedLen := nextPowerOfTwo(len(leaves))
	depth := log2(paddedLen)
	frLeaves := make([]fr.Element, paddedLen)
	for i, leaf := range leaves {
		frLeaves[i] = HashPointWithMeta(leaf, metas[i])
	}
	for i := len(leaves); i < paddedLen; i++ {
		var pad fr.Element
		pad.SetUint64(uint64(i))
		frLeaves[i] = HashElements(pad)
	}

	tree, root := buildBaseMerkleTree(frLeaves, depth)
	return tree, root, depth
}

func GetMerkleProof(tree [][]fr.Element, idx, depth int) []fr.Element {
	proof := make([]fr.Element, depth)
	currIdx := idx
	for level := 0; level < depth; level++ {
		siblingIdx := currIdx ^ 1
		proof[level] = tree[level][siblingIdx]
		currIdx /= 2
	}
	return proof
}

func nextPowerOfTwo(v int) int {
	if v <= 1 {
		return 1
	}
	out := 1
	for out < v {
		out <<= 1
	}
	return out
}

func log2(v int) int {
	out := 0
	for v > 1 {
		v >>= 1
		out++
	}
	return out
}
