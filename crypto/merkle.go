package crypto

import (
	"sort"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const MerkleHashSizeBytes = 32

type MerkleLeafMeta struct {
	GroupID uint64
	ItemID  uint64
	Index   uint64
}

type MerkleMultiProof struct {
	Siblings []fr.Element
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

func GetMerkleMultiProof(tree [][]fr.Element, indices []int, depth int) MerkleMultiProof {
	current := uniqueSortedIndices(indices)
	siblings := make([]fr.Element, 0)

	for level := 0; level < depth; level++ {
		known := make(map[int]struct{}, len(current))
		for _, idx := range current {
			known[idx] = struct{}{}
		}

		nextMap := make(map[int]struct{}, len(current))
		for _, idx := range current {
			siblingIdx := idx ^ 1
			if _, ok := known[siblingIdx]; !ok {
				siblings = append(siblings, tree[level][siblingIdx])
			}
			nextMap[idx/2] = struct{}{}
		}
		current = sortedKeys(nextMap)
	}

	return MerkleMultiProof{Siblings: siblings}
}

func VerifyMerkleMultiProof(root fr.Element, leafHashes []fr.Element, indices []int, proof MerkleMultiProof, depth int) bool {
	if len(leafHashes) != len(indices) || len(leafHashes) == 0 {
		return false
	}

	current := make(map[int]fr.Element, len(indices))
	leafCount := 1 << depth
	for i, idx := range indices {
		if idx < 0 || idx >= leafCount {
			return false
		}
		if existing, ok := current[idx]; ok {
			if !existing.Equal(&leafHashes[i]) {
				return false
			}
			continue
		}
		current[idx] = leafHashes[i]
	}

	proofPos := 0
	for level := 0; level < depth; level++ {
		keys := sortedKeysFromHashes(current)
		next := make(map[int]fr.Element, len(keys))
		processed := make(map[int]struct{}, len(keys))

		for _, idx := range keys {
			if _, ok := processed[idx]; ok {
				continue
			}

			currHash := current[idx]
			siblingIdx := idx ^ 1
			var siblingHash fr.Element
			if knownSibling, ok := current[siblingIdx]; ok {
				siblingHash = knownSibling
				processed[siblingIdx] = struct{}{}
			} else {
				if proofPos >= len(proof.Siblings) {
					return false
				}
				siblingHash = proof.Siblings[proofPos]
				proofPos++
			}
			processed[idx] = struct{}{}

			var parent fr.Element
			if idx%2 == 0 {
				parent = HashElements(currHash, siblingHash)
			} else {
				parent = HashElements(siblingHash, currHash)
			}

			parentIdx := idx / 2
			if existing, ok := next[parentIdx]; ok {
				if !existing.Equal(&parent) {
					return false
				}
			} else {
				next[parentIdx] = parent
			}
		}
		current = next
	}

	if proofPos != len(proof.Siblings) || len(current) != 1 {
		return false
	}
	computedRoot, ok := current[0]
	return ok && computedRoot.Equal(&root)
}

func MerkleMultiProofSizeBytes(proof MerkleMultiProof) int {
	return len(proof.Siblings) * MerkleHashSizeBytes
}

func uniqueSortedIndices(indices []int) []int {
	if len(indices) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		seen[idx] = struct{}{}
	}
	return sortedKeys(seen)
}

func sortedKeys(values map[int]struct{}) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func sortedKeysFromHashes(values map[int]fr.Element) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
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
