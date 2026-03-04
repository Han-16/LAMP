package utils

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// buildBaseMerkleTree is an internal function that takes a slice of fr.Elements and constructs the actual Merkle tree.
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

// 1. Construct Merkle tree based on field elements
// Input: fr.Element vector of length l
func BuildMerkleTreeFromFieldElements(leaves []fr.Element, depth int) ([][]fr.Element, fr.Element) {
	return buildBaseMerkleTree(leaves, depth)
}

// 2. Construct Merkle tree based on group elements
// Input: bn254.G1Affine vector of length l
// Operation: Hashes each group element to convert it into a field element, then constructs the tree.
func BuildMerkleTreeFromGroupElements(leaves []bn254.G1Affine, depth int) ([][]fr.Element, fr.Element) {
	frLeaves := make([]fr.Element, len(leaves))
	for i, leaf := range leaves {
		frLeaves[i] = HashPoint(leaf)
	}
	return buildBaseMerkleTree(frLeaves, depth)
}

// GetMerkleProof generates a Merkle proof for a specific index.
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

// It performs Pedersen commitments on the columns of the matrix and builds a Merkle tree with the results (a vector of group elements).
func CommitMatrix(columns [][]fr.Element, ck CommitKey, depth int) ([][]fr.Element, fr.Element, []bn254.G1Affine) {
	l := len(columns)
	commitments := make([]bn254.G1Affine, l)

	var wg sync.WaitGroup
	for i := 0; i < l; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			commitments[idx] = PedersenCommit(columns[idx], ck)
		}(i)
	}
	wg.Wait()

	tree, root := BuildMerkleTreeFromGroupElements(commitments, depth)

	return tree, root, commitments
}

// GenerateUniqueIndices generates L unique random indices in the range [0, N-1] using a seed.
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
