package crypto

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

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

func BuildMerkleTreeFromFieldElements(leaves []fr.Element, depth int) ([][]fr.Element, fr.Element) {
	return buildBaseMerkleTree(leaves, depth)
}

func BuildMerkleTreeFromGroupElements(leaves []bn254.G1Affine, depth int) ([][]fr.Element, fr.Element) {
	frLeaves := make([]fr.Element, len(leaves))
	for i, leaf := range leaves {
		frLeaves[i] = HashPoint(leaf)
	}
	return buildBaseMerkleTree(frLeaves, depth)
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

func CommitMatrix(columns [][]fr.Element, ck CommitKey, depth int) ([][]fr.Element, fr.Element, []bn254.G1Affine, []fr.Element) {
	l := len(columns)
	commitments := make([]bn254.G1Affine, l)
	blindings := make([]fr.Element, l)

	var wg sync.WaitGroup
	for i := 0; i < l; i++ {
		blindings[i].SetRandom()

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			commitments[idx] = PedersenCommitBlinded(columns[idx], blindings[idx], ck)
		}(i)
	}
	wg.Wait()

	tree, root := BuildMerkleTreeFromGroupElements(commitments, depth)

	return tree, root, commitments, blindings
}
