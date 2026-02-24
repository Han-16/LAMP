package utils

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

func HashElements(elements ...fr.Element) fr.Element {
	h := mimc.NewMiMC()
	for _, e := range elements {
		b := e.Bytes()
		h.Write(b[:])
	}
	var res fr.Element
	res.SetBytes(h.Sum(nil))
	return res
}

func BuildMerkleTree(leaves []fr.Element, depth int) ([][]fr.Element, fr.Element) {
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

func VecMatMul(v []fr.Element, M [][]fr.Element, K int) []fr.Element {
	res := make([]fr.Element, K)
	for j := 0; j < K; j++ {
		var sum fr.Element
		for i := 0; i < K; i++ {
			var tmp fr.Element
			tmp.Mul(&v[i], &M[i][j])
			sum.Add(&sum, &tmp)
		}
		res[j] = sum
	}
	return res
}

func MatMul(A, B [][]fr.Element, K int) [][]fr.Element {
	C := make([][]fr.Element, K)
	for i := 0; i < K; i++ {
		C[i] = make([]fr.Element, K)
	}

	var wg sync.WaitGroup

	for i := 0; i < K; i++ {
		wg.Add(1)
		go func(row int) {
			defer wg.Done()
			for j := 0; j < K; j++ {
				var sum fr.Element
				for k := 0; k < K; k++ {
					var tmp fr.Element
					tmp.Mul(&A[row][k], &B[k][j])
					sum.Add(&sum, &tmp)
				}
				C[row][j] = sum
			}
		}(i)
	}

	wg.Wait()
	return C
}
