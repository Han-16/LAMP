package matrix

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

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

func VecMatMulRect(v []fr.Element, M [][]fr.Element, rows, cols int) []fr.Element {
	res := make([]fr.Element, cols)
	for j := 0; j < cols; j++ {
		var sum fr.Element
		for i := 0; i < rows; i++ {
			var tmp fr.Element
			tmp.Mul(&v[i], &M[i][j])
			sum.Add(&sum, &tmp)
		}
		res[j] = sum
	}
	return res
}

func Powers(r fr.Element, K int) []fr.Element {
	res := make([]fr.Element, K)
	var current fr.Element
	current.SetOne()
	for i := 0; i < K; i++ {
		res[i] = current
		current.Mul(&current, &r)
	}
	return res
}

func MatMul(A, B [][]fr.Element, K int) [][]fr.Element {
	C := make([][]fr.Element, K)
	for i := 0; i < K; i++ {
		C[i] = make([]fr.Element, K)
	}

	BT := make([][]fr.Element, K)
	for i := 0; i < K; i++ {
		BT[i] = make([]fr.Element, K)
		for j := 0; j < K; j++ {
			BT[i][j] = B[j][i]
		}
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
					tmp.Mul(&A[row][k], &BT[j][k])
					sum.Add(&sum, &tmp)
				}
				C[row][j] = sum
			}
		}(i)
	}
	wg.Wait()
	return C
}

func MatMulRect(A, B [][]fr.Element, rows, inner, cols int) [][]fr.Element {
	C := make([][]fr.Element, rows)
	for i := 0; i < rows; i++ {
		C[i] = make([]fr.Element, cols)
	}

	BT := Transpose(B, inner, cols)

	var wg sync.WaitGroup
	for i := 0; i < rows; i++ {
		wg.Add(1)
		go func(row int) {
			defer wg.Done()
			for j := 0; j < cols; j++ {
				var sum fr.Element
				for k := 0; k < inner; k++ {
					var tmp fr.Element
					tmp.Mul(&A[row][k], &BT[j][k])
					sum.Add(&sum, &tmp)
				}
				C[row][j] = sum
			}
		}(i)
	}
	wg.Wait()
	return C
}

func GenerateRandomMatrix(rows, cols int) [][]fr.Element {
	M := make([][]fr.Element, rows)
	for i := 0; i < rows; i++ {
		M[i] = make([]fr.Element, cols)
		for j := 0; j < cols; j++ {
			M[i][j].SetRandom()
		}
	}
	return M
}

func GenerateRandomVector(size int) []fr.Element {
	V := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		V[i].SetRandom()
	}
	return V
}

func Transpose(M [][]fr.Element, rows, cols int) [][]fr.Element {
	T := make([][]fr.Element, cols)
	for i := 0; i < cols; i++ {
		T[i] = make([]fr.Element, rows)
		for j := 0; j < rows; j++ {
			T[i][j] = M[j][i]
		}
	}
	return T
}
