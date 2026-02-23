package utils

import (
	"crypto/rand"
	"math/big"
)

func MakeMatrix(rows, cols int, q *big.Int) [][]*big.Int {
	mat := make([][]*big.Int, rows)
	for i := 0; i < rows; i++ {
		mat[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			mat[i][j], _ = rand.Int(rand.Reader, q)
		}
	}
	return mat
}
