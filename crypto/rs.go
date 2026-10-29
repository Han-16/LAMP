package crypto

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/utils"
)

type Encoder struct{ *rsCode }

func NewEncoder(k, n int) *Encoder {
	code, err := newRSCode(k, n)
	if err != nil {
		panic(err)
	}
	return &Encoder{code}
}

// EncodeMatrices writes square A/B/C matrices directly into one column layout.
func (e *Encoder) EncodeMatrices(matrices [][][]fr.Element) ([][]fr.Element, error) {
	for p, mat := range matrices {
		if len(mat) != e.K {
			return nil, fmt.Errorf("matrix %d must have %d rows", p, e.K)
		}
		for i, row := range mat {
			if len(row) != e.K {
				return nil, fmt.Errorf("matrix %d row %d must have %d columns", p, i, e.K)
			}
		}
	}
	return e.encodeMatrices(matrices, len(matrices)*e.K), nil
}

// Encode returns both the message coefficients (size K) and the encoded codeword (size N)
func (e *Encoder) Encode(data []fr.Element) ([]fr.Element, []fr.Element, error) {
	domainKSize := int(e.domainK.Cardinality)
	domainNSize := int(e.domainN.Cardinality)

	if len(data) > domainKSize {
		return nil, nil, fmt.Errorf("input data length cannot exceed domain K size (%d)", domainKSize)
	}

	// 1. iFFT: 다항식 계수로 변환
	coeffs := make([]fr.Element, domainKSize)
	copy(coeffs, data)

	e.domainK.FFTInverse(coeffs, fft.DIF)
	utils.BitReverse(coeffs)

	// 서킷에 제공할 메시지 계수
	msgCoeffs := make([]fr.Element, domainKSize)
	copy(msgCoeffs, coeffs)

	// 2. Zero-Padding
	paddedCoeffs := make([]fr.Element, domainNSize)
	copy(paddedCoeffs, coeffs)

	// 3. FFT: 인코딩
	e.domainN.FFT(paddedCoeffs, fft.DIF)
	utils.BitReverse(paddedCoeffs)

	return msgCoeffs, paddedCoeffs, nil
}

func GetDomainRoots(domain *fft.Domain, size int) []fr.Element {
	roots := make([]fr.Element, size)
	roots[0].SetOne()
	for i := 1; i < size; i++ {
		roots[i].Mul(&roots[i-1], &domain.Generator)
	}
	return roots
}

func PrecomputeBarycentricWeights(roots []fr.Element) []fr.Element {
	n := len(roots)
	weights := make([]fr.Element, n)

	if n == 0 {
		return weights
	}

	var nEle fr.Element
	nEle.SetUint64(uint64(n))

	var nInv fr.Element
	nInv.Inverse(&nEle)

	for i := 0; i < n; i++ {
		weights[i].Mul(&roots[i], &nInv)
	}

	return weights
}

func (e *Encoder) EncodeMatrix(matrix [][]fr.Element) ([][]fr.Element, [][]fr.Element, error) {
	if len(matrix) != e.K {
		return nil, nil, fmt.Errorf("matrix must have exactly K (%d) rows, got %d", e.K, len(matrix))
	}

	return e.EncodeRows(matrix)
}

func (e *Encoder) EncodeRows(rows [][]fr.Element) ([][]fr.Element, [][]fr.Element, error) {
	coeffsMatrix := make([][]fr.Element, len(rows))
	encodedMatrix := make([][]fr.Element, len(rows))

	for i, row := range rows {
		coeffs, encRow, err := e.Encode(row)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode row %d: %w", i, err)
		}

		coeffsMatrix[i] = coeffs
		encodedMatrix[i] = encRow
	}

	return coeffsMatrix, encodedMatrix, nil
}

func (e *Encoder) EncodeRowsToColumns(rows [][]fr.Element) ([][]fr.Element, error) {
	for i, row := range rows {
		if len(row) > e.K {
			return nil, fmt.Errorf("row %d exceeds code dimension %d", i, e.K)
		}
	}
	cols := make([][]fr.Element, e.N)
	for j := range cols {
		cols[j] = make([]fr.Element, len(rows))
	}
	parallelRanges(len(rows), func(first, last int) {
		scratch := make([]fr.Element, e.N)
		option := fft.WithNbTasks(1)
		for i := first; i < last; i++ {
			if len(rows[i]) < e.K {
				clear(scratch[:e.K])
			}
			e.encodeInto(rows[i], scratch, option)
			for j := range cols {
				cols[j][i] = scratch[j]
			}
		}
	})
	return cols, nil
}
