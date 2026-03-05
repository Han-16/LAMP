package crypto

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/utils"
)

type Encoder struct {
	domainK *fft.Domain
	domainN *fft.Domain
	k, n    int
}

func NewEncoder(k, n int) *Encoder {
	return &Encoder{
		domainK: fft.NewDomain(uint64(k)),
		domainN: fft.NewDomain(uint64(n)),
		k:       k,
		n:       n,
	}
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

func (e *Encoder) EncodeRowWise(data [][]fr.Element) ([][]fr.Element, [][]fr.Element, error) {
	coeffsList := make([][]fr.Element, len(data))
	encodedList := make([][]fr.Element, len(data))
	for i, row := range data {
		coeffs, encRow, err := e.Encode(row)
		if err != nil {
			return nil, nil, err
		}
		coeffsList[i] = coeffs
		encodedList[i] = encRow
	}
	return coeffsList, encodedList, nil
}

func (e *Encoder) Verify(encodedData []fr.Element) bool {
	domainNSize := int(e.domainN.Cardinality)
	domainKSize := int(e.domainK.Cardinality)

	if len(encodedData) != domainNSize {
		return false
	}

	coeffs := make([]fr.Element, domainNSize)
	copy(coeffs, encodedData)

	e.domainN.FFTInverse(coeffs, fft.DIF)
	utils.BitReverse(coeffs)

	for i := domainKSize; i < domainNSize; i++ {
		if !coeffs[i].IsZero() {
			return false
		}
	}

	return true
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
	if len(matrix) != e.k {
		return nil, nil, fmt.Errorf("matrix must have exactly K (%d) rows, got %d", e.k, len(matrix))
	}

	coeffsMatrix := make([][]fr.Element, e.k)
	encodedMatrix := make([][]fr.Element, e.k)

	// 2. 각 행에 대해 K x N 인코딩 수행
	for i, row := range matrix {
		// 각 행의 열(Column) 개수가 K를 초과하는지 검증
		if len(row) > e.k {
			return nil, nil, fmt.Errorf("row %d length cannot exceed K (%d)", i, e.k)
		}

		coeffs, encRow, err := e.Encode(row)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode row %d: %w", i, err)
		}

		coeffsMatrix[i] = coeffs
		encodedMatrix[i] = encRow
	}

	return coeffsMatrix, encodedMatrix, nil
}
