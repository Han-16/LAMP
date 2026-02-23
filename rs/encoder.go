package rs

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/frontend"
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

func (e *Encoder) Encode(data []fr.Element) ([]fr.Element, error) {
	if len(data) > e.k {
		return nil, fmt.Errorf("input data length cannot exceed k (%d)", e.k)
	}

	paddedData := make([]fr.Element, e.n)
	copy(paddedData, data)

	return paddedData, nil
}

// Note: This function is not used in the current implementation.
func (e *Encoder) EncodeInCircuit(data []frontend.Variable) ([]frontend.Variable, error) {
	if len(data) > e.k {
		return nil, fmt.Errorf("input data length cannot exceed k (%d)", e.k)
	}

	paddedData := make([]frontend.Variable, e.n)

	for i := 0; i < e.n; i++ {
		if i < len(data) {
			paddedData[i] = data[i]
		} else {
			paddedData[i] = frontend.Variable(0)
		}
	}

	return paddedData, nil
}
