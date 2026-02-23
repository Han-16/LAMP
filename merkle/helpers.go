package merkle

import (
	"bytes"
	"math/big"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	_ "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
)

const ModNbBytes = 32

func padBytes(v *big.Int) []byte {
	b := v.Bytes()
	if len(b) >= ModNbBytes {
		return b
	}
	padded := make([]byte, ModNbBytes)
	copy(padded[ModNbBytes-len(b):], b)
	return padded
}

func SerializeMatrix(matrix [][]*big.Int) []byte {
	var buf bytes.Buffer
	for _, column := range matrix {
		for _, val := range column {
			buf.Write(padBytes(val))
		}
	}
	return buf.Bytes()
}

func CommitMatrix(matrix [][]*big.Int) (root []byte, serializedData []byte, segmentSize int, numLeaves uint64, err error) {
	if len(matrix) == 0 {
		return nil, nil, 0, 0, nil
	}

	numLeaves = uint64(len(matrix))
	k := len(matrix[0])
	segmentSize = k * ModNbBytes

	serializedData = SerializeMatrix(matrix)

	hasher := hash.MIMC_BN254.New()
	reader := bytes.NewReader(serializedData)

	root, _, _, err = merkletree.BuildReaderProof(reader, hasher, segmentSize, 0)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	return root, serializedData, segmentSize, numLeaves, nil
}

func GenerateProofs(serializedData []byte, segmentSize int, indices []uint64) ([][][]byte, error) {
	hasher := hash.MIMC_BN254.New()
	proofs := make([][][]byte, len(indices))

	for i, idx := range indices {
		reader := bytes.NewReader(serializedData)

		_, proofPath, _, err := merkletree.BuildReaderProof(reader, hasher, segmentSize, idx)
		if err != nil {
			return nil, err
		}

		proofs[i] = proofPath
	}

	return proofs, nil
}
