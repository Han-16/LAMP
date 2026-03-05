package crypto

import (
	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type CommitKey struct {
	G []bn254.G1Affine // G[i] for i in 0..K-1
	H bn254.G1Affine   // H for blinding
}

func SetupCommitKey(K int) CommitKey {
	var ck CommitKey
	ck.G = make([]bn254.G1Affine, K)

	_, _, G1, _ := bn254.Generators()
	fieldSize := ecc.BN254.ScalarField()

	// Generate random points for G and H by multiplying the generator with random scalars.
	for i := 0; i < K; i++ {
		r, err := rand.Int(rand.Reader, fieldSize)
		if err != nil {
			panic(err)
		}
		ck.G[i].ScalarMultiplication(&G1, r)
	}

	rH, err := rand.Int(rand.Reader, fieldSize)
	if err != nil {
		panic(err)
	}
	ck.H.ScalarMultiplication(&G1, rH)

	return ck
}

// PedersenCommit: C = <data, G> + blinding * H
func PedersenCommitBlinded(data []fr.Element, blinding fr.Element, ck CommitKey) bn254.G1Affine {
	if len(data) != len(ck.G) {
		panic("data length must match the number of G points in the commit key")
	}

	points := make([]bn254.G1Affine, len(ck.G)+1)
	copy(points, ck.G)
	points[len(ck.G)] = ck.H

	scalars := make([]fr.Element, len(data)+1)
	copy(scalars, data)
	scalars[len(data)] = blinding

	var res bn254.G1Affine
	_, err := res.MultiExp(points, scalars, ecc.MultiExpConfig{})
	if err != nil {
		panic(err)
	}

	return res
}
