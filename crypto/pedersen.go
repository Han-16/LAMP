package crypto

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type CommitKey = PedersenKey

func SetupCommitKey(size int) CommitKey {
	key, err := CommitmentKey(size)
	if err != nil {
		panic(err)
	}
	return key
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

func BatchPedersenCommitBlinded(columns [][]fr.Element, ck CommitKey) ([]bn254.G1Affine, []fr.Element) {
	blindings, err := randomBlindings(len(columns))
	if err != nil {
		panic(err)
	}
	commitments, err := commitColumns(ck, columns, blindings)
	if err != nil {
		panic(err)
	}
	return commitments, blindings
}

func BatchPedersenCommitABCBlinded(a, b, c [][]fr.Element, ck CommitKey) ([]bn254.G1Affine, []fr.Element) {
	if len(a) != len(b) || len(a) != len(c) {
		panic("A, B, C column counts must match")
	}
	columns := make([][]fr.Element, len(a))
	for j := range columns {
		if len(a[j]) != len(b[j]) || len(a[j]) != len(c[j]) || 3*len(a[j]) != len(ck.G) {
			panic("ABC column width differs from commitment key")
		}
		columns[j] = make([]fr.Element, 0, len(ck.G))
		columns[j] = append(columns[j], a[j]...)
		columns[j] = append(columns[j], b[j]...)
		columns[j] = append(columns[j], c[j]...)
	}
	return BatchPedersenCommitBlinded(columns, ck)
}
