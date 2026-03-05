package crypto

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type CommitKey struct {
	G []bn254.G1Affine
}

func SetupCommitKey(k int) CommitKey {
	var ck CommitKey
	ck.G = make([]bn254.G1Affine, k)

	_, _, G1, _ := bn254.Generators()

	for i := 0; i < k; i++ {
		var r fr.Element
		r.SetRandom()
		var b big.Int
		r.BigInt(&b)

		var tmp bn254.G1Jac
		tmp.FromAffine(&G1)
		tmp.ScalarMultiplication(&tmp, &b)
		ck.G[i].FromJacobian(&tmp)
	}
	return ck
}

func PedersenCommit(column []fr.Element, ck CommitKey) bn254.G1Affine {
	var res bn254.G1Affine

	// Pippenger 알고리즘을 사용한 고속 병렬 스칼라 곱셈
	_, err := res.MultiExp(ck.G, column, ecc.MultiExpConfig{})
	if err != nil {
		panic(err)
	}

	return res
}
