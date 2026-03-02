package utils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// CommitKey contains k+1 group bases for Pedersen commitment.
type CommitKey struct {
	G []bn254.G1Affine // Basis vector of length k
	H bn254.G1Affine   // Basis for hiding (h)
}

// HashElements hashes the given fr.Elements using MiMC.
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

// PedersenCommit performs a Pedersen commitment given a column vector x of length k and a blinding factor o.
func PedersenCommit(column []fr.Element, blinding fr.Element, ck CommitKey) bn254.G1Affine {
	var res bn254.G1Jac
	var tmp bn254.G1Jac
	var baseJac bn254.G1Jac
	var b big.Int

	// 1) Add hiding element: h^o
	blinding.BigInt(&b)
	baseJac.FromAffine(&ck.H)
	res.ScalarMultiplication(&baseJac, &b)

	// 2) Add vector elements: g_i^x_i
	for i, val := range column {
		val.BigInt(&b)
		baseJac.FromAffine(&ck.G[i])
		tmp.ScalarMultiplication(&baseJac, &b)
		res.AddAssign(&tmp)
	}

	var resAffine bn254.G1Affine
	resAffine.FromJacobian(&res)
	return resAffine
}

// FpToFr is a helper function that converts an Fp coordinate of the elliptic curve to an Fr element.
func FpToFr(fpElem fp.Element) fr.Element {
	var frElem fr.Element
	b := fpElem.Bytes()
	frElem.SetBytes(b[:])
	return frElem
}

// HashPoint hashes the x and y coordinates of a point on the elliptic curve (G1Affine) into an Fr element.
func HashPoint(p bn254.G1Affine) fr.Element {
	xFr := FpToFr(p.X)
	yFr := FpToFr(p.Y)
	return HashElements(xFr, yFr)
}

// SetupCommitKey generates a CommitKey with k bases and 1 hiding basis.
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

	var r fr.Element
	r.SetRandom()
	var b big.Int
	r.BigInt(&b)

	var tmp bn254.G1Jac
	tmp.FromAffine(&G1)
	tmp.ScalarMultiplication(&tmp, &b)
	ck.H.FromJacobian(&tmp)

	return ck
}

// GenerateChallengeVector generates a challenge vector using Fiat-Shamir heuristic (hash chaining).
func GenerateChallengeVector(seed fr.Element, size int) []fr.Element {
	r := make([]fr.Element, size)
	currentSeed := seed
	for i := 0; i < size; i++ {
		r[i] = HashElements(currentSeed)
		currentSeed = r[i] // Hash chaining
	}
	return r
}
