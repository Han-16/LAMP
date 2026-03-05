package crypto

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type CPLinkProof struct {
	R1 bn254.G1Affine
	R2 bn254.G1Affine
	Z  []fr.Element
	T  fr.Element
}

func ProveCPLink(x []fr.Element, r fr.Element, ck1 CommitKey, ck2 CommitKey) CPLinkProof {
	K := len(x)

	y := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		y[i].SetRandom()
	}
	var s fr.Element
	s.SetRandom()

	R1 := PedersenCommit(y, ck1)
	yPadded := append(y, s)
	R2 := PedersenCommit(yPadded, ck2)

	C1 := PedersenCommit(x, ck1)
	xPadded := append(x, r)
	C2 := PedersenCommit(xPadded, ck2)

	c := HashElements(HashPoint(C1), HashPoint(C2), HashPoint(R1), HashPoint(R2))

	z := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		var cx fr.Element
		cx.Mul(&c, &x[i])
		z[i].Add(&y[i], &cx)
	}

	var cr fr.Element
	cr.Mul(&c, &r)
	var t fr.Element
	t.Add(&s, &cr)

	return CPLinkProof{
		R1: R1,
		R2: R2,
		Z:  z,
		T:  t,
	}
}

func VerifyCPLink(C1 bn254.G1Affine, C2 bn254.G1Affine, proof CPLinkProof, ck1 CommitKey, ck2 CommitKey) bool {
	c := HashElements(HashPoint(C1), HashPoint(C2), HashPoint(proof.R1), HashPoint(proof.R2))
	var cBig big.Int
	c.BigInt(&cBig)

	lhs1 := PedersenCommit(proof.Z, ck1)

	var rhs1 bn254.G1Jac
	var C1Jac, R1Jac bn254.G1Jac
	C1Jac.FromAffine(&C1)
	R1Jac.FromAffine(&proof.R1)

	var tmp1 bn254.G1Jac
	tmp1.ScalarMultiplication(&C1Jac, &cBig)
	rhs1.AddAssign(&R1Jac).AddAssign(&tmp1)

	var rhs1Affine bn254.G1Affine
	rhs1Affine.FromJacobian(&rhs1)

	if !lhs1.Equal(&rhs1Affine) {
		return false
	}

	zPadded := append(proof.Z, proof.T)

	lhs2 := PedersenCommit(zPadded, ck2)

	var rhs2 bn254.G1Jac
	var C2Jac, R2Jac bn254.G1Jac
	C2Jac.FromAffine(&C2)
	R2Jac.FromAffine(&proof.R2)

	var tmp2 bn254.G1Jac
	tmp2.ScalarMultiplication(&C2Jac, &cBig)
	rhs2.AddAssign(&R2Jac).AddAssign(&tmp2)

	var rhs2Affine bn254.G1Affine
	rhs2Affine.FromJacobian(&rhs2)

	return lhs2.Equal(&rhs2Affine)
}
