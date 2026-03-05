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
	T1 fr.Element // Response for external commit (C1)
	T2 fr.Element // Response for internal commit (C2)
}

func ProveCPLink(x []fr.Element, r1, r2 fr.Element, ck1, ck2 CommitKey) CPLinkProof {
	K := len(x)
	y := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		y[i].SetRandom()
	}

	var s1, s2 fr.Element
	s1.SetRandom()
	s2.SetRandom()

	R1 := PedersenCommitBlinded(y, s1, ck1)
	R2 := PedersenCommitBlinded(y, s2, ck2)

	C1 := PedersenCommitBlinded(x, r1, ck1)
	C2 := PedersenCommitBlinded(x, r2, ck2)

	c := HashElements(HashPoint(C1), HashPoint(C2), HashPoint(R1), HashPoint(R2))

	z := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		var cx fr.Element
		cx.Mul(&c, &x[i])
		z[i].Add(&y[i], &cx)
	}

	var cr1, cr2 fr.Element
	cr1.Mul(&c, &r1)
	cr2.Mul(&c, &r2)

	var t1, t2 fr.Element
	t1.Add(&s1, &cr1)
	t2.Add(&s2, &cr2)

	return CPLinkProof{R1: R1, R2: R2, Z: z, T1: t1, T2: t2}
}

func VerifyCPLink(C1, C2 bn254.G1Affine, proof CPLinkProof, ck1, ck2 CommitKey) bool {
	c := HashElements(HashPoint(C1), HashPoint(C2), HashPoint(proof.R1), HashPoint(proof.R2))
	var cBig big.Int
	c.BigInt(&cBig)

	// 1. C1 (external commit) verification: Commit(Z, T1, ck1) == R1 + c*C1
	lhs1 := PedersenCommitBlinded(proof.Z, proof.T1, ck1)
	var rhs1, C1Jac, R1Jac bn254.G1Jac
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

	// 2. C2 (internal commit) verification: Commit(Z, T2, ck2) == R2 + c*C2
	lhs2 := PedersenCommitBlinded(proof.Z, proof.T2, ck2)
	var rhs2, C2Jac, R2Jac bn254.G1Jac
	C2Jac.FromAffine(&C2)
	R2Jac.FromAffine(&proof.R2)
	var tmp2 bn254.G1Jac
	tmp2.ScalarMultiplication(&C2Jac, &cBig)
	rhs2.AddAssign(&R2Jac).AddAssign(&tmp2)
	var rhs2Affine bn254.G1Affine
	rhs2Affine.FromJacobian(&rhs2)

	return lhs2.Equal(&rhs2Affine)
}
