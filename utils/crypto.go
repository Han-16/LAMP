package utils

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"golang.org/x/crypto/sha3"
)

// CommitKey contains k group bases for commitment.
type CommitKey struct {
	G []bn254.G1Affine // Basis vector of length k
}

// HashElements hashes the given fr.Elements using Ethereum's Keccak-256.
func HashElements(elements ...fr.Element) fr.Element {
	h := sha3.NewLegacyKeccak256()
	for _, e := range elements {
		b := e.Bytes()
		h.Write(b[:])
	}
	var res fr.Element
	res.SetBytes(h.Sum(nil))
	return res
}

// PedersenCommit performs a commitment given a column vector x of length k without a blinding factor.
func PedersenCommit(column []fr.Element, ck CommitKey) bn254.G1Affine {
	var res bn254.G1Jac
	var tmp bn254.G1Jac
	var baseJac bn254.G1Jac
	var b big.Int

	// Add vector elements: g_i^x_i
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

// SetupCommitKey generates a CommitKey with k bases.
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

// =========================================================================
// CP-LINK IMPLEMENTATION
// =========================================================================

// CPLinkProof represents the Schnorr proof for CP-LINK equivalence.
type CPLinkProof struct {
	R1 bn254.G1Affine // Random commitment using ck1
	R2 bn254.G1Affine // Random commitment using ck2
	Z  []fr.Element   // Response vector for the data
	T  fr.Element     // Response scalar for the blinding factor
}

// ProveCPLink generates a Schnorr proof showing that C1 (no blinding) and C2 (with blinding r)
// commit to the same vector x.
func ProveCPLink(x []fr.Element, r fr.Element, ck1 CommitKey, ck2 CommitKey) CPLinkProof {
	K := len(x)

	// 1. Sample random masking vector y and scalar s
	y := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		y[i].SetRandom()
	}
	var s fr.Element
	s.SetRandom()

	// 2. Compute R1 = Commit(y, ck1)
	R1 := PedersenCommit(y, ck1)

	// 3. Compute R2 = Commit(y || s, ck2)
	yPadded := append(y, s)
	R2 := PedersenCommit(yPadded, ck2)

	// Compute base commitments for challenge generation
	C1 := PedersenCommit(x, ck1)
	xPadded := append(x, r)
	C2 := PedersenCommit(xPadded, ck2)

	// 4. Fiat-Shamir Challenge c = Hash(C1, C2, R1, R2)
	c := HashElements(HashPoint(C1), HashPoint(C2), HashPoint(R1), HashPoint(R2))

	// 5. Compute responses: Z = y + c*x, T = s + c*r
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

// VerifyCPLink verifies the CP-LINK Schnorr proof.
func VerifyCPLink(C1 bn254.G1Affine, C2 bn254.G1Affine, proof CPLinkProof, ck1 CommitKey, ck2 CommitKey) bool {
	// 1. Recompute challenge c = Hash(C1, C2, R1, R2)
	c := HashElements(HashPoint(C1), HashPoint(C2), HashPoint(proof.R1), HashPoint(proof.R2))
	var cBig big.Int
	c.BigInt(&cBig)

	// 2. Check 1: Commit(Z, ck1) == R1 + c*C1
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

	// 3. Check 2: Commit(Z || T, ck2) == R2 + c*C2
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

	if !lhs2.Equal(&rhs2Affine) {
		return false
	}

	return true
}
