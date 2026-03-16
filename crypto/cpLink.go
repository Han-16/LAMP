package crypto

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
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

// ProveCPLink: Generate a CP-LINK proof for two commitments C1 and C2 that commit to the same underlying data x with randomness r1 and r2, respectively.
func ProveCPLink(x []fr.Element, r1, r2 fr.Element, ck1, ck2 CommitKey) CPLinkProof {
	K := len(x)

	// 1. Generate random masks
	y := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		y[i].SetRandom()
	}

	var s1, s2 fr.Element
	s1.SetRandom()
	s2.SetRandom()

	// 2. Compute initial commitments (Announcements)
	R1 := PedersenCommitBlinded(y, s1, ck1)
	R2 := PedersenCommitBlinded(y, s2, ck2)

	// 3. Compute actual commitments
	C1 := PedersenCommitBlinded(x, r1, ck1)
	C2 := PedersenCommitBlinded(x, r2, ck2)

	// 4. Generate Fiat-Shamir challenge 'c'
	c := computeCPLinkChallenge(C1, C2, R1, R2)

	// 5. Compute responses (Z, T1, T2)
	z := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		var cx fr.Element
		cx.Mul(&c, &x[i])
		z[i].Add(&y[i], &cx)
	}

	var cr1, cr2, t1, t2 fr.Element
	cr1.Mul(&c, &r1)
	cr2.Mul(&c, &r2)
	t1.Add(&s1, &cr1)
	t2.Add(&s2, &cr2)

	return CPLinkProof{R1: R1, R2: R2, Z: z, T1: t1, T2: t2}
}

// VerifyCPLink: Verify a single CP-LINK proof for commitments C1 and C2.
func VerifyCPLink(C1, C2 bn254.G1Affine, proof CPLinkProof, ck1, ck2 CommitKey) bool {
	c := computeCPLinkChallenge(C1, C2, proof.R1, proof.R2)

	var weight fr.Element
	weight.SetOne()

	capacity := len(proof.Z) + 3

	var wg sync.WaitGroup
	wg.Add(2)
	var res1Ok, res2Ok bool

	// --- 1. C1 Verification ---
	go func() {
		defer wg.Done()
		points := make([]bn254.G1Affine, 0, capacity)
		scalars := make([]fr.Element, 0, capacity)
		points, scalars = appendZeroCheckTerms(points, scalars, proof.Z, proof.T1, proof.R1, C1, ck1, c, weight)

		var res1 bn254.G1Affine
		if _, err := res1.MultiExp(points, scalars, ecc.MultiExpConfig{}); err == nil {
			res1Ok = res1.IsInfinity()
		}
	}()

	// --- 2. C2 Verification ---
	go func() {
		defer wg.Done()
		points := make([]bn254.G1Affine, 0, capacity)
		scalars := make([]fr.Element, 0, capacity)
		points, scalars = appendZeroCheckTerms(points, scalars, proof.Z, proof.T2, proof.R2, C2, ck2, c, weight)

		var res2 bn254.G1Affine
		if _, err := res2.MultiExp(points, scalars, ecc.MultiExpConfig{}); err == nil {
			res2Ok = res2.IsInfinity()
		}
	}()

	wg.Wait()
	return res1Ok && res2Ok
}

// VerifyCPLinksBatched: Verify multiple CP-LINK proofs in a batched manner for lists of commitments C1s and C2s.
func VerifyCPLinksBatched(C1s, C2s []bn254.G1Affine, proofs []CPLinkProof, ck1 CommitKey, ck2s []CommitKey) bool {
	L := len(proofs)
	if L == 0 {
		return true
	}
	K := len(proofs[0].Z)

	// 1. Reconstruct challenges and combination coefficient 'r'
	cs := make([]fr.Element, L)
	for i := 0; i < L; i++ {
		cs[i] = computeCPLinkChallenge(C1s[i], C2s[i], proofs[i].R1, proofs[i].R2)
	}

	r := cs[0]
	for i := 1; i < L; i++ {
		r = HashElements(r, cs[i])
	}

	var rPow fr.Element
	rPow.SetOne()

	// Preallocate structures to avoid dynamic memory resizing overhead
	zBatched := make([]fr.Element, K)
	var t1Batched fr.Element

	rhs1Points := make([]bn254.G1Affine, 0, 2*L)
	rhs1Scalars := make([]fr.Element, 0, 2*L)

	msm2Points := make([]bn254.G1Affine, 0, L*(K+3))
	msm2Scalars := make([]fr.Element, 0, L*(K+3))

	// 2. Compress C1 variables and group C2 equations
	for i := 0; i < L; i++ {
		// --- C1 Compression ---
		for j := 0; j < K; j++ {
			var tmpZ fr.Element
			tmpZ.Mul(&proofs[i].Z[j], &rPow)
			zBatched[j].Add(&zBatched[j], &tmpZ)
		}
		var tmpT1 fr.Element
		tmpT1.Mul(&proofs[i].T1, &rPow)
		t1Batched.Add(&t1Batched, &tmpT1)

		rhs1Points = append(rhs1Points, proofs[i].R1)
		rhs1Scalars = append(rhs1Scalars, rPow)

		var rC fr.Element
		rC.Mul(&rPow, &cs[i])
		rhs1Points = append(rhs1Points, C1s[i])
		rhs1Scalars = append(rhs1Scalars, rC)

		// --- Grouping C2 Equations (Constructing Giant MSM) ---
		msm2Points, msm2Scalars = appendZeroCheckTerms(
			msm2Points, msm2Scalars,
			proofs[i].Z, proofs[i].T2, proofs[i].R2, C2s[i],
			ck2s[i], cs[i], rPow,
		)

		// Update combination weight r^i
		rPow.Mul(&rPow, &r)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var c1Ok, c2Ok bool

	// --- 3. C1 Verification ---
	go func() {
		defer wg.Done()
		lhs1 := PedersenCommitBlinded(zBatched, t1Batched, ck1)
		var rhs1 bn254.G1Affine
		if _, err := rhs1.MultiExp(rhs1Points, rhs1Scalars, ecc.MultiExpConfig{}); err == nil {
			c1Ok = lhs1.Equal(&rhs1)
		}
	}()

	// --- 4. C2 Verification (Giant MSM) ---
	go func() {
		defer wg.Done()
		var msm2 bn254.G1Affine
		if _, err := msm2.MultiExp(msm2Points, msm2Scalars, ecc.MultiExpConfig{}); err == nil {
			c2Ok = msm2.IsInfinity()
		}
	}()

	wg.Wait()
	return c1Ok && c2Ok
}

func computeCPLinkChallenge(C1, C2, R1, R2 bn254.G1Affine) fr.Element {
	return HashElements(HashPoint(C1), HashPoint(C2), HashPoint(R1), HashPoint(R2))
}

func appendZeroCheckTerms(
	points []bn254.G1Affine, scalars []fr.Element,
	Z []fr.Element, T fr.Element, R, C bn254.G1Affine,
	ck CommitKey, c, weight fr.Element,
) ([]bn254.G1Affine, []fr.Element) {
	K := len(Z)

	// 1. LHS: weight * Z_i * G_i
	for j := 0; j < K; j++ {
		points = append(points, ck.G[j])
		var tmpZ fr.Element
		tmpZ.Mul(&Z[j], &weight)
		scalars = append(scalars, tmpZ)
	}

	// 2. LHS: weight * T * H
	points = append(points, ck.H)
	var tmpT fr.Element
	tmpT.Mul(&T, &weight)
	scalars = append(scalars, tmpT)

	// 3. RHS transposed: -weight * R
	var negWeight fr.Element
	negWeight.Neg(&weight)
	points = append(points, R)
	scalars = append(scalars, negWeight)

	// 4. RHS transposed: -(weight * c) * C
	var negWeightC fr.Element
	negWeightC.Mul(&weight, &c)
	negWeightC.Neg(&negWeightC)
	points = append(points, C)
	scalars = append(scalars, negWeightC)

	return points, scalars
}
