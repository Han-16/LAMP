// cmd/main.go
package main

import (
	"bytes"
	"fmt"
	"log"
	"math/big"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/merkle"

	"github.com/consensys/gnark-crypto/ecc"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gmimc "github.com/consensys/gnark-crypto/hash"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ------------------------------
// Helpers (field/bigint/mimc)
// ------------------------------

func frFromU64(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)
	return e
}

func bigFromFr(e fr.Element) *big.Int {
	var b big.Int
	e.BigInt(&b)
	return &b
}

func frFromBig(v *big.Int) fr.Element {
	var e fr.Element
	// SetBigInt reduces mod p
	e.SetBigInt(v)
	return e
}

func bytesToBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// cmFromRoots computes CmABC or CmXYZ off-circuit using bytes absorption.
// NOTE: if your in-circuit MiMC absorbs field elements differently than this,
// CmABC/CmXYZ assertion may fail. If so, we will align encoding (field-based).
func cmFromRoots(rootBytes ...[]byte) []byte {
	h := gmimc.MIMC_BN254.New()
	for _, rb := range rootBytes {
		h.Write(rb)
	}
	return h.Sum(nil)
}

// deriveRFromRoots expands a 32-byte MiMC digest into K field elements by hashing the seed repeatedly.
// r[i] := MiMC(seed), seed := MiMC(seed)
func deriveRFromRoots(rootA, rootB, rootC []byte, K int) []fr.Element {
	h := gmimc.MIMC_BN254.New()

	// seed0 = MiMC(rootA || rootB || rootC)
	h.Write(rootA)
	h.Write(rootB)
	h.Write(rootC)
	seed := h.Sum(nil) // 32 bytes

	r := make([]fr.Element, K)
	for i := 0; i < K; i++ {
		h.Reset()
		h.Write(seed)
		seed = h.Sum(nil) // 32 bytes
		r[i] = frFromBig(bytesToBig(seed))
	}
	return r
}

// ------------------------------
// Matrix utilities (column-major)
// ------------------------------

// Mat is column-major: Mat[j] = column j, with length K.
type Mat [][]fr.Element

func makeMat(K, N int) Mat {
	m := make([][]fr.Element, N)
	for j := 0; j < N; j++ {
		m[j] = make([]fr.Element, K)
	}
	return m
}

// C = A * B (square KxK), stored column-major.
// C[i,j] = sum_t A[i,t] * B[t,j]
// With column-major storage:
//
//	A[i,t] = Acol[t][i]
//	B[t,j] = Bcol[j][t]
func matMulColumnMajorSquare(K int, A, B Mat) Mat {
	C := makeMat(K, K)
	for j := 0; j < K; j++ { // column of C
		for i := 0; i < K; i++ { // row
			var acc fr.Element
			acc.SetZero()
			for t := 0; t < K; t++ {
				var tmp fr.Element
				tmp.Mul(&A[t][i], &B[j][t]) // A[i,t] * B[t,j]
				acc.Add(&acc, &tmp)
			}
			C[j][i] = acc
		}
	}
	return C
}

// x = r * A, where r is 1xK row vector, A is KxN (here N=K).
// x[j] = dot(r, A_col[j]).
func rowTimesMat(r []fr.Element, A Mat) []fr.Element {
	N := len(A)
	K := len(r)
	x := make([]fr.Element, N)
	for j := 0; j < N; j++ {
		var acc fr.Element
		acc.SetZero()
		for i := 0; i < K; i++ {
			var tmp fr.Element
			tmp.Mul(&r[i], &A[j][i])
			acc.Add(&acc, &tmp)
		}
		x[j] = acc
	}
	return x
}

// y = x * B, where x is 1xN, B is NxN.
// y[j] = dot(x, B_col[j]).
func rowTimesMatWithRowLen(x []fr.Element, B Mat) []fr.Element {
	N := len(x)
	y := make([]fr.Element, N)
	for j := 0; j < N; j++ {
		var acc fr.Element
		acc.SetZero()
		for i := 0; i < N; i++ {
			var tmp fr.Element
			tmp.Mul(&x[i], &B[j][i])
			acc.Add(&acc, &tmp)
		}
		y[j] = acc
	}
	return y
}

// Convert a column-major matrix (fr) to merkle helper matrix format ([][]*big.Int).
func toMerkleMatrix(m Mat) [][]*big.Int {
	N := len(m)
	out := make([][]*big.Int, N)
	for j := 0; j < N; j++ {
		K := len(m[j])
		out[j] = make([]*big.Int, K)
		for i := 0; i < K; i++ {
			out[j][i] = bigFromFr(m[j][i])
		}
	}
	return out
}

// Convert vector v (length N) into "matrix of N columns, each of length 1"
func vecToMerkleMatrix(v []fr.Element) [][]*big.Int {
	N := len(v)
	out := make([][]*big.Int, N)
	for j := 0; j < N; j++ {
		out[j] = []*big.Int{bigFromFr(v[j])}
	}
	return out
}

// Convert proofPath ([][]byte) into []frontend.Variable (big.Int)
func proofPathToVars(path [][]byte) []frontend.Variable {
	out := make([]frontend.Variable, len(path))
	for i := 0; i < len(path); i++ {
		out[i] = bytesToBig(path[i])
	}
	return out
}

// Convert fr column to []frontend.Variable
func colToVars(col []fr.Element) []frontend.Variable {
	out := make([]frontend.Variable, len(col))
	for i := 0; i < len(col); i++ {
		out[i] = bigFromFr(col[i])
	}
	return out
}

// ------------------------------
// Main
// ------------------------------

func main() {
	// --------------------------
	// Parameters (keep small)
	// --------------------------
	K := 4
	N := 4 // keep N=K so circuit's foldB = dot(VecX, ColsEncB) is dimension-consistent
	L := 2 // number of sampled indices

	// Fixed indices (verifier-chosen). Must be < N.
	indicesU64 := []uint64{0, 2}

	// --------------------------
	// Build sample matrices A,B (column-major)
	// --------------------------
	A := makeMat(K, N)
	B := makeMat(K, N)

	// Deterministic small values
	// A_col[j][i] = 10*j + i + 1
	// B_col[j][i] = 100 + 10*j + i + 1
	for j := 0; j < N; j++ {
		for i := 0; i < K; i++ {
			A[j][i] = frFromU64(uint64(10*j + i + 1))
			B[j][i] = frFromU64(uint64(100 + 10*j + i + 1))
		}
	}

	// C = A * B
	C := matMulColumnMajorSquare(K, A, B)

	// --------------------------
	// Merkle commit A,B,C (roots are 32 bytes)
	// --------------------------
	rootA, serA, segA, _, err := merkle.CommitMatrix(toMerkleMatrix(A))
	must(err)
	rootB, serB, segB, _, err := merkle.CommitMatrix(toMerkleMatrix(B))
	must(err)
	rootC, serC, segC, _, err := merkle.CommitMatrix(toMerkleMatrix(C))
	must(err)

	// --------------------------
	// Derive r from (rootA, rootB, rootC) (verifier-style)
	// --------------------------
	r := deriveRFromRoots(rootA, rootB, rootC, K)

	// x = r * A, y = x * B, z = r * C
	x := rowTimesMat(r, A)
	y := rowTimesMatWithRowLen(x, B)
	z := rowTimesMat(r, C)

	// --------------------------
	// Merkle commit x,y,z
	// --------------------------
	rootX, serX, segX, _, err := merkle.CommitMatrix(vecToMerkleMatrix(x))
	must(err)
	rootY, serY, segY, _, err := merkle.CommitMatrix(vecToMerkleMatrix(y))
	must(err)
	rootZ, serZ, segZ, _, err := merkle.CommitMatrix(vecToMerkleMatrix(z))
	must(err)

	// Proofs for sampled indices
	proofA, err := merkle.GenerateProofs(serA, segA, indicesU64)
	must(err)
	proofB, err := merkle.GenerateProofs(serB, segB, indicesU64)
	must(err)
	proofC, err := merkle.GenerateProofs(serC, segC, indicesU64)
	must(err)

	proofX, err := merkle.GenerateProofs(serX, segX, indicesU64)
	must(err)
	proofY, err := merkle.GenerateProofs(serY, segY, indicesU64)
	must(err)
	proofZ, err := merkle.GenerateProofs(serZ, segZ, indicesU64)
	must(err)

	// Depth inferred from proof path length
	depth := len(proofA[0])
	fmt.Printf("Merkle depth: %d\n", depth)

	// --------------------------
	// Compute CmABC and CmXYZ (public)
	// --------------------------
	cmABCBytes := cmFromRoots(rootA, rootB, rootC)
	cmXYZBytes := cmFromRoots(rootX, rootY, rootZ)

	// Convert roots & cm to big.Int for witness
	rootAInt := bytesToBig(rootA)
	rootBInt := bytesToBig(rootB)
	rootCInt := bytesToBig(rootC)
	rootXInt := bytesToBig(rootX)
	rootYInt := bytesToBig(rootY)
	rootZInt := bytesToBig(rootZ)

	cmABCInt := bytesToBig(cmABCBytes)
	cmXYZInt := bytesToBig(cmXYZBytes)

	// --------------------------
	// Build circuit template with fixed sizes (gnark needs static lengths)
	// --------------------------
	c := &circuit.MeowCircuit{
		K: K, N: N,

		ChallengeR: make([]frontend.Variable, K),
		Indices:    make([]frontend.Variable, L),

		ColsEncA: make([][]frontend.Variable, L),
		ColsEncB: make([][]frontend.Variable, L),
		ColsEncC: make([][]frontend.Variable, L),

		VecX: make([]frontend.Variable, K),
		VecY: make([]frontend.Variable, K),
		VecZ: make([]frontend.Variable, K),

		MerkleProofsA: make([][]frontend.Variable, L),
		MerkleProofsB: make([][]frontend.Variable, L),
		MerkleProofsC: make([][]frontend.Variable, L),

		MerkleProofsX: make([][]frontend.Variable, L),
		MerkleProofsY: make([][]frontend.Variable, L),
		MerkleProofsZ: make([][]frontend.Variable, L),
	}

	// Allocate inner slices
	for i := 0; i < L; i++ {
		c.ColsEncA[i] = make([]frontend.Variable, K)
		c.ColsEncB[i] = make([]frontend.Variable, K)
		c.ColsEncC[i] = make([]frontend.Variable, K)

		c.MerkleProofsA[i] = make([]frontend.Variable, depth)
		c.MerkleProofsB[i] = make([]frontend.Variable, depth)
		c.MerkleProofsC[i] = make([]frontend.Variable, depth)

		c.MerkleProofsX[i] = make([]frontend.Variable, depth)
		c.MerkleProofsY[i] = make([]frontend.Variable, depth)
		c.MerkleProofsZ[i] = make([]frontend.Variable, depth)
	}

	// --------------------------
	// Compile & show constraints
	// --------------------------
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	must(err)
	fmt.Printf("NbConstraints: %d\n", ccs.GetNbConstraints())

	// --------------------------
	// Build witness assignment
	// --------------------------
	assignment := &circuit.MeowCircuit{
		K: K, N: N,

		// Public
		Roots: [6]frontend.Variable{
			rootAInt, rootBInt, rootCInt,
			rootXInt, rootYInt, rootZInt,
		},
		CmABC: cmABCInt,
		CmXYZ: cmXYZInt,

		ChallengeR: make([]frontend.Variable, K),
		Indices:    make([]frontend.Variable, L),

		// Private
		ColsEncA: make([][]frontend.Variable, L),
		ColsEncB: make([][]frontend.Variable, L),
		ColsEncC: make([][]frontend.Variable, L),

		VecX: make([]frontend.Variable, K),
		VecY: make([]frontend.Variable, K),
		VecZ: make([]frontend.Variable, K),

		MerkleProofsA: make([][]frontend.Variable, L),
		MerkleProofsB: make([][]frontend.Variable, L),
		MerkleProofsC: make([][]frontend.Variable, L),

		MerkleProofsX: make([][]frontend.Variable, L),
		MerkleProofsY: make([][]frontend.Variable, L),
		MerkleProofsZ: make([][]frontend.Variable, L),
	}

	// Fill r (public)
	for i := 0; i < K; i++ {
		assignment.ChallengeR[i] = bigFromFr(r[i])
	}

	// Fill indices (public)
	for i := 0; i < L; i++ {
		assignment.Indices[i] = new(big.Int).SetUint64(indicesU64[i])
	}

	// Fill VecX/VecY/VecZ (private). Here we store x,y,z as length K (since N=K).
	for i := 0; i < K; i++ {
		assignment.VecX[i] = bigFromFr(x[i])
		assignment.VecY[i] = bigFromFr(y[i])
		assignment.VecZ[i] = bigFromFr(z[i])
	}

	// Allocate per-query arrays
	for qi := 0; qi < L; qi++ {
		assignment.ColsEncA[qi] = make([]frontend.Variable, K)
		assignment.ColsEncB[qi] = make([]frontend.Variable, K)
		assignment.ColsEncC[qi] = make([]frontend.Variable, K)

		assignment.MerkleProofsA[qi] = make([]frontend.Variable, depth)
		assignment.MerkleProofsB[qi] = make([]frontend.Variable, depth)
		assignment.MerkleProofsC[qi] = make([]frontend.Variable, depth)

		assignment.MerkleProofsX[qi] = make([]frontend.Variable, depth)
		assignment.MerkleProofsY[qi] = make([]frontend.Variable, depth)
		assignment.MerkleProofsZ[qi] = make([]frontend.Variable, depth)
	}

	// Fill per-query opened columns and proof paths
	for qi := 0; qi < L; qi++ {
		idx := indicesU64[qi]

		// Open A_col[idx], B_col[idx], C_col[idx]
		assignment.ColsEncA[qi] = colToVars(A[idx])
		assignment.ColsEncB[qi] = colToVars(B[idx])
		assignment.ColsEncC[qi] = colToVars(C[idx])

		// Merkle paths
		assignment.MerkleProofsA[qi] = proofPathToVars(proofA[qi])
		assignment.MerkleProofsB[qi] = proofPathToVars(proofB[qi])
		assignment.MerkleProofsC[qi] = proofPathToVars(proofC[qi])

		assignment.MerkleProofsX[qi] = proofPathToVars(proofX[qi])
		assignment.MerkleProofsY[qi] = proofPathToVars(proofY[qi])
		assignment.MerkleProofsZ[qi] = proofPathToVars(proofZ[qi])
	}

	// --------------------------
	// Prove & Verify (Groth16)
	// --------------------------
	pk, vk, err := groth16.Setup(ccs)
	must(err)

	wFull, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	must(err)

	wPub, err := wFull.Public()
	must(err)

	proof, err := groth16.Prove(ccs, pk, wFull)
	must(err)

	err = groth16.Verify(proof, vk, wPub)
	must(err)

	fmt.Println("✅ proof verified")

	// Extra: print public inputs
	printPublicSummary(rootA, rootB, rootC, rootX, rootY, rootZ, cmABCBytes, cmXYZBytes)
}

// ------------------------------
// Debug print
// ------------------------------

func printPublicSummary(rootA, rootB, rootC, rootX, rootY, rootZ, cmABC, cmXYZ []byte) {
	fmt.Println("Public summary (hex):")
	fmt.Printf("  rootA: 0x%x\n", rootA)
	fmt.Printf("  rootB: 0x%x\n", rootB)
	fmt.Printf("  rootC: 0x%x\n", rootC)
	fmt.Printf("  rootX: 0x%x\n", rootX)
	fmt.Printf("  rootY: 0x%x\n", rootY)
	fmt.Printf("  rootZ: 0x%x\n", rootZ)
	fmt.Printf("  CmABC: 0x%x\n", cmABC)
	fmt.Printf("  CmXYZ: 0x%x\n", cmXYZ)

	for name, v := range map[string][]byte{
		"rootA": rootA, "rootB": rootB, "rootC": rootC,
		"rootX": rootX, "rootY": rootY, "rootZ": rootZ,
		"CmABC": cmABC, "CmXYZ": cmXYZ,
	} {
		if len(v) != 32 {
			fmt.Printf("  ⚠️ %s length = %d (expected 32)\n", name, len(v))
		}
	}
}

// ------------------------------
// Error handling
// ------------------------------

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// ------------------------------
// Sanity: ensure we are on BN254 field
// ------------------------------
var _ = bn254.ID
var _ = bytes.MinRead
