package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/rs"
	"github.com/Han-16/meow/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

const (
	K = 1 << 2 // 행렬의 차원 (K x K)
	N = K << 1 // 인코딩된 행렬의 열 수 (K x N), 머클 트리를 위해 2의 거듭제곱 사용
	L = 1 << 0 // 추출할 랜덤 인덱스의 개수
)

func main() {
	fmt.Printf("=== Meow ===\nK=%d, N=%d, L=%d\n", K, N, L)
	depthN := int(math.Log2(float64(N)))
	depthK := int(math.Log2(float64(K)))

	// =========================================================================
	// 1. A, B, C 생성 (A * B = C)
	// =========================================================================
	fmt.Println("\n1. Generating matrices A, B, and computing C = A * B...")
	start := time.Now()
	A := utils.GenerateRandomMatrix(K, K)
	B := utils.GenerateRandomMatrix(K, K)
	C := utils.MatMul(A, B, K)
	fmt.Printf(" -> Matrices generated and multiplied in %s\n", time.Since(start))

	// =========================================================================
	// 2. 인코딩 (K x K -> K x N)
	// =========================================================================
	fmt.Println("2. Encoding matrices to K x N...")
	encoder := rs.NewEncoder(K, N)
	start = time.Now()
	EA_rows, _ := encoder.EncodeRowWise(A)
	EB_rows, _ := encoder.EncodeRowWise(B)
	EC_rows, _ := encoder.EncodeRowWise(C)
	fmt.Printf(" -> Encoding completed in %s\n", time.Since(start))
	EA_cols := utils.Transpose(EA_rows, K, N)
	EB_cols := utils.Transpose(EB_rows, K, N)
	EC_cols := utils.Transpose(EC_rows, K, N)

	// =========================================================================
	// 3. E_A, E_B, E_C 커밋 (열단위 Pedersen + Merkle)
	// =========================================================================
	fmt.Println("3. Committing to encoded matrices...")
	start = time.Now()
	blindingsPedA := utils.GenerateRandomVector(N)
	blindingsPedB := utils.GenerateRandomVector(N)
	blindingsPedC := utils.GenerateRandomVector(N)
	ck1 := utils.SetupCommitKey(K)
	_, root_A, pedCmsA := utils.CommitMatrix(EA_cols, blindingsPedA, ck1, int(math.Log2(float64(N))))
	_, root_B, pedCmsB := utils.CommitMatrix(EB_cols, blindingsPedB, ck1, int(math.Log2(float64(N))))
	_, root_C, pedCmsC := utils.CommitMatrix(EC_cols, blindingsPedC, ck1, int(math.Log2(float64(N))))
	fmt.Printf(" -> Commitments generated in %s\n", time.Since(start))
	fmt.Println(" -> Pedersen Commitments for A, B, C:", pedCmsA, pedCmsB, pedCmsC)

	// =========================================================================
	// 4. Hash cm_A, cm_B, cm_C -> cm_ABC
	// =========================================================================
	fmt.Println("4. Hashing commitments to get cm_ABC...")
	start = time.Now()
	cm_ABC := utils.HashElements(root_A, root_B, root_C)
	fmt.Printf(" -> Hashing completed in %s\n", time.Since(start))

	// =========================================================================
	// 5. Generate random challenge vector r using Fiat-Shamir heuristic
	// =========================================================================
	fmt.Println("5. Generating challenge vector r via Fiat-Shamir...")
	start = time.Now()
	r := utils.GenerateChallengeVector(cm_ABC, K)
	fmt.Printf(" -> Challenge vector generated in %s\n", time.Since(start))

	// =========================================================================
	// 6. Calculate vectors x = A*r, y = x*B, z = C*r
	// =========================================================================
	fmt.Println("6. Computing vectors x, y, z...")
	start = time.Now()
	x := utils.VecMatMul(r, A, K)
	y := utils.VecMatMul(x, B, K)
	z := utils.VecMatMul(r, C, K)
	fmt.Printf(" -> Vectors computed in %s\n", time.Since(start))

	// =========================================================================
	// 7. Encode vectors x, y, z -> EncX, EncY, EncZ
	// =========================================================================
	fmt.Println("7. Encoding vectors x, y, z...")
	start = time.Now()
	Ex_rows, _ := encoder.EncodeRowWise([][]fr.Element{x})
	Ey_rows, _ := encoder.EncodeRowWise([][]fr.Element{y})
	Ez_rows, _ := encoder.EncodeRowWise([][]fr.Element{z})
	encX_vals := Ex_rows[0]
	encY_vals := Ey_rows[0]
	encZ_vals := Ez_rows[0]
	fmt.Printf(" -> Vectors encoded in %s\n", time.Since(start))

	// =========================================================================
	// 8. Merkle committing field vectors x, y, z
	// =========================================================================
	fmt.Println("8. Merkle committing field vectors x, y, z...")
	start = time.Now()
	_, root_x := utils.BuildMerkleTreeFromFieldElements(x, depthK)
	_, root_y := utils.BuildMerkleTreeFromFieldElements(y, depthK)
	_, root_z := utils.BuildMerkleTreeFromFieldElements(z, depthK)
	fmt.Printf(" -> Merkle commitments completed in %s\n", time.Since(start))

	// =========================================================================
	// 9. Hash cm_x, cm_y, cm_z -> cm_xyz
	// =========================================================================
	fmt.Println("9. Hashing cm_x, cm_y, cm_z to get cm_xyz...")
	start = time.Now()
	cm_xyz := utils.HashElements(root_x, root_y, root_z)
	fmt.Printf(" -> Hashing completed in %s\n", time.Since(start))

	// =========================================================================
	// 10. Generate L random indices using Fiat-Shamir heuristic on cm_xyz
	// =========================================================================
	fmt.Println("10. Generating L random indices via Fiat-Shamir on cm_xyz...")
	start = time.Now()
	indices := make([]int, 0, L)
	used := make(map[int]bool)
	h := mimc.NewMiMC()
	cmBytes := cm_xyz.Bytes()
	hashBytes := cmBytes[:]
	for len(indices) < L {
		h.Reset()
		h.Write(hashBytes)
		hashBytes = h.Sum(nil)
		for i := 0; i < 32 && len(indices) < L; i += 8 {
			val := binary.BigEndian.Uint64(hashBytes[i : i+8])
			idx := int(val % uint64(N))
			if !used[idx] {
				used[idx] = true
				indices = append(indices, idx)
			}
		}
	}
	fmt.Printf(" -> Indices extracted in %s\n", time.Since(start))
	fmt.Printf(" -> Extracted indices: %v\n", indices)

	// =========================================================================
	// 11. Compile Circuit & Setup
	// =========================================================================
	fmt.Println("10. Compiling Circuit and running Groth16 Setup...")
	start = time.Now()
	emptyCircuit := circuit.Meow2Circuit{
		K: K, N: N, Depth: depthN,
		ChallengeR: make([]frontend.Variable, K),
		Indices:    make([]frontend.Variable, L),
		ColsEncA:   make([][]frontend.Variable, L),
		ColsEncB:   make([][]frontend.Variable, L),
		ColsEncC:   make([][]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K),
		VecY:       make([]frontend.Variable, K),
		VecZ:       make([]frontend.Variable, K),
		EncX:       make([]frontend.Variable, N),
		EncY:       make([]frontend.Variable, N),
		EncZ:       make([]frontend.Variable, N),
	}

	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
	}

	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyCircuit)
	pk, vk, _ := groth16.Setup(r1cs)
	fmt.Printf(" -> Setup completed in %s\n", time.Since(start))

	// =========================================================================
	// 12. Witness Assignment & Prove & Verify
	// =========================================================================
	fmt.Println("12. Assigning Witness and generating Proof...")
	assignment := circuit.Meow2Circuit{
		Roots:      [6]frontend.Variable{root_A, root_B, root_C, root_x, root_y, root_z},
		CmABC:      cm_ABC,
		CmXYZ:      cm_xyz,
		ChallengeR: make([]frontend.Variable, K),
		Indices:    make([]frontend.Variable, L),
		ColsEncA:   make([][]frontend.Variable, L),
		ColsEncB:   make([][]frontend.Variable, L),
		ColsEncC:   make([][]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K),
		VecY:       make([]frontend.Variable, K),
		VecZ:       make([]frontend.Variable, K),
		EncX:       make([]frontend.Variable, N),
		EncY:       make([]frontend.Variable, N),
		EncZ:       make([]frontend.Variable, N),
	}

	for i := 0; i < K; i++ {
		assignment.ChallengeR[i] = r[i]
		assignment.VecX[i] = x[i]
		assignment.VecY[i] = y[i]
		assignment.VecZ[i] = z[i]
	}

	for i := 0; i < N; i++ {
		assignment.EncX[i] = encX_vals[i]
		assignment.EncY[i] = encY_vals[i]
		assignment.EncZ[i] = encZ_vals[i]
	}

	for i, idx := range indices {
		assignment.Indices[i] = idx
		assignment.ColsEncA[i] = make([]frontend.Variable, K)
		assignment.ColsEncB[i] = make([]frontend.Variable, K)
		assignment.ColsEncC[i] = make([]frontend.Variable, K)

		for j := 0; j < K; j++ {
			assignment.ColsEncA[i][j] = EA_cols[idx][j]
			assignment.ColsEncB[i][j] = EB_cols[idx][j]
			assignment.ColsEncC[i][j] = EC_cols[idx][j]
		}

	}

	witnessFull, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	proof, _ := groth16.Prove(r1cs, pk, witnessFull)
	fmt.Printf("🔍 Proof Details: %+v\n", proof)

	// =========================================================================
	// 13. Compute L Manual Commitments
	// =========================================================================
	fmt.Println("13. Computing Manual Commitments for Extracted Indices...")
	proofVal := reflect.ValueOf(proof).Elem()
	commitmentsField := proofVal.FieldByName("Commitments")
	var proofCommitments []bn254.G1Affine
	if commitmentsField.IsValid() {
		proofCommitments = commitmentsField.Interface().([]bn254.G1Affine)
	}
	val := reflect.ValueOf(pk)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	ckField := val.FieldByName("CommitmentKeys")

	var ck2 [][]bn254.G1Affine
	if ckField.IsValid() {
		ckSlice := reflect.ValueOf(ckField.Interface())
		for i := 0; i < ckSlice.Len(); i++ {
			basisField := ckSlice.Index(i).FieldByName("Basis")
			ck2 = append(ck2, basisField.Interface().([]bn254.G1Affine))
		}
		fmt.Printf("✅ Extracted %d Commiting Keys ck2 from pk!\n", len(ck2))
	}

	hackedBlindings := groth16_bn254.HackBlindings

	allMatched := true

	for i := 0; i < L; i++ {
		// vectorPadded := [ColsEncA[i] | BlindingA[i]]
		vectorPadded := make([]fr.Element, K+1)
		for j := 0; j < K; j++ {
			vectorPadded[j] = assignment.ColsEncA[i][j].(fr.Element)
		}
		vectorPadded[K] = hackedBlindings[i]
		var manualCommitment bn254.G1Affine
		_, err := manualCommitment.MultiExp(ck2[i], vectorPadded, ecc.MultiExpConfig{})
		if err != nil {
			fmt.Printf("⚠️ MultiExp Error on [%d]: %v\n", i, err)
			continue
		}

		circuitCommitment := proofCommitments[i]
		if manualCommitment.Equal(&circuitCommitment) {
			fmt.Printf("  ✅ Match SUCCESS!\n")
		} else {
			fmt.Printf("  ❌ Match FAILED!\n")
			allMatched = false
		}
	}

	fmt.Println("\n=== The Ultimate Comparison Result ===")
	if allMatched {
		fmt.Println("🔥🔥🔥 ALL COMMITMENTS PERFECTLY MATCHED! 🔥🔥🔥")
	} else {
		fmt.Println("❌ SOME COMMITMENTS FAILED.")
	}

	// 증명 검증
	witnessPublic, _ := witnessFull.Public()
	if err := groth16.Verify(proof, vk, witnessPublic); err == nil {
		fmt.Println("\n🎉 Groth16 Verification SUCCESSFUL!")
	}
}
