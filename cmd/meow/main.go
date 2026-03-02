package main

import (
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/rs"
	"github.com/Han-16/meow/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const (
	K = 1 << 2 // 행렬의 차원 (K x K)
	N = K << 1 // 인코딩된 행렬의 열 수 (K x N), 머클 트리를 위해 2의 거듭제곱 사용
	L = 1 << 0 // 추출할 랜덤 인덱스의 개수
)

func main() {
	fmt.Println("Configurations:")
	fmt.Println("K =", K)
	fmt.Println("N =", N)
	fmt.Println("L =", L)
	fmt.Println("=== Starting the Matrix Commitment Protocol ===")
	ck := utils.SetupCommitKey(K)
	depthN := int(math.Log2(float64(N)))
	depthK := int(math.Log2(float64(K)))

	// 1. A, B, C 생성 (A * B = C)
	fmt.Println("\n1. Generating matrices A, B, and computing C = A * B...")
	start := time.Now()
	A := utils.GenerateRandomMatrix(K, K)
	B := utils.GenerateRandomMatrix(K, K)
	C := utils.MatMul(A, B, K)
	fmt.Printf(" -> Matrices generated and multiplied in %s\n", time.Since(start))

	// 2. 인코딩 (K x K -> K x N)
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

	// 3. E_A, E_B, E_C 커밋 (열단위 Pedersen + Merkle)
	fmt.Println("3. Committing to encoded matrices...")
	start = time.Now()
	blindings := utils.GenerateRandomVector(N)
	_, root_A, _ := utils.CommitMatrix(EA_cols, blindings, ck, depthN)
	_, root_B, _ := utils.CommitMatrix(EB_cols, blindings, ck, depthN)
	_, root_C, _ := utils.CommitMatrix(EC_cols, blindings, ck, depthN)
	fmt.Printf(" -> Commitments generated in %s\n", time.Since(start))

	// 4. Hash cm_A, cm_B, cm_C -> cm_ABC
	fmt.Println("4. Hashing cm_A, cm_B, cm_C to get cm_ABC...")
	start = time.Now()
	cm_ABC := utils.HashElements(root_A, root_B, root_C)
	fmt.Printf(" -> Hashing completed in %s\n", time.Since(start))

	// 5. Generate random challenge vector r using Fiat-Shamir heuristic
	fmt.Println("5. Generating challenge vector r via Fiat-Shamir...")
	start = time.Now()
	r := utils.GenerateChallengeVector(cm_ABC, K)
	fmt.Printf(" -> Challenge vector generated in %s\n", time.Since(start))

	// 6. Calculate vectors x = A*r, y = x*B, z = C*r
	fmt.Println("6. Computing vectors x, y, z...")
	start = time.Now()
	x := utils.VecMatMul(r, A, K)
	y := utils.VecMatMul(x, B, K)
	z := utils.VecMatMul(r, C, K)
	fmt.Printf(" -> Vectors computed in %s\n", time.Since(start))

	// 6.5. Encode vectors x, y, z -> EncX, EncY, EncZ
	fmt.Println("6.5. Encoding vectors x, y, z to length N...")
	start = time.Now()
	Ex_rows, _ := encoder.EncodeRowWise([][]fr.Element{x})
	Ey_rows, _ := encoder.EncodeRowWise([][]fr.Element{y})
	Ez_rows, _ := encoder.EncodeRowWise([][]fr.Element{z})
	encX_vals := Ex_rows[0]
	encY_vals := Ey_rows[0]
	encZ_vals := Ez_rows[0]
	fmt.Printf(" -> Vectors encoded in %s\n", time.Since(start))

	// 7. Merkle committing field vectors x, y, z
	fmt.Println("7. Merkle committing field vectors x, y, z...")
	start = time.Now()
	_, root_x := utils.BuildMerkleTreeFromFieldElements(x, depthK)
	_, root_y := utils.BuildMerkleTreeFromFieldElements(y, depthK)
	_, root_z := utils.BuildMerkleTreeFromFieldElements(z, depthK)
	fmt.Printf(" -> Merkle commitments completed in %s\n", time.Since(start))

	// 8. Hash cm_x, cm_y, cm_z -> cm_xyz
	fmt.Println("8. Hashing cm_x, cm_y, cm_z to get cm_xyz...")
	start = time.Now()
	cm_xyz := utils.HashElements(root_x, root_y, root_z)
	fmt.Printf(" -> Hashing completed in %s\n", time.Since(start))

	// 9. Generate L random indices using Fiat-Shamir heuristic on cm_xyz
	fmt.Println("9. [Meow] Extracting indices using Fiat-Shamir heuristic...")
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

	// 10. Compile Circuit & Setup
	fmt.Println("10. Compiling Circuit and running Groth16 Setup...")
	startSetup := time.Now()
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
		RandomA:    make([]frontend.Variable, L), // 추가됨
		RandomB:    make([]frontend.Variable, L), // 추가됨
		RandomC:    make([]frontend.Variable, L), // 추가됨
	}

	for i := 0; i < L; i++ {
		emptyCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		emptyCircuit.ColsEncC[i] = make([]frontend.Variable, K)
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &emptyCircuit)
	pk, vk, _ := groth16.Setup(ccs)
	fmt.Printf(" -> Setup completed in %s\n", time.Since(startSetup))

	// 11. Witness Assignment & Prove
	fmt.Println("11. Assigning Witness and generating Proof...")
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
		RandomA:    make([]frontend.Variable, L), // 추가됨
		RandomB:    make([]frontend.Variable, L), // 추가됨
		RandomC:    make([]frontend.Variable, L), // 추가됨
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

		// 3번 단계에서 행렬 커밋 시 사용했던 해당 열(Column)의 Blinding Factor를 할당합니다.
		assignment.RandomA[i] = blindings[idx]
		assignment.RandomB[i] = blindings[idx]
		assignment.RandomC[i] = blindings[idx]
	}

	witnessFull, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	proof, _ := groth16.Prove(ccs, pk, witnessFull)
	fmt.Printf("🔍 Proof Details: %+v\n", proof)

	// 12. Verify
	fmt.Println("12. Verifying the Proof...")
	witnessPublic, _ := witnessFull.Public()
	err := groth16.Verify(proof, vk, witnessPublic)
	if err != nil {
		fmt.Printf(" -> Verification FAILED: %v\n", err)
	} else {
		fmt.Println(" -> Verification SUCCESSFUL! 🎉")
	}
}
