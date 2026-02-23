package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"

	"github.com/Han-16/meow/circuit"
	"github.com/Han-16/meow/merkle"
	"github.com/Han-16/meow/rs"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// 1. 파라미터 설정 (K, N, L)
	kPtr := flag.Int("k", 8, "Matrix size KxK")
	nPtr := flag.Int("n", 16, "Encoded size N")
	lPtr := flag.Int("l", 4, "Number of query indices L")
	flag.Parse()

	K, N, L := *kPtr, *nPtr, *lPtr
	fmt.Printf("[1] 파라미터 설정: K=%d, N=%d, L=%d\n", K, N, L)

	// 2. K x K 행렬 A, B 생성 및 C = A * B 계산
	matrixA := make([][]fr.Element, K)
	matrixB := make([][]fr.Element, K)
	matrixC := make([][]fr.Element, K)
	for i := 0; i < K; i++ {
		matrixA[i] = make([]fr.Element, K)
		matrixB[i] = make([]fr.Element, K)
		matrixC[i] = make([]fr.Element, K)
		for j := 0; j < K; j++ {
			matrixA[i][j].SetRandom()
			matrixB[i][j].SetRandom()
		}
	}

	for i := 0; i < K; i++ {
		for j := 0; j < K; j++ {
			for l := 0; l < K; l++ {
				var tmp fr.Element
				tmp.Mul(&matrixA[i][l], &matrixB[l][j])
				matrixC[i][j].Add(&matrixC[i][j], &tmp)
			}
		}
	}
	fmt.Println("[2] 행렬 연산 완료 (C = A * B)")

	// 3. RS Encoder를 통해 K x N으로 인코딩
	encoder := rs.NewEncoder(K, N)
	encA, _ := encoder.EncodeRowWise(matrixA)
	encB, _ := encoder.EncodeRowWise(matrixB)
	encC, _ := encoder.EncodeRowWise(matrixC)
	fmt.Println("[3] Reed-Solomon 인코딩 완료")

	// 4. 머클 커밋 함수 (Column-wise)
	commitMatrix := func(mat [][]fr.Element) (root []byte, data []byte, segSize int) {
		// N개의 열(Column)을 리프로 만듦 (각 리프는 K개의 원소를 가짐)
		cols := make([][]*big.Int, N)
		for j := 0; j < N; j++ {
			cols[j] = make([]*big.Int, len(mat))
			for i := 0; i < len(mat); i++ {
				cols[j][i] = new(big.Int)
				mat[i][j].BigInt(cols[j][i])
			}
		}
		var err error
		root, data, segSize, _, err = merkle.CommitMatrix(cols)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	rootA, dataA, segA := commitMatrix(encA)
	rootB, dataB, segB := commitMatrix(encB)
	rootC, dataC, segC := commitMatrix(encC)
	fmt.Println("[4] 행렬 A, B, C 머클 커밋 완료")

	// 5. CmABC 생성 (H(rootA || rootB || rootC))
	hFunc := mimc.NewMiMC()
	hFunc.Write(rootA)
	hFunc.Write(rootB)
	hFunc.Write(rootC)
	cmABC := hFunc.Sum(nil)
	fmt.Printf("[5] CmABC 생성: %x\n", cmABC)

	// 6. ChallengeR 생성 (r, r^2, ..., r^K)
	var r fr.Element
	r.SetBytes(cmABC)
	challengeR := make([]fr.Element, K)
	challengeR[0].SetOne()
	for i := 1; i < K; i++ {
		challengeR[i].Mul(&challengeR[i-1], &r)
	}

	// 7. 벡터 연산: x = r*A, y = x*B, z = r*C
	vecX := make([]fr.Element, K)
	vecY := make([]fr.Element, K)
	vecZ := make([]fr.Element, K)

	for j := 0; j < K; j++ {
		for i := 0; i < K; i++ {
			var tmpX, tmpZ fr.Element
			tmpX.Mul(&challengeR[i], &matrixA[i][j])
			vecX[j].Add(&vecX[j], &tmpX)
			tmpZ.Mul(&challengeR[i], &matrixC[i][j])
			vecZ[j].Add(&vecZ[j], &tmpZ)
		}
	}
	for j := 0; j < K; j++ {
		for i := 0; i < K; i++ {
			var tmpY fr.Element
			tmpY.Mul(&vecX[i], &matrixB[i][j])
			vecY[j].Add(&vecY[j], &tmpY)
		}
	}
	fmt.Println("[7] 벡터 x, y, z 연산 완료")

	// 8. 벡터 x, y, z 인코딩 및 머클 커밋
	encX, _ := encoder.Encode(vecX)
	encY, _ := encoder.Encode(vecY)
	encZ, _ := encoder.Encode(vecZ)

	// 벡터용 머클 커밋 (각 리프는 1개의 원소를 가짐)
	commitVec := func(vec []fr.Element) (root []byte, data []byte, segSize int) {
		cols := make([][]*big.Int, N)
		for j := 0; j < N; j++ {
			cols[j] = []*big.Int{new(big.Int)}
			vec[j].BigInt(cols[j][0])
		}
		root, data, segSize, _, _ = merkle.CommitMatrix(cols)
		return
	}

	rootX, dataX, segX := commitVec(encX)
	rootY, dataY, segY := commitVec(encY)
	rootZ, dataZ, segZ := commitVec(encZ)

	// 9. cmXYZ 생성 및 인덱스 셋 I 추출
	hFunc.Reset()
	hFunc.Write(rootX)
	hFunc.Write(rootY)
	hFunc.Write(rootZ)
	cmXYZ := hFunc.Sum(nil)

	indices := make([]uint64, L)
	for i := 0; i < L; i++ {
		hFunc.Reset()
		hFunc.Write(cmXYZ)
		hFunc.Write([]byte{byte(i)})
		indices[i] = new(big.Int).SetBytes(hFunc.Sum(nil)).Uint64() % uint64(N)
	}
	fmt.Printf("[9] 쿼리 인덱스 추출: %v\n", indices)

	// 10. Merkle Proof 생성
	proofsA, _ := merkle.GenerateProofs(dataA, segA, indices)
	proofsB, _ := merkle.GenerateProofs(dataB, segB, indices)
	proofsC, _ := merkle.GenerateProofs(dataC, segC, indices)
	proofsX, _ := merkle.GenerateProofs(dataX, segX, indices)
	proofsY, _ := merkle.GenerateProofs(dataY, segY, indices)
	proofsZ, _ := merkle.GenerateProofs(dataZ, segZ, indices)

	// 11. 증명 생성 준비 (Assignment)
	assignment := circuit.MeowCircuit{
		K: K, N: N,
		CmABC:      cmABC,
		CmXYZ:      cmXYZ,
		ChallengeR: make([]frontend.Variable, K),
		Indices:    make([]frontend.Variable, L),
		VecX:       make([]frontend.Variable, K),
		VecY:       make([]frontend.Variable, K),
		VecZ:       make([]frontend.Variable, K),
	}

	// Public Roots 설정
	roots := [][]byte{rootA, rootB, rootC, rootX, rootY, rootZ}
	for i := 0; i < 6; i++ {
		assignment.Roots[i] = roots[i]
	}

	// Challenge 및 원본 벡터 설정
	for i := 0; i < K; i++ {
		assignment.ChallengeR[i] = challengeR[i]
		assignment.VecX[i] = vecX[i]
		assignment.VecY[i] = vecY[i]
		assignment.VecZ[i] = vecZ[i]
	}

	// 슬라이스 초기화
	assignment.ColsEncA = make([][]frontend.Variable, L)
	assignment.ColsEncB = make([][]frontend.Variable, L)
	assignment.ColsEncC = make([][]frontend.Variable, L)
	assignment.MerkleProofsA = make([][]frontend.Variable, L)
	assignment.MerkleProofsB = make([][]frontend.Variable, L)
	assignment.MerkleProofsC = make([][]frontend.Variable, L)
	assignment.MerkleProofsX = make([][]frontend.Variable, L)
	assignment.MerkleProofsY = make([][]frontend.Variable, L)
	assignment.MerkleProofsZ = make([][]frontend.Variable, L)

	for i := 0; i < L; i++ {
		idx := indices[i]
		assignment.Indices[i] = idx

		// 선택된 열 데이터 할당
		colA, colB, colC := make([]frontend.Variable, K), make([]frontend.Variable, K), make([]frontend.Variable, K)
		for j := 0; j < K; j++ {
			colA[j] = encA[j][idx]
			colB[j] = encB[j][idx]
			colC[j] = encC[j][idx]
		}
		assignment.ColsEncA[i], assignment.ColsEncB[i], assignment.ColsEncC[i] = colA, colB, colC

		// 머클 증명 경로 변환
		toVar := func(p [][]byte) []frontend.Variable {
			v := make([]frontend.Variable, len(p))
			for j := range p {
				v[j] = p[j]
			}
			return v
		}
		assignment.MerkleProofsA[i] = toVar(proofsA[i])
		assignment.MerkleProofsB[i] = toVar(proofsB[i])
		assignment.MerkleProofsC[i] = toVar(proofsC[i])
		assignment.MerkleProofsX[i] = toVar(proofsX[i])
		assignment.MerkleProofsY[i] = toVar(proofsY[i])
		assignment.MerkleProofsZ[i] = toVar(proofsZ[i])
	}

	// 12. Gnark 컴파일 및 증명 수행
	fmt.Println("[12] ZKP 증명 생성 시작...")
	var myCircuit circuit.MeowCircuit
	myCircuit.K, myCircuit.N = K, N
	myCircuit.ChallengeR = make([]frontend.Variable, K)
	myCircuit.Indices = make([]frontend.Variable, L)
	myCircuit.VecX, myCircuit.VecY, myCircuit.VecZ = make([]frontend.Variable, K), make([]frontend.Variable, K), make([]frontend.Variable, K)
	myCircuit.ColsEncA = make([][]frontend.Variable, L)
	myCircuit.ColsEncB = make([][]frontend.Variable, L)
	myCircuit.ColsEncC = make([][]frontend.Variable, L)

	// 머클 증명 깊이(log2(N)) 계산 및 더미 데이터 생성
	dummyProof := make([]frontend.Variable, len(assignment.MerkleProofsA[0]))
	for i := 0; i < L; i++ {
		myCircuit.ColsEncA[i] = make([]frontend.Variable, K)
		myCircuit.ColsEncB[i] = make([]frontend.Variable, K)
		myCircuit.ColsEncC[i] = make([]frontend.Variable, K)
		myCircuit.MerkleProofsA = append(myCircuit.MerkleProofsA, dummyProof)
		myCircuit.MerkleProofsB = append(myCircuit.MerkleProofsB, dummyProof)
		myCircuit.MerkleProofsC = append(myCircuit.MerkleProofsC, dummyProof)
		myCircuit.MerkleProofsX = append(myCircuit.MerkleProofsX, dummyProof)
		myCircuit.MerkleProofsY = append(myCircuit.MerkleProofsY, dummyProof)
		myCircuit.MerkleProofsZ = append(myCircuit.MerkleProofsZ, dummyProof)
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("증명 검증 실패: %v\n", err)
	} else {
		fmt.Println("🎉 증명 검증 성공! A * B = C 가 성립합니다.")
	}
}
