package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/lookup/logderivlookup" // 💡 룩업 패키지 추가
)

type MeowCircuit struct {
	K, N, Depth int

	DomainK  []fr.Element
	WeightsK []fr.Element

	DomainN  []fr.Element
	WeightsN []fr.Element

	Roots      [6]frontend.Variable `gnark:",public"`
	CmABC      frontend.Variable    `gnark:",public"`
	CmXYZ      frontend.Variable    `gnark:",public"`
	ChallengeR []frontend.Variable  `gnark:",public"`
	Indices    []frontend.Variable  `gnark:",public"`

	ColsEncA [][]frontend.Variable // [L][K]
	ColsEncB [][]frontend.Variable // [L][K]
	ColsEncC [][]frontend.Variable // [L][K]
	VecX     []frontend.Variable   // [K]
	VecY     []frontend.Variable   // [K]
	VecZ     []frontend.Variable   // [K]
	EncX     []frontend.Variable   // [N]
	EncY     []frontend.Variable   // [N]
	EncZ     []frontend.Variable   // [N]

	TargetEncX []frontend.Variable // [L]
	TargetEncY []frontend.Variable // [L]
	TargetEncZ []frontend.Variable // [L]
}

func (c *MeowCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	L := len(c.Indices)

	for k := 0; k < c.K; k++ {
		api.AssertIsEqual(c.VecY[k], c.VecZ[k])
	}

	// =========================================================================
	// 💡 [최적화] logderivlookup을 사용한 O(1) 룩업 테이블 초기화
	// =========================================================================
	tX := logderivlookup.New(api)
	tY := logderivlookup.New(api)
	tZ := logderivlookup.New(api)

	// 테이블에 길이 N짜리 인코딩 데이터 삽입
	for j := 0; j < c.N; j++ {
		tX.Insert(c.EncX[j])
		tY.Insert(c.EncY[j])
		tZ.Insert(c.EncZ[j])
	}

	// 1. Commit A, B, C & X, Y, Z sequentially
	for i := 0; i < L; i++ {
		committer.Commit(c.ColsEncA[i]...)
		committer.Commit(c.ColsEncB[i]...)
		committer.Commit(c.ColsEncC[i]...)

		// 💡 1번의 룩업으로 원하는 인덱스의 값을 즉시 가져옴 (MUX 연산 완전 제거)
		exprEncX := tX.Lookup(c.Indices[i])[0]
		exprEncY := tY.Lookup(c.Indices[i])[0]
		exprEncZ := tZ.Lookup(c.Indices[i])[0]

		// 가져온 룩업 값을 Target 변수와 매핑
		api.AssertIsEqual(exprEncX, c.TargetEncX[i])
		api.AssertIsEqual(exprEncY, c.TargetEncY[i])
		api.AssertIsEqual(exprEncZ, c.TargetEncZ[i])

		committer.Commit(c.TargetEncX[i])
		committer.Commit(c.TargetEncY[i])
		committer.Commit(c.TargetEncZ[i])

		foldA := Fold(api, c.ChallengeR, c.ColsEncA[i]) // x = r * A
		foldB := Fold(api, c.VecX, c.ColsEncB[i])       // y = x * B
		foldC := Fold(api, c.ChallengeR, c.ColsEncC[i]) // z = r * C

		api.AssertIsEqual(foldA, c.TargetEncX[i])
		api.AssertIsEqual(foldB, c.TargetEncY[i])
		api.AssertIsEqual(foldC, c.TargetEncZ[i])
	}

	// 2. Verify Hashes
	h.Reset()
	h.Write(c.Roots[0], c.Roots[1], c.Roots[2])
	api.AssertIsEqual(c.CmABC, h.Sum())

	h.Reset()
	h.Write(c.Roots[3], c.Roots[4], c.Roots[5])
	api.AssertIsEqual(c.CmXYZ, h.Sum())

	// 3. Verify Reed-Solomon encoding for X, Y, Z
	var xFlatData, yFlatData, zFlatData []frontend.Variable
	xFlatData = append(xFlatData, c.VecX...)
	xFlatData = append(xFlatData, c.EncX...)

	yFlatData = append(yFlatData, c.VecY...)
	yFlatData = append(yFlatData, c.EncY...)

	zFlatData = append(zFlatData, c.VecZ...)
	zFlatData = append(zFlatData, c.EncZ...)

	z_x, err := committer.Commit(xFlatData...)
	if err != nil {
		return err
	}
	z_y, err := committer.Commit(yFlatData...)
	if err != nil {
		return err
	}
	z_z, err := committer.Commit(zFlatData...)
	if err != nil {
		return err
	}

	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecX, c.EncX, z_x)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecY, c.EncY, z_y)
	VerifyRSEncoding(api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.VecZ, c.EncZ, z_z)
	return nil
}
