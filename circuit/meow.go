package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
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
}

func (c *MeowCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	L := len(c.Indices)

	// 0. 🚨 [매우 중요] Freivalds 핵심 검증: Y == Z
	for k := 0; k < c.K; k++ {
		api.AssertIsEqual(c.VecY[k], c.VecZ[k])
	}

	// 1. Commit A, B, C & X, Y, Z sequentially (총 6L 개의 내부 커밋 생성)
	for i := 0; i < L; i++ {
		committer.Commit(c.ColsEncA[i]...)
		committer.Commit(c.ColsEncB[i]...)
		committer.Commit(c.ColsEncC[i]...)

		idxBits := api.ToBinary(c.Indices[i], c.Depth)

		// 위에서 수정한 안전한 SelectTargetIndex 사용
		targetEncX := SelectTargetIndex(api, c.EncX, idxBits)
		targetEncY := SelectTargetIndex(api, c.EncY, idxBits)
		targetEncZ := SelectTargetIndex(api, c.EncZ, idxBits)

		committer.Commit(targetEncX)
		committer.Commit(targetEncY)
		committer.Commit(targetEncZ)

		// 질문자님의 완벽한 수학적 통찰이 반영된 Fold 로직!
		foldA := Fold(api, c.ChallengeR, c.ColsEncA[i])
		foldB := Fold(api, c.VecX, c.ColsEncB[i])       // y = x * B
		foldC := Fold(api, c.ChallengeR, c.ColsEncC[i]) // z = r * C

		api.AssertIsEqual(foldA, targetEncX)
		api.AssertIsEqual(foldB, targetEncY)
		api.AssertIsEqual(foldC, targetEncZ)
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
