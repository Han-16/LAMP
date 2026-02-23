package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// MatrixCommitmentCircuit은 행렬 A의 특정 열(Column)들이 머클 루트에 포함되어 있는지 검증하는 서킷입니다.
type MatrixCommitmentCircuit struct {
	// 머클 루트 (공개 입력)
	Root frontend.Variable `gnark:",public"`

	// 검증할 인덱스 목록
	Indices []frontend.Variable `gnark:",public"`

	// 추출된 행렬의 열 벡터들: 크기 [NumQueries][K] (비공개 입력)
	Columns [][]frontend.Variable

	// 각 인덱스에 대한 머클 증명 경로: 크기 [NumQueries][Depth]
	MerkleProofs [][]frontend.Variable
}

func (c *MatrixCommitmentCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := 0; i < len(c.Indices); i++ {
		VerifyColumnMerkleProof(
			api,
			h,
			c.Root,
			c.Columns[i],
			c.Indices[i],
			c.MerkleProofs[i],
		)
	}

	return nil
}
