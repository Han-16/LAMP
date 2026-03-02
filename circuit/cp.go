package circuit

import "github.com/consensys/gnark/frontend"

type Cp struct {
	CommittedValues [][]frontend.Variable
}

func (c *Cp) Define(api frontend.API) error {
	sum := frontend.Variable(0)
	committer := api.(frontend.Committer)

	// L개의 행(Row)에 대해 각각 커밋을 생성합니다.
	for i := 0; i < len(c.CommittedValues); i++ {
		for j := 0; j < len(c.CommittedValues[i]); j++ {
			sum = api.Add(sum, c.CommittedValues[i][j])
		}

		// 🔥 각 행(Row) 단위로 커밋을 수행합니다. (총 L번 호출됨)
		_, err := committer.Commit(c.CommittedValues[i]...)
		if err != nil {
			return err
		}
	}

	api.AssertIsDifferent(sum, 0)
	return nil
}
