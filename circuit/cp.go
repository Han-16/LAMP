package circuit

import "github.com/consensys/gnark/frontend"

type Cp struct {
	CommittedValues [][]frontend.Variable
}

func (c *Cp) Define(api frontend.API) error {
	sum := frontend.Variable(0)
	committer := api.(frontend.Committer)

	for i := 0; i < len(c.CommittedValues); i++ {
		for j := 0; j < len(c.CommittedValues[i]); j++ {
			sum = api.Add(sum, c.CommittedValues[i][j])
		}
		committer.Commit(c.CommittedValues[i]...)
	}

	return nil
}
