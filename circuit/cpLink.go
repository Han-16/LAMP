package circuit

import "github.com/consensys/gnark/frontend"

type CpLink struct {
	CommittedValues []frontend.Variable
}

func (c *CpLink) Define(api frontend.API) error {
	sum := frontend.Variable(0)
	for _, v := range c.CommittedValues {
		sum = api.Add(sum, v)
	}
	api.AssertIsDifferent(sum, 0)

	committer := api.(frontend.Committer)
	_, err := committer.Commit(c.CommittedValues...)
	return err
}
