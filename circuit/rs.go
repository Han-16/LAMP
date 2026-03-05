package circuit

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

type RSCircuit struct {
	K, N int

	DomainK  []fr.Element
	WeightsK []fr.Element

	DomainN  []fr.Element // Roots of unity for the evaluation domain of size N (w^i)
	WeightsN []fr.Element // Barycentric weights for the evaluation domain of size N (\lambda_i)

	Message        []frontend.Variable // Input message of size K {a_i}
	CodewordValues []frontend.Variable // Codeword values of size N {c_i}
}

func (c *RSCircuit) Define(api frontend.API) error {
	committer, _ := api.(frontend.Committer)

	var flatData []frontend.Variable
	flatData = append(flatData, c.Message...)
	flatData = append(flatData, c.CodewordValues...)

	z, err := committer.Commit(flatData...)
	if err != nil {
		return err
	}

	VerifyRSEncoding(
		api, c.K, c.N, c.DomainK, c.WeightsK, c.DomainN, c.WeightsN, c.Message, c.CodewordValues, z,
	)

	return nil
}
