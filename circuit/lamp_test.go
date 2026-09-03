package circuit

import (
	"testing"

	"example.com/lamp/crypto"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func TestLAMPCommitmentLayout(t *testing.T) {
	const K, N, L = 4, 8, 1

	domainK := fft.NewDomain(K)
	domainN := fft.NewDomain(N)
	c := &LAMPCircuit{
		K: K, N: N,
		DomainK:    crypto.GetDomainRoots(domainK, K),
		WeightsK:   crypto.PrecomputeBarycentricWeights(crypto.GetDomainRoots(domainK, K)),
		DomainN:    crypto.GetDomainRoots(domainN, N),
		WeightsN:   crypto.PrecomputeBarycentricWeights(crypto.GetDomainRoots(domainN, N)),
		Indices:    make([]frontend.Variable, L),
		ColsEncABC: [][]frontend.Variable{make([]frontend.Variable, 3*K)},
		VecX:       make([]frontend.Variable, K),
		VecYZ:      make([]frontend.Variable, K),
		VecBTest:   make([]frontend.Variable, K),
		EncX:       make([]frontend.Variable, N),
		EncYZ:      make([]frontend.Variable, N),
		EncBTest:   make([]frontend.Variable, N),
		QueriedEncValues: [][]frontend.Variable{
			make([]frontend.Variable, 3),
		},
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	commitments := ccs.GetCommitments().(constraint.Groth16Commitments)
	if len(commitments) < 3 {
		t.Fatalf("got %d commitments, want at least 3", len(commitments))
	}

	// Commit adds one private random mask after the explicitly committed values.
	wantPrivate := []int{3*L*K + 1, 3*L + 1, 3*(K+N) + 1}
	for i, want := range wantPrivate {
		if got := len(commitments[i].PrivateCommitted); got != want {
			t.Fatalf("commitment %d has %d private values, want %d", i, got, want)
		}
	}
}
