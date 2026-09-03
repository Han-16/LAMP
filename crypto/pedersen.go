package crypto

import (
	"crypto/rand"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type CommitKey struct {
	G []bn254.G1Affine // G[i] for i in 0..K-1
	H bn254.G1Affine   // H for blinding
}

func SetupCommitKey(K int) CommitKey {
	var ck CommitKey
	ck.G = make([]bn254.G1Affine, K)

	_, _, G1, _ := bn254.Generators()
	fieldSize := ecc.BN254.ScalarField()

	// Generate random points for G and H by multiplying the generator with random scalars.
	for i := 0; i < K; i++ {
		r, err := rand.Int(rand.Reader, fieldSize)
		if err != nil {
			panic(err)
		}
		ck.G[i].ScalarMultiplication(&G1, r)
	}

	rH, err := rand.Int(rand.Reader, fieldSize)
	if err != nil {
		panic(err)
	}
	ck.H.ScalarMultiplication(&G1, rH)

	return ck
}

// PedersenCommit: C = <data, G> + blinding * H
func PedersenCommitBlinded(data []fr.Element, blinding fr.Element, ck CommitKey) bn254.G1Affine {
	if len(data) != len(ck.G) {
		panic("data length must match the number of G points in the commit key")
	}

	points := make([]bn254.G1Affine, len(ck.G)+1)
	copy(points, ck.G)
	points[len(ck.G)] = ck.H

	scalars := make([]fr.Element, len(data)+1)
	copy(scalars, data)
	scalars[len(data)] = blinding

	var res bn254.G1Affine
	_, err := res.MultiExp(points, scalars, ecc.MultiExpConfig{})
	if err != nil {
		panic(err)
	}

	return res
}

func BatchPedersenCommitBlinded(matrix [][]fr.Element, ck CommitKey) ([]bn254.G1Affine, []fr.Element) {
	L := len(matrix)
	if L == 0 {
		return nil, nil
	}
	K := len(matrix[0])

	cm := make([]bn254.G1Affine, L)
	blindings := make([]fr.Element, L)

	basisPoints := make([]bn254.G1Affine, len(ck.G)+1)
	copy(basisPoints, ck.G)
	basisPoints[len(ck.G)] = ck.H

	numWorkers := runtime.NumCPU()
	chunkSize := (L + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > L {
			end = L
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			localScalars := make([]fr.Element, K+1)
			cfg := ecc.MultiExpConfig{NbTasks: 1}

			for i := start; i < end; i++ {
				blindings[i].SetRandom()
				copy(localScalars, matrix[i])
				localScalars[K] = blindings[i]

				_, err := cm[i].MultiExp(basisPoints, localScalars, cfg)
				if err != nil {
					panic(err)
				}
			}
		}(start, end)
	}
	wg.Wait()

	return cm, blindings
}

func BatchPedersenCommitABCBlinded(a, b, c [][]fr.Element, ck CommitKey) ([]bn254.G1Affine, []fr.Element) {
	L := len(a)
	if L == 0 {
		return nil, nil
	}
	if len(b) != L || len(c) != L {
		panic("A, B, C column counts must match")
	}

	K := len(a[0])
	if len(ck.G) != 3*K {
		panic("commit key length must be 3 times the ABC column length")
	}
	for i := 0; i < L; i++ {
		if len(a[i]) != K || len(b[i]) != K || len(c[i]) != K {
			panic("all A, B, C columns must have the same length")
		}
	}

	cm := make([]bn254.G1Affine, L)
	blindings := make([]fr.Element, L)

	basisPoints := make([]bn254.G1Affine, len(ck.G)+1)
	copy(basisPoints, ck.G)
	basisPoints[len(ck.G)] = ck.H

	numWorkers := runtime.NumCPU()
	chunkSize := (L + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > L {
			end = L
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			localScalars := make([]fr.Element, 3*K+1)
			cfg := ecc.MultiExpConfig{NbTasks: 1}

			for i := start; i < end; i++ {
				blindings[i].SetRandom()
				copy(localScalars[:K], a[i])
				copy(localScalars[K:2*K], b[i])
				copy(localScalars[2*K:3*K], c[i])
				localScalars[3*K] = blindings[i]

				_, err := cm[i].MultiExp(basisPoints, localScalars, cfg)
				if err != nil {
					panic(err)
				}
			}
		}(start, end)
	}
	wg.Wait()

	return cm, blindings
}
