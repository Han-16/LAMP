// Common input primitives. Keep this file identical in LED/protocol and LAMP/crypto,
// except for the package declaration.
package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

// PedersenKey defines Com(ck, v; eta) = sum_i v[i] ck.G[i] + eta ck.H.
// The bases must have no efficiently known discrete-log relationships.
type PedersenKey struct {
	G []bn254.G1Affine
	H bn254.G1Affine
}

// CommitmentKey derives public bases with hash-to-curve.
// Size and role separate the message bases and the blinding base.
func CommitmentKey(size int) (PedersenKey, error) {
	if size <= 0 {
		return PedersenKey{}, fmt.Errorf("commitment key size must be positive")
	}
	const dst = "LED_PEDERSEN_BN254G1_XMD:SHA-256_SVDW_RO_V1"
	key := PedersenKey{G: make([]bn254.G1Affine, size)}
	derive := func(role byte, index uint64) (bn254.G1Affine, error) {
		var message [17]byte
		message[0] = role
		binary.BigEndian.PutUint64(message[1:9], uint64(size))
		binary.BigEndian.PutUint64(message[9:17], index)
		return bn254.HashToG1(message[:], []byte(dst))
	}
	for i := range key.G {
		point, err := derive('G', uint64(i))
		if err != nil {
			return PedersenKey{}, fmt.Errorf("derive commitment base %d: %w", i, err)
		}
		key.G[i] = point
	}
	var err error
	key.H, err = derive('H', 0)
	if err != nil {
		return PedersenKey{}, fmt.Errorf("derive blinding base: %w", err)
	}
	return key, nil
}

// Independent columns share the bases; each worker reuses its scalar buffer.
func commitColumns(key PedersenKey, columns [][]fr.Element, blindings []fr.Element) ([]bn254.G1Affine, error) {
	if len(key.G) == 0 || len(columns) != len(blindings) {
		return nil, fmt.Errorf("invalid column commitment key or blinding count")
	}
	for j, column := range columns {
		if len(column) != len(key.G) {
			return nil, fmt.Errorf("column %d: commitment width mismatch: key %d, values %d", j, len(key.G), len(column))
		}
	}
	points := make([]bn254.G1Affine, len(key.G)+1)
	copy(points, key.G)
	points[len(key.G)] = key.H
	commitments := make([]bn254.G1Affine, len(columns))
	errs := make([]error, len(columns))
	parallelRanges(len(columns), func(first, last int) {
		scalars := make([]fr.Element, len(points))
		for j := first; j < last; j++ {
			copy(scalars, columns[j])
			scalars[len(key.G)] = blindings[j]
			if _, err := commitments[j].MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: 1}); err != nil {
				errs[j] = err
				return
			}
		}
	})
	for j, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("commit column %d: %w", j, err)
		}
	}
	return commitments, nil
}

// Each worker owns a contiguous range. All workers finish before returning.
func parallelRanges(count int, work func(first, last int)) {
	workers := min(runtime.GOMAXPROCS(0), count)
	if workers == 0 {
		return
	}
	if workers == 1 {
		work(0, count)
		return
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		first, last := w*count/workers, (w+1)*count/workers
		wg.Add(1)
		go func() {
			defer wg.Done()
			work(first, last)
		}()
	}
	wg.Wait()
}

type rsCode struct {
	K, N    int
	domainK *fft.Domain
	domainN *fft.Domain
}

// The encoder stores only FFT domains. K and N must be supported powers of two,
// with 1 <= K <= N. In particular, it never allocates a K-by-N matrix.
func newRSCode(k, n int) (*rsCode, error) {
	if !isPowerOfTwo(k) || !isPowerOfTwo(n) || n < k {
		return nil, fmt.Errorf("encoder requires powers of two with 1 <= k <= n, got k=%d n=%d", k, n)
	}
	order := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	if new(big.Int).Mod(order, new(big.Int).SetUint64(uint64(n))).Sign() != 0 {
		return nil, fmt.Errorf("encoder domain size %d is unsupported by the scalar field", n)
	}
	return &rsCode{
		K: k, N: n,
		domainK: fft.NewDomain(uint64(k)),
		domainN: fft.NewDomain(uint64(n)),
	}, nil
}

// The caller owns the N-element scratch buffer; no shared encoder state is mutated.
func (e *rsCode) encodeInto(v, codeword []fr.Element, options ...fft.Option) {
	copy(codeword, v)
	coefficients := codeword[:e.K]
	e.domainK.FFTInverse(coefficients, fft.DIF, options...)
	fft.BitReverse(coefficients)

	// A reused buffer still contains the preceding row's evaluations here.
	clear(codeword[e.K:])
	e.domainN.FFT(codeword, fft.DIF, options...)
	fft.BitReverse(codeword)
}

// Matrices occupy consecutive K-element blocks in each preallocated column.
// Callers validate shapes; unused slots in a partial group remain zero.
func (e *rsCode) encodeMatricesInto(matrices [][][]fr.Element, columns [][]fr.Element) {
	parallelRanges(len(matrices)*e.K, func(first, last int) {
		scratch := make([]fr.Element, e.N)
		// Parallelize rows, rather than spawning FFT workers for every row.
		option := fft.WithNbTasks(1)
		for row := first; row < last; row++ {
			e.encodeInto(matrices[row/e.K][row%e.K], scratch, option)
			for j := range columns {
				columns[j][row] = scratch[j]
			}
		}
	})
}

// Allocate the final column layout once, including zero padding for unused slots.
func (e *rsCode) encodeMatrices(matrices [][][]fr.Element, height int) [][]fr.Element {
	columns := make([][]fr.Element, e.N)
	for j := range columns {
		columns[j] = make([]fr.Element, height)
	}
	e.encodeMatricesInto(matrices, columns)
	return columns
}

func randomBlindings(n int) ([]fr.Element, error) {
	blindings := make([]fr.Element, n)
	for i := range blindings {
		if _, err := blindings[i].SetRandom(); err != nil {
			return nil, err
		}
	}
	return blindings, nil
}

func isPowerOfTwo(n int) bool { return n > 0 && n&(n-1) == 0 }

type Digest [sha256.Size]byte

func merkleLeaf(point bn254.G1Affine, index, n, group int) Digest {
	hash := sha256.New()
	hash.Write([]byte("LED/generalized/MERKLE/LEAF/v1"))
	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[:8], uint64(n))
	binary.BigEndian.PutUint64(metadata[8:], uint64(index))
	binary.BigEndian.PutUint64(metadata[16:], uint64(group))
	hash.Write(metadata[:])
	encoded := point.Bytes()
	hash.Write(encoded[:])
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func merkleNode(left, right Digest) Digest {
	hash := sha256.New()
	hash.Write([]byte("LED/generalized/MERKLE/NODE/v1"))
	hash.Write(left[:])
	hash.Write(right[:])
	var digest Digest
	copy(digest[:], hash.Sum(nil))
	return digest
}

func merkleLevels(leaves []Digest) [][]Digest {
	levels := [][]Digest{leaves}
	for len(leaves) > 1 {
		parents := make([]Digest, len(leaves)/2)
		for i := range parents {
			parents[i] = merkleNode(leaves[2*i], leaves[2*i+1])
		}
		levels = append(levels, parents)
		leaves = parents
	}
	return levels
}
