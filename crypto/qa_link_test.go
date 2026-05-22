package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestQALinkRoundTrip(t *testing.T) {
	const (
		blockCount = 3
		blockLen   = 4
	)

	snarkCK := SetupCommitKey(blockCount * blockLen)
	externalCK := SetupCommitKey(blockLen)
	blocks := randomBlocks(blockCount, blockLen)

	var alpha fr.Element
	alpha.SetRandom()
	betas := make([]fr.Element, blockCount)
	for i := range betas {
		betas[i].SetRandom()
	}

	snarkCommit := PedersenCommitBlinded(flattenBlocks(blocks), alpha, snarkCK)
	externalCommits := make([]bn254.G1Affine, blockCount)
	for i := range blocks {
		externalCommits[i] = PedersenCommitBlinded(blocks[i], betas[i], externalCK)
	}

	pk, vk, err := SetupQALink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proof, err := ProveQALink(blocks, alpha, betas, pk)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if !VerifyQALink(snarkCommit, externalCommits, proof, vk) {
		t.Fatal("expected qa-link proof to verify")
	}
}

func TestQALinkRejectsMismatchedExternalCommitment(t *testing.T) {
	const (
		blockCount = 2
		blockLen   = 3
	)

	snarkCK := SetupCommitKey(blockCount * blockLen)
	externalCK := SetupCommitKey(blockLen)
	blocks := randomBlocks(blockCount, blockLen)

	var alpha fr.Element
	alpha.SetRandom()
	betas := make([]fr.Element, blockCount)
	for i := range betas {
		betas[i].SetRandom()
	}

	snarkCommit := PedersenCommitBlinded(flattenBlocks(blocks), alpha, snarkCK)
	externalCommits := make([]bn254.G1Affine, blockCount)
	for i := range blocks {
		externalCommits[i] = PedersenCommitBlinded(blocks[i], betas[i], externalCK)
	}

	pk, vk, err := SetupQALink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proof, err := ProveQALink(blocks, alpha, betas, pk)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}

	var badBlinding fr.Element
	badBlinding.SetRandom()
	externalCommits[0] = PedersenCommitBlinded(randomBlocks(1, blockLen)[0], badBlinding, externalCK)
	if VerifyQALink(snarkCommit, externalCommits, proof, vk) {
		t.Fatal("expected qa-link proof to reject a mismatched external commitment")
	}
}

func randomBlocks(blockCount, blockLen int) [][]fr.Element {
	blocks := make([][]fr.Element, blockCount)
	for i := range blocks {
		blocks[i] = make([]fr.Element, blockLen)
		for j := range blocks[i] {
			blocks[i][j].SetRandom()
		}
	}
	return blocks
}
