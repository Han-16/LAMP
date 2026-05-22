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

func TestQABatchLinkRoundTrip(t *testing.T) {
	const (
		blockCount = 4
		blockLen   = 5
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

	pk, vk, err := SetupQABatchLink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	context := testQABatchContext(7, 11)
	proof, err := ProveQABatchLink(blocks, alpha, betas, pk, snarkCommit, externalCommits, context...)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if !VerifyQABatchLink(snarkCommit, externalCommits, proof, vk, context...) {
		t.Fatal("expected qa-batch-link proof to verify")
	}
}

func TestQABatchLinkRejectsMismatchedExternalCommitment(t *testing.T) {
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

	pk, vk, err := SetupQABatchLink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	context := testQABatchContext(3, 9)
	proof, err := ProveQABatchLink(blocks, alpha, betas, pk, snarkCommit, externalCommits, context...)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}

	var badBlinding fr.Element
	badBlinding.SetRandom()
	externalCommits[1] = PedersenCommitBlinded(randomBlocks(1, blockLen)[0], badBlinding, externalCK)
	if VerifyQABatchLink(snarkCommit, externalCommits, proof, vk, context...) {
		t.Fatal("expected qa-batch-link proof to reject a mismatched external commitment")
	}
}

func TestQABatchLinkRejectsDifferentContext(t *testing.T) {
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

	pk, vk, err := SetupQABatchLink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	context := testQABatchContext(1, 2)
	proof, err := ProveQABatchLink(blocks, alpha, betas, pk, snarkCommit, externalCommits, context...)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if VerifyQABatchLink(snarkCommit, externalCommits, proof, vk, testQABatchContext(1, 3)...) {
		t.Fatal("expected qa-batch-link proof to reject a different transcript context")
	}
}

func TestQABatchLinkRejectsMismatchedSnarkCommitment(t *testing.T) {
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

	pk, vk, err := SetupQABatchLink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	context := testQABatchContext(4, 8)
	proof, err := ProveQABatchLink(blocks, alpha, betas, pk, snarkCommit, externalCommits, context...)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}

	var badAlpha fr.Element
	badAlpha.SetRandom()
	badSnarkCommit := PedersenCommitBlinded(flattenBlocks(randomBlocks(blockCount, blockLen)), badAlpha, snarkCK)
	if VerifyQABatchLink(badSnarkCommit, externalCommits, proof, vk, context...) {
		t.Fatal("expected qa-batch-link proof to reject a mismatched snark commitment")
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

func testQABatchContext(values ...uint64) []fr.Element {
	out := make([]fr.Element, len(values))
	for i, value := range values {
		out[i].SetUint64(value)
	}
	return out
}
