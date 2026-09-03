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

func TestQALinkRejectsSeparateOpenings(t *testing.T) {
	const (
		blockCount = 3
		blockLen   = 4
	)

	snarkCK := SetupCommitKey(blockCount * blockLen)
	externalCK := SetupCommitKey(blockLen)
	snarkBlocks := randomBlocks(blockCount, blockLen)
	externalBlocks := randomBlocks(blockCount, blockLen)

	var alpha fr.Element
	alpha.SetRandom()
	betas := make([]fr.Element, blockCount)
	for i := range betas {
		betas[i].SetRandom()
	}

	snarkCommit := PedersenCommitBlinded(flattenBlocks(snarkBlocks), alpha, snarkCK)
	externalCommits := make([]bn254.G1Affine, blockCount)
	for i := range externalBlocks {
		externalCommits[i] = PedersenCommitBlinded(externalBlocks[i], betas[i], externalCK)
	}

	pk, vk, err := SetupQALink(blockCount, blockLen, snarkCK, externalCK)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	proof, err := ProveQALink(snarkBlocks, alpha, betas, pk)
	if err != nil {
		t.Fatalf("prove failed: %v", err)
	}
	if VerifyQALink(snarkCommit, externalCommits, proof, vk) {
		t.Fatal("expected qa-link proof to reject separate snark and external openings")
	}
}

func TestQALinksBatchedRoundTrip(t *testing.T) {
	first := newQALinkTestInstance(t, 2, 3)
	second := newQALinkTestInstance(t, 4, 2)

	context := testLinkBatchContext(7, 11)
	if !VerifyQALinksBatched([]QALinkVerification{first, second}, context...) {
		t.Fatal("expected batched qa-link verification to accept")
	}

	second.ExternalCommits[0] = PedersenCommitBlinded(randomBlocks(1, 2)[0], randomElement(), SetupCommitKey(2))
	if VerifyQALinksBatched([]QALinkVerification{first, second}, context...) {
		t.Fatal("expected batched qa-link verification to reject a bad equation")
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

func newQALinkTestInstance(t *testing.T, blockCount, blockLen int) QALinkVerification {
	t.Helper()

	snarkCK := SetupCommitKey(blockCount * blockLen)
	externalCK := SetupCommitKey(blockLen)
	blocks := randomBlocks(blockCount, blockLen)

	alpha := randomElement()
	betas := make([]fr.Element, blockCount)
	for i := range betas {
		betas[i] = randomElement()
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

	return QALinkVerification{
		SnarkCommit:     snarkCommit,
		ExternalCommits: externalCommits,
		Proof:           proof,
		VK:              vk,
	}
}

func randomElement() fr.Element {
	var out fr.Element
	out.SetRandom()
	return out
}

func testLinkBatchContext(values ...uint64) []fr.Element {
	out := make([]fr.Element, len(values))
	for i, value := range values {
		out[i].SetUint64(value)
	}
	return out
}
