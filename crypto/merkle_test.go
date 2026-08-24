package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestMerkleMultiProofRoundTrip(t *testing.T) {
	leaves := randomCommitments(16)
	tree, root := BuildMerkleTreeFromGroupElements(leaves, 4)
	indices := []int{1, 2, 3, 9, 14}
	proof := GetMerkleMultiProof(tree, indices, 4)

	leafHashes := make([]fr.Element, len(indices))
	for i, idx := range indices {
		leafHashes[i] = HashPoint(leaves[idx])
	}

	if !VerifyMerkleMultiProof(root, leafHashes, indices, proof, 4) {
		t.Fatal("valid multiproof did not verify")
	}

	independentSize := len(indices) * 4 * MerkleHashSizeBytes
	if got := MerkleMultiProofSizeBytes(proof); got >= independentSize {
		t.Fatalf("expected multiproof smaller than independent paths, got %d >= %d", got, independentSize)
	}
}

func TestMerkleMultiProofWithMetaRejectsTamperedLeaf(t *testing.T) {
	leaves := randomCommitments(9)
	metas := make([]MerkleLeafMeta, len(leaves))
	for i := range metas {
		metas[i] = MerkleLeafMeta{GroupID: 7, ItemID: uint64(i / 3), Index: uint64(i)}
	}
	tree, root, depth := BuildMerkleTreeFromGroupElementsWithMeta(leaves, metas)
	indices := []int{0, 4, 8}
	proof := GetMerkleMultiProof(tree, indices, depth)

	leafHashes := make([]fr.Element, len(indices))
	for i, idx := range indices {
		leafHashes[i] = HashPointWithMeta(leaves[idx], metas[idx])
	}
	if !VerifyMerkleMultiProof(root, leafHashes, indices, proof, depth) {
		t.Fatal("valid metadata multiproof did not verify")
	}

	leafHashes[1] = HashPointWithMeta(leaves[4], MerkleLeafMeta{GroupID: 99, ItemID: 4, Index: 4})
	if VerifyMerkleMultiProof(root, leafHashes, indices, proof, depth) {
		t.Fatal("tampered metadata multiproof verified")
	}
}

func randomCommitments(count int) []bls12381.G1Affine {
	ck := SetupCommitKey(1)
	out := make([]bls12381.G1Affine, count)
	for i := range out {
		var value, blinding fr.Element
		value.SetRandom()
		blinding.SetRandom()
		out[i] = PedersenCommitBlinded([]fr.Element{value}, blinding, ck)
	}
	return out
}
