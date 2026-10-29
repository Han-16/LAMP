package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestMerkleMultiProofRoundTrip(t *testing.T) {
	leaves := randomCommitments(16)
	tree, root := BuildMerkleTreeFromGroupElements(leaves, 4)
	indices := []int{1, 2, 3, 9, 14}
	proof := GetMerkleMultiProof(tree, indices, 4)

	leafHashes := make([]Digest, len(indices))
	for i, idx := range indices {
		leafHashes[i] = MerkleLeafHash(leaves[idx], idx, len(leaves))
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

	leafHashes := make([]Digest, len(indices))
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

func randomCommitments(count int) []bn254.G1Affine {
	ck := SetupCommitKey(1)
	out := make([]bn254.G1Affine, count)
	for i := range out {
		var value, blinding fr.Element
		value.SetRandom()
		blinding.SetRandom()
		out[i] = PedersenCommitBlinded([]fr.Element{value}, blinding, ck)
	}
	return out
}

func TestSHA256MerklePathsAndMalformedProofs(t *testing.T) {
	leaves := randomCommitments(8)
	tree, root := BuildMerkleTreeFromGroupElements(leaves, 3)
	for i := range leaves {
		leaf := MerkleLeafHash(leaves[i], i, len(leaves))
		path := GetMerkleProof(tree, i, 3)
		if !VerifyMerkleProof(root, leaf, path, i, 3) {
			t.Fatalf("path %d", i)
		}
		path[0][0] ^= 1
		if VerifyMerkleProof(root, leaf, path, i, 3) {
			t.Fatal("tampered sibling accepted")
		}
	}
	indices := []int{5, 1, 5}
	hashes := []Digest{tree[0][5], tree[0][1], tree[0][5]}
	proof := GetMerkleMultiProof(tree, indices, 3)
	if !VerifyMerkleMultiProof(root, hashes, indices, proof, 3) {
		t.Fatal("repeated query rejected")
	}
	for name, bad := range map[string]MerkleMultiProof{
		"truncated": {Siblings: proof.Siblings[:len(proof.Siblings)-1]},
		"extra":     {Siblings: append(append([]Digest(nil), proof.Siblings...), Digest{})},
	} {
		if VerifyMerkleMultiProof(root, hashes, indices, bad, 3) {
			t.Fatal(name)
		}
	}
	hashes[2][0] ^= 1
	if VerifyMerkleMultiProof(root, hashes, indices, proof, 3) {
		t.Fatal("conflicting duplicate accepted")
	}
	if VerifyMerkleMultiProof(root, hashes, indices, proof, -1) {
		t.Fatal("invalid depth accepted")
	}
}
