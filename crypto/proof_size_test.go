package crypto

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestProofComponentSizesMatchCompressedEncoding(t *testing.T) {
	_, _, point, _ := bn254.Generators()
	for _, p := range []bn254.G1Affine{point, {}} {
		encoded := p.Bytes()
		if got := QALinkProofSizeBytes(QALinkProof{Pi: p}); got != len(encoded) {
			t.Fatalf("link bytes=%d, serialized=%d; want 32", got, len(encoded))
		}
	}
	if G1AffineSizeBytes != 32 {
		t.Fatal("BN254 G1 payload must use compressed encoding")
	}
	// Keep repeated query commitments, exactly as transmitted in the payload.
	queries := []bn254.G1Affine{point, point, point}
	payload := []byte{}
	for _, p := range queries {
		encoded := p.Bytes()
		payload = append(payload, encoded[:]...)
	}
	if len(queries)*G1AffineSizeBytes != len(payload) || len(payload) != 96 {
		t.Fatal("query commitment size differs from compressed payload")
	}
	proof := MerkleMultiProof{Siblings: make([]fr.Element, 2)}
	payload = nil
	for _, hash := range proof.Siblings {
		encoded := hash.Bytes()
		payload = append(payload, encoded[:]...)
	}
	if MerkleMultiProofSizeBytes(proof) != len(payload) || len(payload) != 64 {
		t.Fatal("Merkle size must count sibling hashes only")
	}
}
