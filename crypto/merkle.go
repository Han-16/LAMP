package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const MerkleHashSizeBytes = 32

type MerkleLeafMeta struct {
	GroupID uint64
	ItemID  uint64
	Index   uint64
}

type MerkleMultiProof struct {
	Siblings []Digest
}

// Merkle nodes retain all 32 SHA-256 bytes. Only the final root is reduced
// to Fr to preserve the existing MiMC/circuit interface.
func MerkleRootField(digest Digest) fr.Element {
	var root fr.Element
	root.SetBytes(digest[:])
	return root
}

func MerkleLeafHash(point bn254.G1Affine, index, count int) Digest {
	return merkleLeaf(point, index, count, 0)
}

func buildBaseMerkleTree(leaves []Digest, depth int) ([][]Digest, fr.Element) {
	if !validMerkleDepth(depth) || len(leaves) != 1<<depth {
		panic("Merkle depth does not match leaf count")
	}
	tree := merkleLevels(leaves)
	return tree, MerkleRootField(tree[depth][0])
}

func BuildMerkleTreeFromGroupElements(leaves []bn254.G1Affine, depth int) ([][]Digest, fr.Element) {
	hashes := make([]Digest, len(leaves))
	for i, leaf := range leaves {
		hashes[i] = MerkleLeafHash(leaf, i, len(leaves))
	}
	return buildBaseMerkleTree(hashes, depth)
}

func HashPointWithMeta(point bn254.G1Affine, meta MerkleLeafMeta) Digest {
	h := sha256.New()
	h.Write([]byte("LAMP/MERKLE/LEAF/META"))
	var metadata [24]byte
	binary.BigEndian.PutUint64(metadata[:8], meta.GroupID)
	binary.BigEndian.PutUint64(metadata[8:16], meta.ItemID)
	binary.BigEndian.PutUint64(metadata[16:], meta.Index)
	h.Write(metadata[:])
	encoded := point.Bytes()
	h.Write(encoded[:])
	var digest Digest
	copy(digest[:], h.Sum(nil))
	return digest
}

func validMerkleDepth(depth int) bool {
	return depth >= 0 && depth < strconv.IntSize-1
}

func VerifyMerkleProof(root fr.Element, leaf Digest, proof []Digest, index, depth int) bool {
	if !validMerkleDepth(depth) || len(proof) != depth || index < 0 || index >= 1<<depth {
		return false
	}
	for _, sibling := range proof {
		if index&1 == 0 {
			leaf = merkleNode(leaf, sibling)
		} else {
			leaf = merkleNode(sibling, leaf)
		}
		index /= 2
	}
	computed := MerkleRootField(leaf)
	return computed.Equal(&root)
}

func BuildMerkleTreeFromGroupElementsWithMeta(leaves []bn254.G1Affine, metas []MerkleLeafMeta) ([][]Digest, fr.Element, int) {
	if len(leaves) != len(metas) {
		panic("leaf and metadata counts must match")
	}

	paddedLen := nextPowerOfTwo(len(leaves))
	depth := log2(paddedLen)
	hashes := make([]Digest, paddedLen)
	for i, leaf := range leaves {
		hashes[i] = HashPointWithMeta(leaf, metas[i])
	}
	for i := len(leaves); i < paddedLen; i++ {
		var pad [8]byte
		binary.BigEndian.PutUint64(pad[:], uint64(i))
		hashes[i] = sha256.Sum256(append([]byte("LAMP/MERKLE/PAD"), pad[:]...))
	}

	tree, root := buildBaseMerkleTree(hashes, depth)
	return tree, root, depth
}

func GetMerkleProof(tree [][]Digest, idx, depth int) []Digest {
	proof := make([]Digest, depth)
	currIdx := idx
	for level := 0; level < depth; level++ {
		siblingIdx := currIdx ^ 1
		proof[level] = tree[level][siblingIdx]
		currIdx /= 2
	}
	return proof
}

func GetMerkleMultiProof(tree [][]Digest, indices []int, depth int) MerkleMultiProof {
	current := uniqueSortedIndices(indices)
	siblings := make([]Digest, 0)

	for level := 0; level < depth; level++ {
		known := make(map[int]struct{}, len(current))
		for _, idx := range current {
			known[idx] = struct{}{}
		}

		nextMap := make(map[int]struct{}, len(current))
		for _, idx := range current {
			siblingIdx := idx ^ 1
			if _, ok := known[siblingIdx]; !ok {
				siblings = append(siblings, tree[level][siblingIdx])
			}
			nextMap[idx/2] = struct{}{}
		}
		current = sortedKeys(nextMap)
	}

	return MerkleMultiProof{Siblings: siblings}
}

func VerifyMerkleMultiProof(root fr.Element, leafHashes []Digest, indices []int, proof MerkleMultiProof, depth int) bool {
	if !validMerkleDepth(depth) || len(leafHashes) != len(indices) || len(leafHashes) == 0 {
		return false
	}

	current := make(map[int]Digest, len(indices))
	leafCount := 1 << depth
	for i, idx := range indices {
		if idx < 0 || idx >= leafCount {
			return false
		}
		if existing, ok := current[idx]; ok {
			if existing != leafHashes[i] {
				return false
			}
			continue
		}
		current[idx] = leafHashes[i]
	}

	proofPos := 0
	for level := 0; level < depth; level++ {
		keys := sortedKeysFromHashes(current)
		next := make(map[int]Digest, len(keys))
		processed := make(map[int]struct{}, len(keys))

		for _, idx := range keys {
			if _, ok := processed[idx]; ok {
				continue
			}

			currHash := current[idx]
			siblingIdx := idx ^ 1
			var siblingHash Digest
			if knownSibling, ok := current[siblingIdx]; ok {
				siblingHash = knownSibling
				processed[siblingIdx] = struct{}{}
			} else {
				if proofPos >= len(proof.Siblings) {
					return false
				}
				siblingHash = proof.Siblings[proofPos]
				proofPos++
			}
			processed[idx] = struct{}{}

			var parent Digest
			if idx%2 == 0 {
				parent = merkleNode(currHash, siblingHash)
			} else {
				parent = merkleNode(siblingHash, currHash)
			}

			parentIdx := idx / 2
			if existing, ok := next[parentIdx]; ok {
				if existing != parent {
					return false
				}
			} else {
				next[parentIdx] = parent
			}
		}
		current = next
	}

	if proofPos != len(proof.Siblings) || len(current) != 1 {
		return false
	}
	computedRoot, ok := current[0]
	computedField := MerkleRootField(computedRoot)
	return ok && computedField.Equal(&root)
}

func MerkleMultiProofSizeBytes(proof MerkleMultiProof) int {
	return len(proof.Siblings) * MerkleHashSizeBytes
}

func uniqueSortedIndices(indices []int) []int {
	if len(indices) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(indices))
	for _, idx := range indices {
		seen[idx] = struct{}{}
	}
	return sortedKeys(seen)
}

func sortedKeys(values map[int]struct{}) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func sortedKeysFromHashes(values map[int]Digest) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

func nextPowerOfTwo(v int) int {
	if v <= 1 {
		return 1
	}
	out := 1
	for out < v {
		out <<= 1
	}
	return out
}

func log2(v int) int {
	out := 0
	for v > 1 {
		v >>= 1
		out++
	}
	return out
}
