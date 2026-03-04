package main

import (
	"fmt"
	"math"
	"time"

	"github.com/Han-16/meow/rs"
	"github.com/Han-16/meow/utils"
)

func main() {
	// =========================================================================
	// 0. Initial Parameter Setup
	// =========================================================================
	K := 1 << 4                         // K x K matrix
	N := K << 1                         // Encode to K x N (N must be a power of 2 for FFT)
	depth := int(math.Log2(float64(N))) // Depth of the Merkle Tree
	L := 3                              // Number of random indices to extract

	fmt.Printf("🔥 [Protocol Start]: K = %d, N = %d, L = %d\n", K, N, L)

	// =========================================================================
	// 1. Generate K x K Matrix and Reed-Solomon Encoding (Row-wise)
	// =========================================================================
	fmt.Println("\n--- Step 1: Generating & RS Encoding Matrix ---")
	matrixKxK := utils.GenerateRandomMatrix(K, K)

	encoder := rs.NewEncoder(K, N)
	_, matrixKxN, err := encoder.EncodeMatrix(matrixKxK)
	if err != nil {
		fmt.Printf("❌ RS Encoding failed: %v\n", err)
		return
	}
	fmt.Printf("✅ KxK Matrix successfully encoded to KxN (Rows: %d, Cols: %d)\n", len(matrixKxN), len(matrixKxN[0]))

	// =========================================================================
	// 2. Column-wise Pedersen Commitments of K x N Matrix
	// =========================================================================
	fmt.Println("\n--- Step 2: Column-wise Pedersen Commitments ---")
	columnsNxK := utils.Transpose(matrixKxN, K, N)

	ck := utils.SetupCommitKey(K)
	fmt.Printf("✅ Commitment Key (ck) generated with %d bases\n", K)

	// =========================================================================
	// 3. Generate Merkle Tree Commitment (cm) from N Pedersen Commitments
	// =========================================================================
	fmt.Println("\n--- Step 3: Merkle Tree Commitment ---")
	startTime := time.Now()
	// Returns tree[level][idx], root, and all N commitments.
	tree, cm, commitments := utils.CommitMatrix(columnsNxK, ck, depth)
	fmt.Printf("✅ Merkle Tree built with root (cm): %v\n", cm)
	fmt.Printf("✅ Merkle Tree construction completed in %.3f seconds\n", time.Since(startTime).Seconds())

	// =========================================================================
	// 4. Extract L Random Indices using cm as seed
	// =========================================================================
	fmt.Println("\n--- Step 4: Extract L Random Indices ---")
	start := time.Now()
	// indices := make([]int, L)
	currentSeed := cm

	indices, err := utils.GenerateUniqueIndices(currentSeed, N, L)
	if err != nil {
		fmt.Printf("❌ Failed to generate unique indices: %v\n", err)
		return
	}
	fmt.Printf("✅ Generated %d random indices in %.6f seconds\n", L, time.Since(start).Seconds())

	// =========================================================================
	// 5 & 6. Generate & Verify Membership Proofs
	// =========================================================================
	fmt.Println("\n--- Step 5 & 6: Generate & Verify Merkle Proofs ---")
	startTime = time.Now()
	for _, idx := range indices {
		fmt.Printf("\n[Processing Random Index: %d]\n", idx)

		// Step 5: Generate Merkle path (Proof) for the given index
		proof := utils.GetMerkleProof(tree, idx, depth)

		// The original Pedersen commitment for the given index
		pedersenCommit := commitments[idx]

		fmt.Printf("   Pedersen Commitment: %v\n", pedersenCommit)
		fmt.Printf("   Proof (Path) Length: %d\n", len(proof))

		// Step 6: Verify membership using cm, Pedersen commitment, and Merkle path (Manual verification simulation)
		leafHash := utils.HashPoint(pedersenCommit) // Hash the group element into a field element
		currHash := leafHash
		currIdx := idx

		for level := 0; level < depth; level++ {
			sibling := proof[level]
			// Determine hash order based on whether current index is even (left node) or odd (right node)
			if currIdx%2 == 0 {
				currHash = utils.HashElements(currHash, sibling)
			} else {
				currHash = utils.HashElements(sibling, currHash)
			}
			currIdx /= 2 // Move to parent index
		}

		// Compare the final calculated root with cm (initially generated root)
		if currHash.Equal(&cm) {
			fmt.Printf("   ✅ Verification SUCCESS: Path logically matches the root (cm)!\n")
		} else {
			fmt.Printf("   ❌ Verification FAILED: Path mismatch!\n")
		}
	}
	fmt.Printf("✅ Membership verification completed in %.3f seconds\n", time.Since(startTime).Seconds())
}
