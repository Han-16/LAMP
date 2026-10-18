package matrix

import (
	"os"
	"path/filepath"
	"testing"
)

// Called with the independently compiled host helper from gpu_test.go.
func testGPUFiles(t *testing.T, helper string) {
	t.Helper()
	for _, tc := range []struct{ k, block int }{{1, 4}, {7, 3}, {8, 4}} {
		path := FilePath(t.TempDir(), tc.k)
		stats, err := GenerateGPUFile(path, tc.k, tc.block, "cuda", helper, nil)
		if err != nil {
			t.Fatal(err)
		}
		if stats.GPU.Device != "HOST TEST ONLY" {
			t.Fatal("missing block metrics")
		}
		a, b, c, err := Load(path, tc.k)
		if err != nil {
			t.Fatal(err)
		}
		want := MultiplyWithWorkers(a, b, 1)
		for i := range c {
			assertVector(t, c[i], want[i])
		}
		if _, err := GenerateGPUFile(path, tc.k, tc.block, "cuda", helper, nil); err == nil {
			t.Fatal("overwrote existing dataset")
		}
		// The disk check must reject a changed result, independently of the GPU.
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		one := testVector(1)[0]
		for i := range c {
			c[i][i].Add(&c[i][i], &one)
		}
		if err := writeGPUFileBlock(f, tc.k, 0, 0, c); err != nil {
			t.Fatal(err)
		}
		if err := checkGPUFileProduct(f, tc.k); err == nil {
			t.Fatal("corrupted file product passed")
		}
		f.Close()
	}
	dir := t.TempDir()
	path := FilePath(dir, 7)
	if _, err := GenerateGPUFile(path, 7, 3, "cuda", filepath.Join(dir, "absent"), nil); err == nil {
		t.Fatal("missing helper accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed generation left files: %v, %v", entries, err)
	}
	for _, tc := range []struct{ k, block int }{{0, 3}, {7, 0}, {7, 4097}, {1 << 28, 2048}} {
		if _, err := GenerateGPUFile(path, tc.k, tc.block, "cuda", helper, nil); err == nil {
			t.Fatalf("accepted invalid dimensions: %+v", tc)
		}
	}
}
