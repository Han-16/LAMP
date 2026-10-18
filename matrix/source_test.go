package matrix

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareUsesSavedProductWithoutRecomputing(t *testing.T) {
	dir := t.TempDir()
	a := Matrix{testVector(1, 2), testVector(3, 4)}
	b := Matrix{testVector(5, 6), testVector(7, 8)}
	// Deliberately save a false C: loading must leave AB=C to the proof.
	c := New(2)
	path := FilePath(dir, 2)
	if err := Save(path, a, b, c); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"auto", "file"} {
		input, err := Prepare(2, source, dir)
		if err != nil {
			t.Fatal(err)
		}
		if input.Source != "file" || input.Path != path || input.Compute != 0 || input.Load <= 0 {
			t.Fatalf("wrong file input metadata: %+v", input)
		}
		for i := range c {
			assertVector(t, input.A[i], a[i])
			assertVector(t, input.B[i], b[i])
			assertVector(t, input.C[i], c[i])
		}
	}
}

func TestPrepareGeneratesOnlyWhenRequestedOrAbsent(t *testing.T) {
	dir := t.TempDir()
	for _, source := range []string{"auto", "generate"} {
		input, err := Prepare(3, source, dir)
		if err != nil {
			t.Fatal(err)
		}
		if input.Source != "generate" || input.Path != "" || input.Load != 0 || input.Compute <= 0 {
			t.Fatalf("wrong generated input metadata: %+v", input)
		}
		want := MatMulRect(input.A, input.B, 3, 3, 3)
		for i := range want {
			assertVector(t, input.C[i], want[i])
		}
	}
	if _, err := os.Stat(FilePath(dir, 3)); !os.IsNotExist(err) {
		t.Fatalf("in-memory preparation persisted a dataset: %v", err)
	}
	if _, err := Prepare(3, "file", dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("required missing file must fail: %v", err)
	}
	path := FilePath(dir, 3)
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(3, "auto", dir); err == nil {
		t.Fatal("auto silently replaced a malformed input")
	}
	if _, err := Prepare(3, "generate", dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "broken" {
		t.Fatal("generation overwrote an existing file")
	}
}

func TestPrepareRejectsBrokenLinksAndInvalidOptions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "absent"), FilePath(dir, 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(2, "auto", dir); err == nil {
		t.Fatal("broken dataset link caused automatic generation")
	}
	for _, tc := range []struct {
		k      int
		source string
	}{{0, "auto"}, {-1, "generate"}, {1 << 28, "file"}, {2, "unknown"}} {
		if _, err := Prepare(tc.k, tc.source, dir); err == nil {
			t.Fatalf("accepted invalid options: %+v", tc)
		}
	}
}
