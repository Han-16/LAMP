package matrix

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatrixFiles(t *testing.T) {
	path := FilePath(t.TempDir(), 4)
	a, err := Random(4)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Random(4)
	if err != nil {
		t.Fatal(err)
	}
	c := Multiply(a, b)
	if err := Save(path, a, b, c); err != nil {
		t.Fatal(err)
	}
	aa, bb, cc, err := Load(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		assertVector(t, aa[i], a[i])
		assertVector(t, bb[i], b[i])
		assertVector(t, cc[i], c[i])
	}
	if err := Save(path, a, b, c); err == nil {
		t.Fatal("overwrote existing dataset")
	}
	if _, _, _, err := Load(path, 8); err == nil {
		t.Fatal("accepted wrong dimension")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated":    append([]byte{}, bytes[:len(bytes)-1]...),
		"trailing":     append(append([]byte{}, bytes...), 0),
		"header":       append([]byte{}, bytes...),
		"noncanonical": append([]byte{}, bytes...),
	}
	cases["header"][0] ^= 1
	for i := 16; i < 48; i++ {
		cases["noncanonical"][i] = 255
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			bad := filepath.Join(t.TempDir(), "bad.bin")
			if err := os.WriteFile(bad, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := Load(bad, 4); err == nil {
				t.Fatal("accepted invalid file")
			}
		})
	}
}
