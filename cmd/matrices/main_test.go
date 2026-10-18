package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/lamp/matrix"
)

func TestGenerateReusableCPUFile(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "timings.csv")
	if err := generate(dir, 2, 2, csvPath, "cpu", "", 2048); err != nil {
		t.Fatal(err)
	}
	a, b, c, err := matrix.Load(matrix.FilePath(dir, 4), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := matrix.CheckProductRandom(a, b, c); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(matrix.FilePath(dir, 4))
	if err != nil {
		t.Fatal(err)
	}
	if err := generate(dir, 2, 2, csvPath, "cpu", "", 2048); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(matrix.FilePath(dir, 4))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeated generation changed the saved dataset")
	}
	data, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil || len(rows) != 2 || rows[1][0] != "cpu" {
		t.Fatalf("expected one generation record: %v, %v", rows, err)
	}
	if got := strings.Join(rows[0], ","); got != strings.Join(csvHeader, ",") {
		t.Fatalf("wrong timing header: %s", got)
	}
}

func TestGenerationCSVRefusesIncompatibleHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.csv")
	if err := os.WriteFile(path, []byte("old,header\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := appendGenerationCSV(path, csvHeader, make([]string, len(csvHeader))); err == nil {
		t.Fatal("appended a generation row under an incompatible header")
	}
}
