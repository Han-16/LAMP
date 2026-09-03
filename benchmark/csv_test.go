package benchmark

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCSVAppendsWithoutRepeatingHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.csv")
	header := []string{"value"}

	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	file, writer := initCSV(path, header)
	if err := writer.Write([]string{"first"}); err != nil {
		t.Fatal(err)
	}
	writer.Flush()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	file, writer = initCSV(path, header)
	if err := writer.Write([]string{"second"}); err != nil {
		t.Fatal(err)
	}
	writer.Flush()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(data)), "value\nfirst\nsecond"; got != want {
		t.Fatalf("unexpected CSV contents:\n%s", got)
	}
}
