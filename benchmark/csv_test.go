package benchmark

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCSVRejectsIncompatibleAppend(t *testing.T) {
	if path := os.Getenv("LAMP_TEST_OLD_CSV"); path != "" {
		t.Setenv("BENCHMARK_APPEND_CSV", "true")
		initCSV(path, []string{"new", "header"})
		return
	}
	path := filepath.Join(t.TempDir(), "old.csv")
	before := "old,header\nkeep,this\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInitCSVRejectsIncompatibleAppend$")
	cmd.Env = append(os.Environ(), "LAMP_TEST_OLD_CSV="+path)
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "CSV header mismatch") {
		t.Fatalf("expected incompatible append to fail: %v, %s", err, output)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != before {
		t.Fatal("incompatible append modified the existing CSV")
	}
}

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
