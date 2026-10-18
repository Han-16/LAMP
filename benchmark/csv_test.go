package benchmark

import (
	"encoding/csv"
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

func TestLAMPTimingColumns(t *testing.T) {
	tests := []struct {
		name  string
		write func(string)
	}{
		{"square", func(path string) {
			f, w := InitLAMPCSV(path)
			defer f.Close()
			AppendLAMPResultToCSV(w, LAMPResult{MatrixCommitTime: .011, VectorComputeTime: .013, VectorCommitTime: .017, EncodingTime: .007, CommitTime: .028, TotalCommitTime: .041, MerkleProveTime: .019, CircuitProveTime: .023, CPLinkProveTime: .029, TotalProveTime: .071, CommitAndProveTime: .112})
		}},
		{"batch", func(path string) {
			f, w := InitLAMPBATCHCSV(path)
			defer f.Close()
			AppendLAMPBATCHResultToCSV(w, LAMPBATCHResult{MatrixCommitTime: .011, VectorComputeTime: .013, VectorCommitTime: .017, EncodingTime: .007, CommitTime: .028, TotalCommitTime: .041, MerkleProveTime: .019, CircuitProveTime: .023, CPLinkProveTime: .029, TotalProveTime: .071, CommitAndProveTime: .112})
		}},
		{"gpt2", func(path string) {
			f, w := InitLAMPGPT2CSV(path)
			defer f.Close()
			AppendLAMPGPT2ResultToCSV(w, LAMPGPT2Result{MatrixCommitTime: .011, VectorComputeTime: .013, VectorCommitTime: .017, EncodingTime: .007, CommitTime: .028, TotalCommitTime: .041, MerkleProveTime: .019, CircuitProveTime: .023, CPLinkProveTime: .029, TotalProveTime: .071, CommitAndProveTime: .112})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BENCHMARK_APPEND_CSV", "false")
			path := filepath.Join(t.TempDir(), "timing.csv")
			tt.write(path)
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			rows, err := csv.NewReader(f).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || len(rows[0]) != len(rows[1]) {
				t.Fatal("invalid CSV shape")
			}
			cells := map[string]string{}
			for i, key := range rows[0] {
				if _, ok := cells[key]; ok {
					t.Fatalf("duplicate header %s", key)
				}
				cells[key] = rows[1][i]
			}
			for key, sec := range map[string]float64{"abc_commit_time": .011, "vector_compute_time": .013, "vector_commit_time": .017, "encoding_time": .007, "commit_time": .028, "total_commit_time": .041, "merkle_prove_time": .019, "circuit_prove_time": .023, "cplink_prove_time": .029, "total_prove_time": .071, "commit_and_prove_time": .112} {
				if cells[key] != formatSeconds(sec) {
					t.Errorf("%s=%q, want %q", key, cells[key], formatSeconds(sec))
				}
			}
		})
	}
}
