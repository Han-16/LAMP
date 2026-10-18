package benchmark

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFreivaldsSplitAndRawAverages(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	path := filepath.Join(t.TempDir(), "freivalds.csv")
	set, err := InitFreivaldsCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, duration := range []float64{.001004, .001004, .001014} {
		err := AppendFreivaldsResultToCSV(set, FreivaldsResult{
			Repeat: i + 1, LogK: 2, Constraints: 771,
			MatrixSource: "file", MatrixPath: "k4.bin", MatrixLoadTime: .009,
			SetupTime: .003, ProveTime: duration, VerifyTime: .002,
			ProofSize:   292 + i,
			SetupMemory: Memory{RSSBytes: 1000 << 20, RSSAvailable: true, Measured: true},
			ProveMemory: Memory{RSSBytes: []uint64{2, 10, 4}[i] << 20, RSSAvailable: true, Measured: true},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(set.averagePath); !os.IsNotExist(err) {
		t.Fatal("premature summary")
	}
	if err := set.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	var runID string
	for _, suffix := range []string{"", "_info", "_memory"} {
		rows := readCSV(t, strings.TrimSuffix(path, ".csv")+suffix+".csv")
		if len(rows) != 4 {
			t.Fatalf("%s: want three measurements: %v", suffix, rows)
		}
		if runID == "" {
			runID = rows[1][0]
		}
		for i, row := range rows[1:] {
			cells := csvCells(rows[0], row)
			if cells["run_id"] != runID || cells["repeat"] != []string{"1", "2", "3"}[i] || cells["logk"] != "2" {
				t.Fatalf("unaligned repetition: %v", cells)
			}
			if cells["commit_mode"] != "" || cells["rho"] != "" {
				t.Fatal("invented protocol metadata")
			}
		}
	}
	raw := readCSV(t, path)
	if !slices.Equal(raw[0], lampCSVHeader) {
		t.Fatal("performance header differs from LAMP")
	}
	cells := csvCells(raw[0], raw[1])
	for _, name := range []string{"matrix_compute_time", "matrix_path", "peak", "PeakMemory(B)"} {
		if _, ok := cells[name]; ok {
			t.Fatalf("%s was not moved out of performance", name)
		}
	}
	for _, name := range []string{"protocol_setup_time", "cplink_setup_time", "pedersen_commit_time", "merkle_commit_time", "abc_commit_time", "vector_compute_time", "vector_commit_time", "commit_time", "encoding_time", "commit_other_time", "total_commit_time", "cplink_prove_time", "merkle_prove_time", "cplink_verify_time", "merkle_verify_time", "d_agg_msm_time", "q_h_msm_time", "verifier_msm_time"} {
		if cells[name] != "" {
			t.Fatalf("nonexistent phase %s=%q", name, cells[name])
		}
	}
	for name, want := range map[string]string{"snark_proof_bytes": "292", "total_proof_bytes": "292", "merkle_proof_bytes": "0", "cplink_proof_bytes": "0", "query_commitments_bytes": "0"} {
		if cells[name] != want {
			t.Errorf("%s=%q, want %q", name, cells[name], want)
		}
	}
	info := readCSV(t, filepath.Join(filepath.Dir(path), "freivalds_info.csv"))
	metadata := csvCells(info[0], info[1])
	if metadata["matrix_source"] != "file" || metadata["matrix_path"] != "k4.bin" || metadata["matrix_load_time"] != "9.00 ms" || metadata["samples"] != "" || metadata["n"] != "" {
		t.Fatalf("wrong input metadata: %v", metadata)
	}
	memory := readCSV(t, filepath.Join(filepath.Dir(path), "freivalds_memory.csv"))
	peaks := csvCells(memory[0], memory[1])
	if peaks["peak_setup"] != "1000.00 MiB" || peaks["peak_commit"] != "" || peaks["peak_prove"] != "2.00 MiB" || peaks["peak"] != peaks["peak_prove"] {
		t.Fatalf("wrong peaks: %v", peaks)
	}
	avg := readCSV(t, set.averagePath)
	mean := csvCells(avg[0], avg[1])
	for name, want := range map[string]string{
		"runs": "3", "circuit_setup_time": "3.00 ms", "total_setup_time": "3.00 ms",
		"circuit_prove_time": "1.01 ms", "total_prove_time": "1.01 ms", "commit_and_prove_time": "1.01 ms",
		"circuit_verify_time": "2.00 ms", "total_verify_time": "2.00 ms",
		"snark_proof_bytes": "293.00", "total_proof_bytes": "293.00",
		"peak_setup": "1000.00 MiB", "peak_commit": "", "peak_prove": "5.33 MiB", "peak": "5.33 MiB",
	} {
		if mean[name] != want {
			t.Errorf("average %s=%q, want %q", name, mean[name], want)
		}
	}
	// Append only the current invocation's averages, with a new identity.
	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	set, err = InitFreivaldsCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendFreivaldsResultToCSV(set, FreivaldsResult{LogK: 2, ProveTime: .123, ProofSize: 300}); err != nil {
		t.Fatal(err)
	}
	if err := set.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := set.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	avg = readCSV(t, set.averagePath)
	if len(avg) != 3 {
		t.Fatalf("unexpected appended summaries: %v", avg)
	}
	last := csvCells(avg[0], avg[2])
	if last["runs"] != "1" || last["run_id"] == runID || last["circuit_prove_time"] != "123.00 ms" || last["peak"] != "" {
		t.Fatalf("mixed invocations: %v", last)
	}
}

func TestFreivaldsVariantGroupingAndMissingRSS(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	for _, variant := range []string{"batch", "gpt2"} {
		t.Run(variant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.csv")
			init := InitFreivaldsBatchCSV
			if variant == "gpt2" {
				init = InitFreivaldsGPT2CSV
			}
			set, err := init(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, dimension := range []int{1, 2} {
				for repeat := 1; repeat <= 2; repeat++ {
					memory := Memory{RSSBytes: 8 << 20, Measured: true, RSSAvailable: repeat == 1}
					if variant == "batch" {
						err = AppendFreivaldsBatchResultToCSV(set, FreivaldsBatchResult{Repeat: repeat, LogK: 2, Batch: dimension, Constraints: 5, ProveMemory: memory})
					} else {
						err = AppendFreivaldsGPT2ResultToCSV(set, FreivaldsGPT2Result{Repeat: repeat, SeqLog: dimension, SeqLen: 1 << dimension, NumClaims: 36, Constraints: 5, ProveMemory: memory})
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := set.SaveAverages(); err != nil {
				t.Fatal(err)
			}
			if err := set.Close(); err != nil {
				t.Fatal(err)
			}
			avg := readCSV(t, set.averagePath)
			if len(avg) != 3 {
				t.Fatalf("configuration groups merged: %v", avg)
			}
			for _, row := range avg[1:] {
				cells := csvCells(avg[0], row)
				if cells["runs"] != "2" || cells["peak"] != "" || cells["peak_prove"] != "" || cells["peak_commit"] != "" {
					t.Fatalf("invalid missing-memory average: %v", cells)
				}
				if variant == "gpt2" && (cells["logk"] != "" || cells["n"] != "" || cells["num_claims"] != "36") {
					t.Fatalf("wrong rectangular dimensions: %v", cells)
				}
			}
		})
	}
}

func TestFreivaldsPartialAndIncompatibleOutput(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	path := filepath.Join(t.TempDir(), "result.csv")
	set, err := InitFreivaldsCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendFreivaldsResultToCSV(set, FreivaldsResult{LogK: 2, MatrixSource: "compile", Constraints: 9}); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(set.averagePath); !os.IsNotExist(err) {
		t.Fatal("partial run created summary")
	}
	raw := readCSV(t, path)
	cells := csvCells(raw[0], raw[1])
	for _, key := range lampTimingHeader {
		if cells[key] != "" {
			t.Fatalf("compile-only recorded %s", key)
		}
	}
	infoPath := filepath.Join(filepath.Dir(path), "result_info.csv")
	if err := os.Remove(infoPath); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	if _, err := InitFreivaldsCSV(path); err == nil {
		t.Fatal("accepted missing companion")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed append changed raw results")
	}
	legacy := "log(K),Constraint,PeakMemory(B)\n2,9,100\n"
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitFreivaldsCSV(path); err == nil || !strings.Contains(err.Error(), "header mismatch") {
		t.Fatalf("accepted legacy schema: %v", err)
	}
	after, _ = os.ReadFile(path)
	if string(after) != legacy {
		t.Fatal("legacy results were modified")
	}
}
