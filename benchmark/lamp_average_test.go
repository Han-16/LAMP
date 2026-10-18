package benchmark

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func csvCells(header, row []string) map[string]string {
	cells := make(map[string]string, len(header))
	for i, name := range header {
		cells[name] = row[i]
	}
	return cells
}

func TestLAMPAveragesUseRawValuesAndCurrentInvocation(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	path := filepath.Join(t.TempDir(), "repeated.csv")
	set, err := InitLAMPCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, duration := range []float64{.001004, .001004, .001014} {
		r := LAMPResult{Repeat: i + 1, LogK: 2, N: 8, Rho: "1/2", NumQueries: 3,
			MatrixSource: "file", MatrixPath: "k4.bin", MatrixLoadTime: .009,
			CircuitProveTime: duration, ProtocolSetupTime: float64(i+1) * .5,
			MerkleProofSize: []int{64, 96, 97}[i],
			SetupMemory:     Memory{HeapBytes: uint64(i+1) << 20, RSSBytes: 4 << 20, Measured: true, RSSAvailable: i != 1},
			CommitMemory:    Memory{HeapBytes: 5 << 20, RSSBytes: 6 << 20, Measured: true, RSSAvailable: true}}
		if err := AppendLAMPResultToCSV(set, r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(set.averagePath); !os.IsNotExist(err) {
		t.Fatal("summary created before completion")
	}
	if err := set.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := set.SaveAverages(); err != nil {
		t.Fatal(err)
	} // No duplicate summary on a second call.
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, set.averagePath)
	if len(rows) != 2 || len(rows[1]) != len(set.averageHeader) {
		t.Fatalf("unexpected summary shape: %v", rows)
	}
	first := csvCells(rows[0], rows[1])
	for name, want := range map[string]string{
		"run_id": set.runID, "runs": "3", "logk": "2", "matrix_load_time": "9.00 ms",
		"circuit_prove_time": "1.01 ms", "protocol_setup_time": "1.00 s", "merkle_proof_bytes": "85.67",
		"setup_peak_heap": "2.00 MiB", "setup_peak_rss": "", "commit_peak_rss": "6.00 MiB", "prove_peak_heap": "",
		"d_agg_msm_time": "", "q_h_msm_time": "", "verifier_msm_time": "",
	} {
		if first[name] != want {
			t.Errorf("%s=%q, want %q", name, first[name], want)
		}
	}
	for _, suffix := range []string{"", "_info", "_memory"} {
		raw := readCSV(t, filepath.Join(filepath.Dir(path), "repeated"+suffix+".csv"))
		if len(raw) != 4 {
			t.Fatal("lost individual repetitions")
		}
		for i, row := range raw[1:] {
			cells := csvCells(raw[0], row)
			if cells["repeat"] != strconv.Itoa(i+1) || cells["run_id"] != set.runID || cells["commit_mode"] != "legacy" {
				t.Fatal("raw file identities disagree")
			}
		}
	}
	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	next, err := InitLAMPCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendLAMPResultToCSV(next, LAMPResult{LogK: 2, Rho: "1/2", CircuitProveTime: .099}); err != nil {
		t.Fatal(err)
	}
	if err := next.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	rows = readCSV(t, next.averagePath)
	last := csvCells(rows[0], rows[2])
	if len(rows) != 3 || last["runs"] != "1" || last["circuit_prove_time"] != "99.00 ms" || last["run_id"] == first["run_id"] {
		t.Fatal("appended run mixed with previous measurements")
	}
}

func TestLAMPAverageGroupsAndFailure(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	path := filepath.Join(t.TempDir(), "batch.csv")
	set, err := InitLAMPBATCHCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, logk := range []int{2, 3} {
		for repetition := 1; repetition <= 3; repetition++ {
			for _, batch := range []int{1, 5} {
				if err := AppendLAMPBATCHResultToCSV(set, LAMPBATCHResult{Repeat: repetition, LogK: logk, Batch: batch}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := set.SaveAverages(); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, set.averagePath)
	if len(rows) != 5 {
		t.Fatalf("got %d groups, want 4", len(rows)-1)
	}
	for i, row := range rows[1:] {
		cells := csvCells(rows[0], row)
		if cells["runs"] != "3" || cells["logk"] != strconv.Itoa(2+i/2) || cells["batch"] != []string{"1", "5"}[i%2] {
			t.Fatal("configuration groups mixed or reordered")
		}
	}
	// Starting a fresh invocation clears its predecessor's average. Closing
	// after a failed/incomplete invocation must preserve only the raw results.
	next, err := InitLAMPBATCHCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendLAMPBATCHResultToCSV(next, LAMPBATCHResult{Repeat: 1, LogK: 2, Batch: 1}); err != nil {
		t.Fatal(err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(next.averagePath); !os.IsNotExist(err) {
		t.Fatal("incomplete invocation left a summary")
	}
	if rows := readCSV(t, path); len(rows) != 2 {
		t.Fatal("incomplete invocation lost successful raw row")
	}
}

func TestLAMPRejectsIncompatibleAverageBeforeAppend(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	path := filepath.Join(t.TempDir(), "lamp.csv")
	set, err := InitLAMPCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendLAMPResultToCSV(set, LAMPResult{}); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(set.averagePath, []byte("old,header\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	if _, err := InitLAMPCSV(path); err == nil {
		t.Fatal("accepted incompatible average schema")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("failed preflight modified raw output")
	}
}
