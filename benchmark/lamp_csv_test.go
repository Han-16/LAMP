package benchmark

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestLAMPCSVSplit(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	path := filepath.Join(t.TempDir(), "lamp.csv")
	set, err := InitLAMPCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	res := LAMPResult{
		LogK: 7, Rho: "1/2", N: 256, NumQueries: 309, Constraints: 771,
		Linker: "qa_link", Merkle: "multi", MatrixSource: "file", MatrixPath: "matrices/k128.bin", MatrixLoadTime: .00381,
		ProtocolSetupTime: .001, CircuitSetupTime: .002, CPLinkSetupTime: .003, SetupTime: .006,
		PedersenCommitTime: .008, MerkleCommitTime: .003, EncodingTime: .007,
		MatrixCommitTime: .018, VectorComputeTime: .013, VectorCommitTime: .017,
		CommitTime: .035, CommitOtherTime: .005, TotalCommitTime: .048,
		CircuitProveTime: .029, CPLinkProveTime: .037, MerkleProveTime: .019, TotalProveTime: .085, CommitAndProveTime: .133,
		CircuitVerifyTime: .001, CPLinkVerifyTime: .002, MerkleVerifyTime: .003, TotalVerifyTime: .007,
		Groth16ProofSize: 292, MerkleProofSize: 64, CPLinkProofSize: 64, QueryCommitmentsSize: 128, TotalProofSize: 548,
		SetupMemory:  Memory{HeapBytes: 128 << 20, RSSBytes: 1536 << 20, RSSAvailable: true, Measured: true},
		CommitMemory: Memory{HeapBytes: 1 << 30, Measured: true},
	}
	if err := AppendLAMPResultToCSV(set, res); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	wantHeader := strings.Split("run_id,repeat,commit_mode,logk,rho,constraint,protocol_setup_time,circuit_setup_time,cplink_setup_time,total_setup_time,pedersen_commit_time,merkle_commit_time,abc_commit_time,vector_compute_time,vector_commit_time,commit_time,encoding_time,commit_other_time,total_commit_time,circuit_prove_time,cplink_prove_time,merkle_prove_time,total_prove_time,commit_and_prove_time,circuit_verify_time,cplink_verify_time,merkle_verify_time,d_agg_msm_time,q_h_msm_time,verifier_msm_time,total_verify_time,snark_proof_bytes,merkle_proof_bytes,cplink_proof_bytes,query_commitments_bytes,total_proof_bytes", ",")
	rows := readCSV(t, path)
	if !slices.Equal(rows[0], wantHeader) {
		t.Fatalf("performance schema differs from LED: %v", rows[0])
	}
	want := []string{set.runID, "1", "legacy", "7", "1/2", "771", "1.00 ms", "2.00 ms", "3.00 ms", "6.00 ms", "8.00 ms", "3.00 ms", "18.00 ms", "13.00 ms", "17.00 ms", "35.00 ms", "7.00 ms", "5.00 ms", "48.00 ms", "29.00 ms", "37.00 ms", "19.00 ms", "85.00 ms", "133.00 ms", "1.00 ms", "2.00 ms", "3.00 ms", "", "", "", "7.00 ms", "292", "64", "64", "128", "548"}
	if !slices.Equal(rows[1], want) {
		t.Fatalf("wrong performance row: %v", rows[1])
	}
	info := readCSV(t, filepath.Join(filepath.Dir(path), "lamp_info.csv"))
	if !slices.Equal(info[0][:11], strings.Split("run_id,repeat,commit_mode,logk,rho,samples,matrix_source,matrix_path,matrix_workers,matrix_compute_time,matrix_load_time", ",")) {
		t.Fatal("wrong LED info columns")
	}
	if !slices.Equal(info[1], []string{set.runID, "1", "legacy", "7", "1/2", "309", "file", "matrices/k128.bin", "0", "0.00 ms", "3.81 ms", "qa_link", "multi", "256"}) {
		t.Fatalf("wrong info row: %v", info[1])
	}
	memory := readCSV(t, filepath.Join(filepath.Dir(path), "lamp_memory.csv"))
	if !slices.Equal(memory[0], strings.Split("run_id,repeat,commit_mode,logk,rho,setup_peak_heap,setup_peak_rss,commit_peak_heap,commit_peak_rss,prove_peak_heap,prove_peak_rss", ",")) {
		t.Fatal("wrong LED memory columns")
	}
	if !slices.Equal(memory[1], []string{set.runID, "1", "legacy", "7", "1/2", "128.00 MiB", "1.50 GiB", "1.00 GiB", "", "", ""}) {
		t.Fatalf("wrong memory row: %v", memory[1])
	}

	// A second session appends exactly one aligned row to each companion.
	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	set, err = InitLAMPCSV(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := AppendLAMPResultToCSV(set, res); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{"lamp.csv", "lamp_info.csv", "lamp_memory.csv"} {
		if rows := readCSV(t, filepath.Join(filepath.Dir(path), filename)); len(rows) != 3 {
			t.Fatalf("misaligned %s: %d rows", filename, len(rows))
		}
	}
	infoPath := filepath.Join(filepath.Dir(path), "lamp_info.csv")
	if err := os.Remove(infoPath); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := InitLAMPCSV(path); err == nil {
		t.Fatal("accepted missing companion")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("failed append modified performance data")
	}
}

func TestLAMPVariantCSVs(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "false")
	for _, variant := range []string{"batch", "gpt2"} {
		t.Run(variant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "result.csv")
			var set *LAMPCSV
			var err error
			var extraHeader, extraRow []string
			if variant == "batch" {
				set, err = InitLAMPBATCHCSV(path)
				if err != nil {
					t.Fatal(err)
				}
				err = AppendLAMPBATCHResultToCSV(set, LAMPBATCHResult{LogK: 2, Rho: "1/2", Batch: 5, VectorComputeTime: .013, QueryCommitmentsSize: 128})
				extraHeader, extraRow = []string{"batch"}, []string{"5"}
			} else {
				set, err = InitLAMPGPT2CSV(path)
				if err != nil {
					t.Fatal(err)
				}
				err = AppendLAMPGPT2ResultToCSV(set, LAMPGPT2Result{SeqLog: 1, SeqLen: 2, Rho: "1/2", NumClaims: 36, NumCommitGroups: 5, VectorComputeTime: .013, QueryCommitmentsSize: 128})
				extraHeader, extraRow = []string{"seq_log", "seq_len", "num_claims", "num_commit_groups"}, []string{"1", "2", "36", "5"}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := set.Close(); err != nil {
				t.Fatal(err)
			}
			rows := readCSV(t, path)
			if !slices.Equal(rows[0], lampCSVHeader) || rows[1][13] != "13.00 ms" || rows[1][34] != "128" {
				t.Fatalf("wrong variant performance: %v", rows)
			}
			info := readCSV(t, filepath.Join(filepath.Dir(path), "result_info.csv"))
			n := len(lampInfoCSVHeader)
			if !slices.Equal(info[0][n:], extraHeader) || !slices.Equal(info[1][n:], extraRow) {
				t.Fatalf("lost variant metadata: %v", info)
			}
			if variant == "gpt2" && (rows[1][3] != "" || info[1][3] != "" || info[1][13] != "") {
				t.Fatal("GPT-2 has no single square K/N")
			}
		})
	}
}

func TestLAMPCSVRejectsOldHeader(t *testing.T) {
	t.Setenv("BENCHMARK_APPEND_CSV", "true")
	path := filepath.Join(t.TempDir(), "old.csv")
	before := "LogK,Rho\n7,1/2\n"
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InitLAMPCSV(path); err == nil || !strings.Contains(err.Error(), "CSV header mismatch") {
		t.Fatalf("accepted old schema: %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != before {
		t.Fatal("old data was modified")
	}
}

func TestLEDDurationFormat(t *testing.T) {
	for seconds, want := range map[float64]string{0: "0.00 ms", .000001: "0.00 ms", .001: "1.00 ms", .01: "10.00 ms", .999: "999.00 ms", 1: "1.00 s", 1.234: "1.23 s"} {
		if got := FormatDurationSeconds(seconds); got != want {
			t.Errorf("%g seconds: %s, want %s", seconds, got, want)
		}
	}
}
