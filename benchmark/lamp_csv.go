package benchmark

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Metric names and ordering match LED's individual and average CSVs.
var lampTimingHeader = []string{
	"protocol_setup_time", "circuit_setup_time", "cplink_setup_time", "total_setup_time",
	"pedersen_commit_time", "merkle_commit_time", "abc_commit_time", "vector_compute_time", "vector_commit_time",
	"commit_time", "encoding_time", "commit_other_time", "total_commit_time",
	"circuit_prove_time", "cplink_prove_time", "merkle_prove_time", "total_prove_time", "commit_and_prove_time",
	"circuit_verify_time", "cplink_verify_time", "merkle_verify_time", "d_agg_msm_time", "q_h_msm_time", "verifier_msm_time", "total_verify_time",
}
var lampProofSizeHeader = []string{
	"snark_proof_bytes", "merkle_proof_bytes", "cplink_proof_bytes", "query_commitments_bytes", "total_proof_bytes",
}
var lampMemoryMetricHeader = []string{
	"setup_peak_heap", "setup_peak_rss", "commit_peak_heap", "commit_peak_rss", "prove_peak_heap", "prove_peak_rss",
}
var lampCSVHeader = slices.Concat(
	[]string{"run_id", "repeat", "commit_mode", "logk", "rho", "constraint"}, lampTimingHeader, lampProofSizeHeader,
)
var lampInfoCSVHeader = []string{
	"run_id", "repeat", "commit_mode", "logk", "rho", "samples", "matrix_source", "matrix_path",
	"matrix_workers", "matrix_compute_time", "matrix_load_time", "linker", "merkle", "n",
}
var lampMemoryCSVHeader = slices.Concat(
	[]string{"run_id", "repeat", "commit_mode", "logk", "rho"}, lampMemoryMetricHeader,
)

// LAMPCSV owns one aligned performance/info/memory file set. Use one writer per set.
type LAMPCSV struct {
	files         []*os.File
	writers       []*csv.Writer
	gpt2          bool
	runID         string
	averagePath   string
	averageHeader []string
	appendResults bool
	averagesSaved bool
	groups        map[string]*lampAverageGroup
	groupOrder    []*lampAverageGroup
}

func InitLAMPCSV(path string) (*LAMPCSV, error) {
	return initLAMPCSV(path, nil, false)
}

func InitLAMPBATCHCSV(path string) (*LAMPCSV, error) {
	return initLAMPCSV(path, []string{"batch"}, false)
}

func InitLAMPGPT2CSV(path string) (*LAMPCSV, error) {
	return initLAMPCSV(path, []string{"seq_log", "seq_len", "num_claims", "num_commit_groups"}, true)
}

func initLAMPCSV(path string, extraInfo []string, gpt2 bool) (*LAMPCSV, error) {
	stem := strings.TrimSuffix(path, filepath.Ext(path))
	paths := []string{path, stem + "_info.csv", stem + "_memory.csv"}
	headers := [][]string{lampCSVHeader, append(slices.Clone(lampInfoCSVHeader), extraInfo...), lampMemoryCSVHeader}
	appendResults, _ := strconv.ParseBool(os.Getenv("BENCHMARK_APPEND_CSV"))
	averagePath := stem + "_average.csv"
	averageHeader := slices.Concat([]string{
		"run_id", "logk", "rho", "samples", "commit_mode", "runs", "constraint",
		"matrix_source", "matrix_path", "matrix_workers", "matrix_compute_time", "matrix_load_time",
	}, lampTimingHeader, lampProofSizeHeader, lampMemoryMetricHeader, []string{"linker", "merkle", "n"}, extraInfo)
	counts := make([]int, len(paths))
	if appendResults {
		for i, filename := range paths {
			count, err := csvRowCount(filename, headers[i])
			if err != nil {
				return nil, fmt.Errorf("check CSV %s: %w", filename, err)
			}
			counts[i] = count
			if i > 0 && counts[i] != counts[0] {
				return nil, fmt.Errorf("CSV row counts differ; keep all three files together or choose a new output directory")
			}
		}
	}
	if appendResults {
		if _, err := csvRowCount(averagePath, averageHeader); err != nil {
			return nil, fmt.Errorf("check average CSV: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	// A fresh run replaces the output set, including any previous summary.
	if !appendResults {
		if err := os.Remove(averagePath); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	set := &LAMPCSV{gpt2: gpt2, runID: time.Now().UTC().Format("20060102T150405.000000000Z"),
		averagePath: averagePath, averageHeader: averageHeader, appendResults: appendResults, groups: make(map[string]*lampAverageGroup)}
	for i, filename := range paths {
		flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		if appendResults {
			flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		}
		f, err := os.OpenFile(filename, flags, 0666)
		if err != nil {
			set.Close()
			return nil, err
		}
		set.files = append(set.files, f)
		w := csv.NewWriter(f)
		set.writers = append(set.writers, w)
		stat, err := f.Stat()
		if err != nil {
			set.Close()
			return nil, err
		}
		if stat.Size() == 0 {
			if err := w.Write(headers[i]); err != nil {
				set.Close()
				return nil, err
			}
			w.Flush()
			if err := w.Error(); err != nil {
				set.Close()
				return nil, err
			}
		}
	}
	writeSystemInfoForCSV(path)
	return set, nil
}

func csvRowCount(path string, header []string) (int, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	existing, err := r.Read()
	if err == io.EOF {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !slices.Equal(existing, header) {
		return 0, fmt.Errorf("CSV header mismatch; choose a new output directory")
	}
	for count := 0; ; count++ {
		if _, err := r.Read(); err == io.EOF {
			return count, nil
		} else if err != nil {
			return 0, err
		}
	}
}

func (set *LAMPCSV) Close() error {
	var err error
	for i, f := range set.files {
		set.writers[i].Flush()
		err = errors.Join(err, set.writers[i].Error(), f.Close())
	}
	return err
}

func (res LAMPResult) timings() []float64 {
	return []float64{
		res.ProtocolSetupTime, res.CircuitSetupTime, res.CPLinkSetupTime, res.SetupTime,
		res.PedersenCommitTime, res.MerkleCommitTime, res.MatrixCommitTime, res.VectorComputeTime, res.VectorCommitTime,
		res.CommitTime, res.EncodingTime, res.CommitOtherTime, res.TotalCommitTime,
		res.CircuitProveTime, res.CPLinkProveTime, res.MerkleProveTime, res.TotalProveTime, res.CommitAndProveTime,
		res.CircuitVerifyTime, res.CPLinkVerifyTime, res.MerkleVerifyTime,
		math.NaN(), math.NaN(), math.NaN(), res.TotalVerifyTime,
	}
}

func (res LAMPResult) proofSizes() []int {
	return []int{res.Groth16ProofSize, res.MerkleProofSize, res.CPLinkProofSize, res.QueryCommitmentsSize, res.TotalProofSize}
}

func optionalSeconds(seconds float64) string {
	// LED's separate verifier MSM phases do not exist in LAMP.
	if math.IsNaN(seconds) {
		return ""
	}
	return formatSeconds(seconds)
}

func (set *LAMPCSV) dimensions(res LAMPResult) (string, string) {
	// Rectangular tensors have no single square K or N.
	if set.gpt2 {
		return "", ""
	}
	return strconv.Itoa(res.LogK), strconv.Itoa(res.N)
}

func (set *LAMPCSV) append(res LAMPResult, extraInfo []string) error {
	if set.averagesSaved {
		return fmt.Errorf("cannot append measurements after saving averages")
	}
	if res.Repeat < 1 {
		res.Repeat = 1
	}
	logk, n := set.dimensions(res)
	// Encoded-column MSM commitments correspond to LED's legacy algorithm.
	identity := []string{set.runID, strconv.Itoa(res.Repeat), "legacy", logk, res.Rho}
	record := append(slices.Clone(identity), strconv.Itoa(res.Constraints))
	for _, value := range res.timings() {
		record = append(record, optionalSeconds(value))
	}
	for _, value := range res.proofSizes() {
		record = append(record, strconv.Itoa(value))
	}
	info := append(slices.Clone(identity), strconv.Itoa(res.NumQueries), res.MatrixSource, res.MatrixPath,
		strconv.Itoa(res.MatrixWorkers), formatSeconds(res.MatrixComputeTime), formatSeconds(res.MatrixLoadTime), res.Linker, res.Merkle, n)
	info = append(info, extraInfo...)
	memory := slices.Clone(identity)
	for _, m := range []Memory{res.SetupMemory, res.CommitMemory, res.ProveMemory} {
		heap, rss := "", ""
		if m.Measured {
			heap = memorySize(m.HeapBytes)
		}
		if m.Measured && m.RSSAvailable {
			rss = memorySize(m.RSSBytes)
		}
		memory = append(memory, heap, rss)
	}
	for i, row := range [][]string{record, info, memory} {
		if err := set.writers[i].Write(row); err != nil {
			return err
		}
		set.writers[i].Flush()
		if err := set.writers[i].Error(); err != nil {
			return err
		}
	}
	set.addAverage(res, extraInfo)
	fmt.Printf("Result saved to CSV: %s (repeat=%d)\n", set.files[0].Name(), res.Repeat)
	return nil
}

func memorySize(bytes uint64) string {
	if bytes < 1<<30 {
		return fmt.Sprintf("%.2f MiB", float64(bytes)/(1<<20))
	}
	return fmt.Sprintf("%.2f GiB", float64(bytes)/(1<<30))
}

func AppendLAMPResultToCSV(set *LAMPCSV, res LAMPResult) error {
	return set.append(res, nil)
}

func AppendLAMPBATCHResultToCSV(set *LAMPCSV, res LAMPBATCHResult) error {
	return set.append(LAMPResult{
		Repeat:               res.Repeat,
		PedersenCommitTime:   res.PedersenCommitTime,
		MerkleCommitTime:     res.MerkleCommitTime,
		CommitOtherTime:      res.CommitOtherTime,
		MatrixWorkers:        res.MatrixWorkers,
		SetupMemory:          res.SetupMemory,
		CommitMemory:         res.CommitMemory,
		ProveMemory:          res.ProveMemory,
		LogK:                 res.LogK,
		Rho:                  res.Rho,
		Linker:               res.Linker,
		Merkle:               res.Merkle,
		N:                    res.N,
		NumQueries:           res.NumQueries,
		Constraints:          res.Constraints,
		MatrixComputeTime:    res.MatrixComputeTime,
		SetupTime:            res.SetupTime,
		ProtocolSetupTime:    res.ProtocolSetupTime,
		CircuitSetupTime:     res.CircuitSetupTime,
		CPLinkSetupTime:      res.CPLinkSetupTime,
		MatrixCommitTime:     res.MatrixCommitTime,
		VectorComputeTime:    res.VectorComputeTime,
		VectorCommitTime:     res.VectorCommitTime,
		EncodingTime:         res.EncodingTime,
		CommitTime:           res.CommitTime,
		TotalCommitTime:      res.TotalCommitTime,
		MerkleProveTime:      res.MerkleProveTime,
		CircuitProveTime:     res.CircuitProveTime,
		CPLinkProveTime:      res.CPLinkProveTime,
		TotalProveTime:       res.TotalProveTime,
		CommitAndProveTime:   res.CommitAndProveTime,
		CircuitVerifyTime:    res.CircuitVerifyTime,
		MerkleVerifyTime:     res.MerkleVerifyTime,
		CPLinkVerifyTime:     res.CPLinkVerifyTime,
		TotalVerifyTime:      res.TotalVerifyTime,
		MerkleProofSize:      res.MerkleProofSize,
		Groth16ProofSize:     res.Groth16ProofSize,
		CPLinkProofSize:      res.CPLinkProofSize,
		QueryCommitmentsSize: res.QueryCommitmentsSize,
		TotalProofSize:       res.TotalProofSize,
		PeakMemoryBytes:      res.PeakMemoryBytes,
		MatrixSource:         res.MatrixSource,
		MatrixPath:           res.MatrixPath,
		MatrixLoadTime:       res.MatrixLoadTime,
	}, []string{strconv.Itoa(res.Batch)})
}

func AppendLAMPGPT2ResultToCSV(set *LAMPCSV, res LAMPGPT2Result) error {
	return set.append(LAMPResult{
		Repeat:               res.Repeat,
		PedersenCommitTime:   res.PedersenCommitTime,
		MerkleCommitTime:     res.MerkleCommitTime,
		CommitOtherTime:      res.CommitOtherTime,
		MatrixWorkers:        res.MatrixWorkers,
		SetupMemory:          res.SetupMemory,
		CommitMemory:         res.CommitMemory,
		ProveMemory:          res.ProveMemory,
		Rho:                  res.Rho,
		Linker:               res.Linker,
		Merkle:               res.Merkle,
		NumQueries:           res.NumQueries,
		Constraints:          res.Constraints,
		MatrixComputeTime:    res.MatrixComputeTime,
		SetupTime:            res.SetupTime,
		ProtocolSetupTime:    res.ProtocolSetupTime,
		CircuitSetupTime:     res.CircuitSetupTime,
		CPLinkSetupTime:      res.CPLinkSetupTime,
		MatrixCommitTime:     res.MatrixCommitTime,
		VectorComputeTime:    res.VectorComputeTime,
		VectorCommitTime:     res.VectorCommitTime,
		EncodingTime:         res.EncodingTime,
		CommitTime:           res.CommitTime,
		TotalCommitTime:      res.TotalCommitTime,
		MerkleProveTime:      res.MerkleProveTime,
		CircuitProveTime:     res.CircuitProveTime,
		CPLinkProveTime:      res.CPLinkProveTime,
		TotalProveTime:       res.TotalProveTime,
		CommitAndProveTime:   res.CommitAndProveTime,
		CircuitVerifyTime:    res.CircuitVerifyTime,
		MerkleVerifyTime:     res.MerkleVerifyTime,
		CPLinkVerifyTime:     res.CPLinkVerifyTime,
		TotalVerifyTime:      res.TotalVerifyTime,
		MerkleProofSize:      res.MerkleProofSize,
		Groth16ProofSize:     res.Groth16ProofSize,
		CPLinkProofSize:      res.CPLinkProofSize,
		QueryCommitmentsSize: res.QueryCommitmentsSize,
		TotalProofSize:       res.TotalProofSize,
		PeakMemoryBytes:      res.PeakMemoryBytes,
		MatrixSource:         res.MatrixSource,
		MatrixPath:           res.MatrixPath,
		MatrixLoadTime:       res.MatrixLoadTime,
	}, []string{strconv.Itoa(res.SeqLog), strconv.Itoa(res.SeqLen), strconv.Itoa(res.NumClaims), strconv.Itoa(res.NumCommitGroups)})
}
