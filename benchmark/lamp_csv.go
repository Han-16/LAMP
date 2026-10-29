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

// Timing and proof-size names and ordering match LED's CSVs.
var lampTimingHeader = []string{
	"protocol_setup_time", "circuit_setup_time", "cplink_setup_time", "total_setup_time",
	"pedersen_commit_time", "merkle_commit_time", "abc_commit_time", "intermediate_compute_time", "intermediate_commit_time",
	"fold_compute_time", "fold_commit_time",
	"abc_encoding_time", "intermediate_encoding_time", "total_commit_time",
	"circuit_prove_time", "cplink_prove_time", "merkle_prove_time", "total_prove_time", "commit_and_prove_time",
	"circuit_verify_time", "cplink_verify_time", "merkle_verify_time", "c_in_agg_msm_time", "c_h_msm_time", "mid_msm_time", "error_msm_time", "verifier_msm_time", "total_verify_time",
}
var lampProofSizeHeader = []string{
	"snark_proof_bytes", "merkle_proof_bytes", "cplink_proof_bytes", "query_commitments_bytes", "mid_commitments_bytes", "cross_commitments_bytes", "total_proof_bytes", "statement_roots_bytes",
}
var lampMemoryMetricHeader = []string{
	"setup_peak", "commit_peak", "prove_peak", "peak",
}
var lampCSVHeader = slices.Concat(
	[]string{"repeat", "commit_mode", "logk", "rho", "m", "b", "g", "constraint"}, lampTimingHeader, lampProofSizeHeader,
)
var lampInfoCSVHeader = []string{
	"repeat", "commit_mode", "logk", "rho", "m", "b", "g", "samples", "distinct_queries", "context", "matrix_source", "matrix_path",
	"matrix_workers", "matrix_compute_time", "matrix_load_time",
}
var lampMemoryCSVHeader = slices.Concat(
	[]string{"repeat", "commit_mode", "logk", "rho", "m", "b", "g"}, lampMemoryMetricHeader,
)

// LAMPCSV owns the aligned LED-schema files and their configuration sidecar.
type LAMPCSV struct {
	files         []*os.File
	writers       []*csv.Writer
	gpt2          bool
	freivalds     bool
	runID         string
	averagePath   string
	averageHeader []string
	appendResults bool
	averagesSaved bool
	groups        map[string]*lampAverageGroup
	groupOrder    []*lampAverageGroup
	rawRows       int
	averageRows   int
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
	return initExperimentCSV(path, extraInfo, gpt2, false)
}

func initExperimentCSV(path string, extraInfo []string, gpt2, freivalds bool) (*LAMPCSV, error) {
	stem := strings.TrimSuffix(path, filepath.Ext(path))
	paths := []string{path, stem + "_info.csv", stem + "_memory.csv", stem + "_config.csv"}
	configHeader := append([]string{"record_type", "csv_row", "run_id", "repeat", "commit_mode", "logk", "rho", "linker", "merkle", "n"}, extraInfo...)
	headers := [][]string{lampCSVHeader, lampInfoCSVHeader, lampMemoryCSVHeader, configHeader}
	appendResults, _ := strconv.ParseBool(os.Getenv("BENCHMARK_APPEND_CSV"))
	averagePath := stem + "_average.csv"
	averageHeader := slices.Concat([]string{
		"logk", "rho", "m", "b", "g", "samples", "commit_mode", "runs", "constraint",
	}, lampTimingHeader, lampProofSizeHeader, lampMemoryMetricHeader)
	counts := make([]int, len(paths))
	if appendResults {
		for i, filename := range paths {
			count, err := csvRowCount(filename, headers[i])
			if err != nil {
				return nil, fmt.Errorf("check CSV %s: %w", filename, err)
			}
			counts[i] = count
			if i > 0 && i < 3 && counts[i] != counts[0] {
				return nil, fmt.Errorf("CSV row counts differ; keep all three files together or choose a new output directory")
			}
		}
	}
	averageRows := 0
	if appendResults {
		var err error
		averageRows, err = csvRowCount(averagePath, averageHeader)
		if err != nil {
			return nil, fmt.Errorf("check average CSV: %w", err)
		}
		if counts[3] != counts[0]+averageRows {
			return nil, fmt.Errorf("config CSV row count differs; keep the full output set together or choose a new output directory")
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
	set := &LAMPCSV{gpt2: gpt2, freivalds: freivalds, runID: time.Now().UTC().Format("20060102T150405.000000000Z"),
		averagePath: averagePath, averageHeader: averageHeader, appendResults: appendResults, groups: make(map[string]*lampAverageGroup), rawRows: counts[0], averageRows: averageRows}
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

// Internal preparation timers include encoding; split it out for LED's phases.
func (res LAMPResult) timings() []float64 {
	values := []float64{
		res.ProtocolSetupTime, res.CircuitSetupTime, res.CPLinkSetupTime, res.SetupTime,
		res.PedersenCommitTime, res.MerkleCommitTime, res.PedersenCommitTime + res.MerkleCommitTime,
		res.VectorComputeTime - res.VectorEncodingTime, res.VectorCommitTime,
		math.NaN(), math.NaN(),
		res.EncodingTime, res.VectorEncodingTime, res.TotalCommitTime,
		res.CircuitProveTime, res.CPLinkProveTime, res.MerkleProveTime, res.TotalProveTime, res.CommitAndProveTime,
		res.CircuitVerifyTime, res.CPLinkVerifyTime, res.MerkleVerifyTime,
		math.NaN(), math.NaN(), math.NaN(), math.NaN(), math.NaN(), res.TotalVerifyTime,
	}
	if res.MatrixSource == "compile" {
		for i := range values {
			values[i] = math.NaN()
		}
	}
	return values
}

func (set *LAMPCSV) proofSizes(res LAMPResult) []float64 {
	// LED's mid/cross commitments are absent; statement roots are not measured.
	values := []float64{
		float64(res.Groth16ProofSize), float64(res.MerkleProofSize), float64(res.CPLinkProofSize), float64(res.QueryCommitmentsSize),
		math.NaN(), math.NaN(), float64(res.TotalProofSize), math.NaN(),
	}
	if set.freivalds {
		values[1], values[2], values[3] = math.NaN(), math.NaN(), math.NaN()
	}
	if res.MatrixSource == "compile" {
		for i := range values {
			values[i] = math.NaN()
		}
	}
	return values
}

// Compute the combined peak from raw bytes, excluding setup and requiring both
// commit/prove observations. Shared by individual rows and repetition averages.
func (res LAMPResult) memoryPeaks() [4]Memory {
	commit, prove := res.CommitMemory, res.ProveMemory
	peak := Memory{RSSBytes: max(commit.RSSBytes, prove.RSSBytes),
		RSSAvailable: commit.RSSAvailable && prove.RSSAvailable,
		Measured:     commit.Measured && prove.Measured}
	return [4]Memory{res.SetupMemory, commit, prove, peak}
}

func optionalSeconds(seconds float64) string {
	// NaN marks phases absent from the measured protocol.
	if math.IsNaN(seconds) {
		return "-"
	}
	return formatSeconds(seconds)
}

func optionalNumber(value float64, precision int) string {
	if math.IsNaN(value) {
		return "-"
	}
	return strconv.FormatFloat(value, 'f', precision, 64)
}

func dashMissingCells(row []string) []string {
	for i, value := range row {
		if value == "" {
			row[i] = "-"
		}
	}
	return row
}

func (set *LAMPCSV) dimensions(res LAMPResult) (string, string) {
	// Rectangular tensors have no single square K or N.
	if set.gpt2 {
		return "", ""
	}
	if set.freivalds {
		return strconv.Itoa(res.LogK), ""
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
	if res.Instances < 1 {
		res.Instances = 1
	}
	logk, _ := set.dimensions(res)
	// m is comparable; LED's b/g grouping has no equivalent in LAMP.
	identity := []string{strconv.Itoa(res.Repeat), set.commitMode(), logk, res.Rho, strconv.Itoa(res.Instances), "-", "-"}
	record := append(slices.Clone(identity), strconv.Itoa(res.Constraints))
	for _, value := range res.timings() {
		record = append(record, optionalSeconds(value))
	}
	for _, value := range set.proofSizes(res) {
		record = append(record, optionalNumber(value, 0))
	}
	workers, compute, load := "-", "-", "-"
	if res.MatrixSource == "generate" {
		compute = formatSeconds(res.MatrixComputeTime)
		if res.MatrixWorkers > 0 {
			workers = strconv.Itoa(res.MatrixWorkers)
		}
	} else if res.MatrixSource == "file" {
		load = formatSeconds(res.MatrixLoadTime)
	}
	// Distinct-query counts and LED transcript context are not recorded.
	info := append(slices.Clone(identity), set.samples(res), "-", "-", res.MatrixSource, res.MatrixPath,
		workers, compute, load)
	memory := slices.Clone(identity)
	for _, m := range set.memoryPeaks(res) {
		cell := ""
		if m.Measured && m.RSSAvailable {
			cell = memorySize(m.RSSBytes)
		}
		memory = append(memory, cell)
	}
	for i, row := range [][]string{record, info, memory} {
		if err := set.writers[i].Write(dashMissingCells(row)); err != nil {
			return err
		}
		set.writers[i].Flush()
		if err := set.writers[i].Error(); err != nil {
			return err
		}
	}
	set.rawRows++
	if err := set.writeConfig("measurement", set.rawRows, res, extraInfo); err != nil {
		return err
	}
	set.addAverage(res, extraInfo)
	fmt.Printf("Result saved to CSV: %s (repeat=%d)\n", set.files[0].Name(), res.Repeat)
	return nil
}

// Config rows retain LAMP-only settings without changing LED's four schemas.
// csv_row is one-based, excluding the header; record_type selects raw or average.
func (set *LAMPCSV) writeConfig(kind string, row int, res LAMPResult, extra []string) error {
	logk, n := set.dimensions(res)
	repeat := strconv.Itoa(res.Repeat)
	if kind == "average" {
		repeat = ""
	}
	record := []string{kind, strconv.Itoa(row), set.runID, repeat, set.commitMode(), logk, res.Rho, res.Linker, res.Merkle, n}
	record = append(record, extra...)
	if err := set.writers[3].Write(dashMissingCells(record)); err != nil {
		return err
	}
	set.writers[3].Flush()
	return set.writers[3].Error()
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
		Instances:            res.Batch,
		VectorEncodingTime:   res.VectorEncodingTime,
		PedersenCommitTime:   res.PedersenCommitTime,
		MerkleCommitTime:     res.MerkleCommitTime,
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
		MatrixSource:         res.MatrixSource,
		MatrixPath:           res.MatrixPath,
		MatrixLoadTime:       res.MatrixLoadTime,
	}, []string{strconv.Itoa(res.Batch)})
}

func AppendLAMPGPT2ResultToCSV(set *LAMPCSV, res LAMPGPT2Result) error {
	return set.append(LAMPResult{
		Repeat:               res.Repeat,
		Instances:            res.NumClaims,
		VectorEncodingTime:   res.VectorEncodingTime,
		PedersenCommitTime:   res.PedersenCommitTime,
		MerkleCommitTime:     res.MerkleCommitTime,
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
		MatrixSource:         res.MatrixSource,
		MatrixPath:           res.MatrixPath,
		MatrixLoadTime:       res.MatrixLoadTime,
	}, []string{strconv.Itoa(res.SeqLog), strconv.Itoa(res.SeqLen), strconv.Itoa(res.NumClaims), strconv.Itoa(res.NumCommitGroups)})
}
