package benchmark

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
)

func EnsureDir(dir string) error {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, os.ModePerm)
	}
	return err
}

func initCSV(filename string, header []string) (*os.File, *csv.Writer) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	writeHeader := true
	appendResults, _ := strconv.ParseBool(os.Getenv("BENCHMARK_APPEND_CSV"))
	if appendResults {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if info, err := os.Stat(filename); err == nil && info.Size() > 0 {
			writeHeader = false
		}
	}

	file, err := os.OpenFile(filename, flags, 0666)
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	writeSystemInfoForCSV(filename)

	writer := csv.NewWriter(file)
	if writeHeader {
		if err := writer.Write(header); err != nil {
			log.Fatalf("Failed to write CSV header: %v", err)
		}
		writer.Flush()
	}

	return file, writer
}

func appendCSV(writer *csv.Writer, record []string, successLog string) {
	if err := writer.Write(record); err != nil {
		log.Printf("⚠️ Failed to write result record to CSV: %v", err)
	}
	writer.Flush()

	if err := writer.Error(); err != nil {
		log.Printf("⚠️ Error flushing csv writer: %v", err)
	} else {
		fmt.Printf("💾 Result saved to CSV: %s\n\n\n", successLog)
	}
}

type FreivaldsResult struct {
	LogK              int
	MatrixComputeTime float64
	Constraints       int
	SetupTime         float64
	ProveTime         float64
	VerifyTime        float64
	ProofSize         int
	PeakMemoryBytes   uint64
}

type FreivaldsBatchResult struct {
	LogK              int
	Batch             int
	MatrixComputeTime float64
	Constraints       int
	SetupTime         float64
	ProveTime         float64
	VerifyTime        float64
	ProofSize         int
	PeakMemoryBytes   uint64
}

type LAMPResult struct {
	LogK              int
	Rho               string
	Linker            string
	Merkle            string
	N                 int
	NumQueries        int // L
	Constraints       int
	MatrixComputeTime float64
	SetupTime         float64
	ProtocolSetupTime float64
	CircuitSetupTime  float64
	CPLinkSetupTime   float64
	MatrixCommitTime  float64
	VectorCommitTime  float64
	EncodingTime      float64
	CommitTime        float64
	TotalCommitTime   float64
	MerkleProveTime   float64
	CircuitProveTime  float64
	CPLinkProveTime   float64
	TotalProveTime    float64
	CircuitVerifyTime float64
	MerkleVerifyTime  float64
	CPLinkVerifyTime  float64
	TotalVerifyTime   float64
	MerkleProofSize   int
	Groth16ProofSize  int
	CPLinkProofSize   int
	TotalProofSize    int
	PeakMemoryBytes   uint64
}

type LAMPBATCHResult struct {
	LogK              int
	Rho               string
	Linker            string
	Merkle            string
	Batch             int
	N                 int
	NumQueries        int // L
	Constraints       int
	MatrixComputeTime float64
	SetupTime         float64
	ProtocolSetupTime float64
	CircuitSetupTime  float64
	CPLinkSetupTime   float64
	MatrixCommitTime  float64
	VectorCommitTime  float64
	EncodingTime      float64
	CommitTime        float64
	TotalCommitTime   float64
	MerkleProveTime   float64
	CircuitProveTime  float64
	CPLinkProveTime   float64
	TotalProveTime    float64
	CircuitVerifyTime float64
	MerkleVerifyTime  float64
	CPLinkVerifyTime  float64
	TotalVerifyTime   float64
	MerkleProofSize   int
	Groth16ProofSize  int
	CPLinkProofSize   int
	TotalProofSize    int
	PeakMemoryBytes   uint64
}

type LAMPGPT2Result struct {
	SeqLog            int
	SeqLen            int
	Rho               string
	Linker            string
	Merkle            string
	NumQueries        int
	NumClaims         int
	NumCommitGroups   int
	Constraints       int
	MatrixComputeTime float64
	SetupTime         float64
	ProtocolSetupTime float64
	CircuitSetupTime  float64
	CPLinkSetupTime   float64
	EncodingTime      float64
	CommitTime        float64
	TotalCommitTime   float64
	MerkleProveTime   float64
	CircuitProveTime  float64
	CPLinkProveTime   float64
	TotalProveTime    float64
	CircuitVerifyTime float64
	MerkleVerifyTime  float64
	CPLinkVerifyTime  float64
	TotalVerifyTime   float64
	MerkleProofSize   int
	Groth16ProofSize  int
	CPLinkProofSize   int
	TotalProofSize    int
	PeakMemoryBytes   uint64
}

type FreivaldsGPT2Result struct {
	SeqLog            int
	SeqLen            int
	NumClaims         int
	Constraints       int
	MatrixComputeTime float64
	SetupTime         float64
	ProveTime         float64
	VerifyTime        float64
	ProofSize         int
	PeakMemoryBytes   uint64
}

// --- Freivalds Benchmark ---
func InitFreivaldsCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"log(K)", "Constraint", "MatrixComputeTime (s/ms)", "Setup (s/ms)", "Prove (s/ms)", "Verify (s/ms)", "ProofSize(B)", "PeakMemory(B)",
	})
}

func AppendFreivaldsResultToCSV(writer *csv.Writer, res FreivaldsResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.ProveTime),
		formatSeconds(res.VerifyTime),
		strconv.Itoa(res.ProofSize),
		strconv.FormatUint(res.PeakMemoryBytes, 10),
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d", res.LogK))
}

func InitFreivaldsBatchCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"log(K)", "Batch", "Constraint", "MatrixComputeTime (s/ms)", "Setup (s/ms)", "Prove (s/ms)", "Verify (s/ms)", "ProofSize(B)", "PeakMemory(B)",
	})
}

func AppendFreivaldsBatchResultToCSV(writer *csv.Writer, res FreivaldsBatchResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		strconv.Itoa(res.Batch),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.ProveTime),
		formatSeconds(res.VerifyTime),
		strconv.Itoa(res.ProofSize),
		strconv.FormatUint(res.PeakMemoryBytes, 10),
	}
	appendCSV(writer, record, fmt.Sprintf("Freivalds batch: logK=%d, batch=%d, constraints=%d", res.LogK, res.Batch, res.Constraints))
}

func InitLAMPCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "Rho", "Linker", "Merkle", "N", "NumQueries", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)",
		"ProtocolSetupTime(s/ms)", "CircuitSetupTime(s/ms)", "CPLinkSetupTime(s/ms)",
		"MatrixCommitTime(s/ms)", "VectorCommitTime(s/ms)",
		"EncodingTime(s/ms)", "CommitTime(s/ms)", "TotalCommitTime(s/ms)",
		"MerkleProveTime(s/ms)", "CircuitProveTime(s/ms)",
		"CPLinkProveTime(s/ms)", "TotalProveTime(s/ms)",
		"CircuitVerifyTime(s/ms)", "MerkleVerifyTime(s/ms)", "CPLinkVerifyTime(s/ms)", "TotalVerifyTime(s/ms)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)", "PeakMemory(B)",
	})
}

func AppendLAMPResultToCSV(writer *csv.Writer, res LAMPResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		res.Linker,
		res.Merkle,
		strconv.Itoa(res.N),
		strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.ProtocolSetupTime),
		formatSeconds(res.CircuitSetupTime),
		formatSeconds(res.CPLinkSetupTime),
		formatSeconds(res.MatrixCommitTime),
		formatSeconds(res.VectorCommitTime),
		formatSeconds(res.EncodingTime),
		formatSeconds(res.CommitTime),
		formatSeconds(res.TotalCommitTime),
		formatSeconds(res.MerkleProveTime),
		formatSeconds(res.CircuitProveTime),
		formatSeconds(res.CPLinkProveTime),
		formatSeconds(res.TotalProveTime),
		formatSeconds(res.CircuitVerifyTime),
		formatSeconds(res.MerkleVerifyTime),
		formatSeconds(res.CPLinkVerifyTime),
		formatSeconds(res.TotalVerifyTime),
		strconv.Itoa(res.MerkleProofSize),
		strconv.Itoa(res.Groth16ProofSize),
		strconv.Itoa(res.CPLinkProofSize),
		strconv.Itoa(res.TotalProofSize),
		strconv.FormatUint(res.PeakMemoryBytes, 10),
	}
	appendCSV(writer, record, fmt.Sprintf("LAMP Protocol: logK=%d, rho=%s, linker=%s, merkle=%s, L=%d, constraints=%d", res.LogK, res.Rho, res.Linker, res.Merkle, res.NumQueries, res.Constraints))
}

func InitLAMPBATCHCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "Rho", "Linker", "Merkle", "Batch", "N", "NumQueries", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)",
		"ProtocolSetupTime(s/ms)", "CircuitSetupTime(s/ms)", "CPLinkSetupTime(s/ms)",
		"MatrixCommitTime(s/ms)", "VectorCommitTime(s/ms)",
		"EncodingTime(s/ms)", "CommitTime(s/ms)", "TotalCommitTime(s/ms)",
		"MerkleProveTime(s/ms)", "CircuitProveTime(s/ms)",
		"CPLinkProveTime(s/ms)", "TotalProveTime(s/ms)",
		"CircuitVerifyTime(s/ms)", "MerkleVerifyTime(s/ms)", "CPLinkVerifyTime(s/ms)", "TotalVerifyTime(s/ms)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)", "PeakMemory(B)",
	})
}

func AppendLAMPBATCHResultToCSV(writer *csv.Writer, res LAMPBATCHResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		res.Linker,
		res.Merkle,
		strconv.Itoa(res.Batch),
		strconv.Itoa(res.N),
		strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.ProtocolSetupTime),
		formatSeconds(res.CircuitSetupTime),
		formatSeconds(res.CPLinkSetupTime),
		formatSeconds(res.MatrixCommitTime),
		formatSeconds(res.VectorCommitTime),
		formatSeconds(res.EncodingTime),
		formatSeconds(res.CommitTime),
		formatSeconds(res.TotalCommitTime),
		formatSeconds(res.MerkleProveTime),
		formatSeconds(res.CircuitProveTime),
		formatSeconds(res.CPLinkProveTime),
		formatSeconds(res.TotalProveTime),
		formatSeconds(res.CircuitVerifyTime),
		formatSeconds(res.MerkleVerifyTime),
		formatSeconds(res.CPLinkVerifyTime),
		formatSeconds(res.TotalVerifyTime),
		strconv.Itoa(res.MerkleProofSize),
		strconv.Itoa(res.Groth16ProofSize),
		strconv.Itoa(res.CPLinkProofSize),
		strconv.Itoa(res.TotalProofSize),
		strconv.FormatUint(res.PeakMemoryBytes, 10),
	}
	appendCSV(writer, record, fmt.Sprintf("LAMPBATCH Protocol: logK=%d, rho=%s, linker=%s, merkle=%s, L=%d, batch=%d, constraints=%d", res.LogK, res.Rho, res.Linker, res.Merkle, res.NumQueries, res.Batch, res.Constraints))
}

func InitLAMPGPT2CSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"SeqLog", "SeqLen", "Rho", "Linker", "Merkle", "NumQueries", "NumClaims", "NumCommitGroups", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)",
		"ProtocolSetupTime(s/ms)", "CircuitSetupTime(s/ms)", "CPLinkSetupTime(s/ms)",
		"EncodingTime(s/ms)", "CommitTime(s/ms)", "TotalCommitTime(s/ms)",
		"MerkleProveTime(s/ms)", "CircuitProveTime(s/ms)",
		"CPLinkProveTime(s/ms)", "TotalProveTime(s/ms)",
		"CircuitVerifyTime(s/ms)", "MerkleVerifyTime(s/ms)", "CPLinkVerifyTime(s/ms)", "TotalVerifyTime(s/ms)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)", "PeakMemory(B)",
	})
}

func AppendLAMPGPT2ResultToCSV(writer *csv.Writer, res LAMPGPT2Result) {
	record := []string{
		strconv.Itoa(res.SeqLog),
		strconv.Itoa(res.SeqLen),
		res.Rho,
		res.Linker,
		res.Merkle,
		strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.NumClaims),
		strconv.Itoa(res.NumCommitGroups),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.ProtocolSetupTime),
		formatSeconds(res.CircuitSetupTime),
		formatSeconds(res.CPLinkSetupTime),
		formatSeconds(res.EncodingTime),
		formatSeconds(res.CommitTime),
		formatSeconds(res.TotalCommitTime),
		formatSeconds(res.MerkleProveTime),
		formatSeconds(res.CircuitProveTime),
		formatSeconds(res.CPLinkProveTime),
		formatSeconds(res.TotalProveTime),
		formatSeconds(res.CircuitVerifyTime),
		formatSeconds(res.MerkleVerifyTime),
		formatSeconds(res.CPLinkVerifyTime),
		formatSeconds(res.TotalVerifyTime),
		strconv.Itoa(res.MerkleProofSize),
		strconv.Itoa(res.Groth16ProofSize),
		strconv.Itoa(res.CPLinkProofSize),
		strconv.Itoa(res.TotalProofSize),
		strconv.FormatUint(res.PeakMemoryBytes, 10),
	}
	appendCSV(writer, record, fmt.Sprintf("LAMP GPT-2 medium layer: seq=2^%d, rho=%s, linker=%s, merkle=%s, L=%d, claims=%d, constraints=%d", res.SeqLog, res.Rho, res.Linker, res.Merkle, res.NumQueries, res.NumClaims, res.Constraints))
}

func InitFreivaldsGPT2CSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"SeqLog", "SeqLen", "NumClaims", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)", "ProveTime(s/ms)", "VerifyTime(s/ms)", "ProofSize(B)", "PeakMemory(B)",
	})
}

func AppendFreivaldsGPT2ResultToCSV(writer *csv.Writer, res FreivaldsGPT2Result) {
	record := []string{
		strconv.Itoa(res.SeqLog),
		strconv.Itoa(res.SeqLen),
		strconv.Itoa(res.NumClaims),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.ProveTime),
		formatSeconds(res.VerifyTime),
		strconv.Itoa(res.ProofSize),
		strconv.FormatUint(res.PeakMemoryBytes, 10),
	}
	appendCSV(writer, record, fmt.Sprintf("Freivalds GPT-2 medium layer: seq=2^%d, claims=%d, constraints=%d", res.SeqLog, res.NumClaims, res.Constraints))
}

func formatSeconds(seconds float64) string {
	return FormatDurationSeconds(seconds)
}

func FormatDurationSeconds(seconds float64) string {
	if math.Abs(seconds) < 0.005 {
		return fmt.Sprintf("%dms", int(math.Round(seconds*1000)))
	}
	return fmt.Sprintf("%.2fs", seconds)
}
