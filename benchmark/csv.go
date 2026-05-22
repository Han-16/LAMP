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
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	writeSystemInfoForCSV(filename)

	writer := csv.NewWriter(file)
	if err := writer.Write(header); err != nil {
		log.Fatalf("Failed to write CSV header: %v", err)
	}
	writer.Flush()

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
}

type MeowResult struct {
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
}

type MeowGPT2Result struct {
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
	CommitTime        float64
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
}

// --- Freivalds Benchmark ---
func InitFreivaldsCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"log(K)", "Constraint", "MatrixComputeTime (s/ms)", "Setup (s/ms)", "Prove (s/ms)", "Verify (s/ms)",
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
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d", res.LogK))
}

func InitMeowCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "Rho", "Linker", "Merkle", "N", "NumQueries", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)",
		"ProtocolSetupTime(s/ms)", "CircuitSetupTime(s/ms)", "CPLinkSetupTime(s/ms)",
		"MatrixCommitTime(s/ms)", "VectorCommitTime(s/ms)", "MerkleProveTime(s/ms)", "CircuitProveTime(s/ms)",
		"CPLinkProveTime(s/ms)", "TotalProveTime(s/ms)",
		"CircuitVerifyTime(s/ms)", "MerkleVerifyTime(s/ms)", "CPLinkVerifyTime(s/ms)", "TotalVerifyTime(s/ms)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)",
	})
}

func AppendMeowResultToCSV(writer *csv.Writer, res MeowResult) {
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
	}
	appendCSV(writer, record, fmt.Sprintf("Meow Protocol: logK=%d, rho=%s, linker=%s, merkle=%s, L=%d, constraints=%d", res.LogK, res.Rho, res.Linker, res.Merkle, res.NumQueries, res.Constraints))
}

func InitMeowGPT2CSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"SeqLog", "SeqLen", "Rho", "Linker", "Merkle", "NumQueries", "NumClaims", "NumCommitGroups", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)",
		"ProtocolSetupTime(s/ms)", "CircuitSetupTime(s/ms)", "CPLinkSetupTime(s/ms)",
		"CommitTime(s/ms)", "MerkleProveTime(s/ms)", "CircuitProveTime(s/ms)",
		"CPLinkProveTime(s/ms)", "TotalProveTime(s/ms)",
		"CircuitVerifyTime(s/ms)", "MerkleVerifyTime(s/ms)", "CPLinkVerifyTime(s/ms)", "TotalVerifyTime(s/ms)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)",
	})
}

func AppendMeowGPT2ResultToCSV(writer *csv.Writer, res MeowGPT2Result) {
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
		formatSeconds(res.CommitTime),
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
	}
	appendCSV(writer, record, fmt.Sprintf("Meow GPT-2 medium layer: seq=2^%d, rho=%s, linker=%s, merkle=%s, L=%d, claims=%d, constraints=%d", res.SeqLog, res.Rho, res.Linker, res.Merkle, res.NumQueries, res.NumClaims, res.Constraints))
}

func InitFreivaldsGPT2CSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"SeqLog", "SeqLen", "NumClaims", "Constraints",
		"MatrixComputeTime(s/ms)", "SetupTime(s/ms)", "ProveTime(s/ms)", "VerifyTime(s/ms)",
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
