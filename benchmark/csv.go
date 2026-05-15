package benchmark

import (
	"encoding/csv"
	"fmt"
	"log"
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
	N                 int
	NumQueries        int // L
	Constraints       int
	MatrixComputeTime float64
	MatrixCommitTime  float64
	VectorCommitTime  float64
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

// --- Freivalds Benchmark ---
func InitFreivaldsCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"log(K)", "Constraint", "MatrixComputeTime (s)", "Setup (s)", "Prove (s)", "Verify (s)",
	})
}

func AppendFreivaldsResultToCSV(writer *csv.Writer, res FreivaldsResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		strconv.Itoa(res.Constraints),
		fmt.Sprintf("%.3f", res.MatrixComputeTime),
		fmt.Sprintf("%.3f", res.SetupTime),
		fmt.Sprintf("%.3f", res.ProveTime),
		fmt.Sprintf("%.3f", res.VerifyTime),
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d", res.LogK))
}

func InitMeowCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "Rho", "N", "NumQueries", "Constraints",
		"MatrixComputeTime(s)", "MatrixCommitTime(s)", "VectorCommitTime(s)", "CircuitProveTime(s)",
		"CPLinkProveTime(s)", "TotalProveTime(s)",
		"CircuitVerifyTime(s)", "MerkleVerifyTime(s)", "CPLinkVerifyTime(s)", "TotalVerifyTime(s)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)",
	})
}

func AppendMeowResultToCSV(writer *csv.Writer, res MeowResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		strconv.Itoa(res.N),
		strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.Constraints),
		fmt.Sprintf("%.6f", res.MatrixComputeTime),
		fmt.Sprintf("%.6f", res.MatrixCommitTime),
		fmt.Sprintf("%.6f", res.VectorCommitTime),
		fmt.Sprintf("%.6f", res.CircuitProveTime),
		fmt.Sprintf("%.6f", res.CPLinkProveTime),
		fmt.Sprintf("%.6f", res.TotalProveTime),
		fmt.Sprintf("%.6f", res.CircuitVerifyTime),
		fmt.Sprintf("%.6f", res.MerkleVerifyTime),
		fmt.Sprintf("%.6f", res.CPLinkVerifyTime),
		fmt.Sprintf("%.6f", res.TotalVerifyTime),
		strconv.Itoa(res.MerkleProofSize),
		strconv.Itoa(res.Groth16ProofSize),
		strconv.Itoa(res.CPLinkProofSize),
		strconv.Itoa(res.TotalProofSize),
	}
	appendCSV(writer, record, fmt.Sprintf("Meow Protocol: logK=%d, rho=%s, L=%d, constraints=%d", res.LogK, res.Rho, res.NumQueries, res.Constraints))
}
