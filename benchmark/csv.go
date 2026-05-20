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
	SetupTime         float64
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

type RectMeowResult struct {
	LogRows           int
	LogInner          int
	LogCols           int
	Rows              int
	Inner             int
	Cols              int
	Rho               string
	NIn               int
	NOut              int
	NumQueries        int
	Constraints       int
	MatrixComputeTime float64
	SetupTime         float64
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

type MeowGPT2Result struct {
	SeqLog            int
	SeqLen            int
	Rho               string
	NumQueries        int
	NumClaims         int
	NumCommitGroups   int
	Constraints       int
	MatrixComputeTime float64
	SetupTime         float64
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
		"log(K)", "Constraint", "MatrixComputeTime (s)", "Setup (s)", "Prove (s)", "Verify (s)",
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
		"LogK", "Rho", "N", "NumQueries", "Constraints",
		"MatrixComputeTime(s)", "SetupTime(s)",
		"MatrixCommitTime(s)", "VectorCommitTime(s)", "MerkleProveTime(s)", "CircuitProveTime(s)",
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
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
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
	appendCSV(writer, record, fmt.Sprintf("Meow Protocol: logK=%d, rho=%s, L=%d, constraints=%d", res.LogK, res.Rho, res.NumQueries, res.Constraints))
}

func InitRectMeowCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogRows", "LogInner", "LogCols", "Rows", "Inner", "Cols", "Rho", "NIn", "NOut", "NumQueries", "Constraints",
		"MatrixComputeTime(s)", "SetupTime(s)",
		"MatrixCommitTime(s)", "VectorCommitTime(s)", "CircuitProveTime(s)",
		"CPLinkProveTime(s)", "TotalProveTime(s)",
		"CircuitVerifyTime(s)", "MerkleVerifyTime(s)", "CPLinkVerifyTime(s)", "TotalVerifyTime(s)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)",
	})
}

func AppendRectMeowResultToCSV(writer *csv.Writer, res RectMeowResult) {
	record := []string{
		strconv.Itoa(res.LogRows),
		strconv.Itoa(res.LogInner),
		strconv.Itoa(res.LogCols),
		strconv.Itoa(res.Rows),
		strconv.Itoa(res.Inner),
		strconv.Itoa(res.Cols),
		res.Rho,
		strconv.Itoa(res.NIn),
		strconv.Itoa(res.NOut),
		strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
		formatSeconds(res.MatrixCommitTime),
		formatSeconds(res.VectorCommitTime),
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
	appendCSV(writer, record, fmt.Sprintf("RectMeow Protocol: logRows=%d, logInner=%d, logCols=%d, rows=%d, inner=%d, cols=%d, rho=%s, L=%d, constraints=%d", res.LogRows, res.LogInner, res.LogCols, res.Rows, res.Inner, res.Cols, res.Rho, res.NumQueries, res.Constraints))
}

func InitMeowGPT2CSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"SeqLog", "SeqLen", "Rho", "NumQueries", "NumClaims", "NumCommitGroups", "Constraints",
		"MatrixComputeTime(s)", "SetupTime(s)", "CommitTime(s)", "MerkleProveTime(s)", "CircuitProveTime(s)",
		"CPLinkProveTime(s)", "TotalProveTime(s)",
		"CircuitVerifyTime(s)", "MerkleVerifyTime(s)", "CPLinkVerifyTime(s)", "TotalVerifyTime(s)",
		"MerkleProofSize(B)", "Groth16ProofSize(B)", "CPLinkProofSize(B)", "TotalProofSize(B)",
	})
}

func AppendMeowGPT2ResultToCSV(writer *csv.Writer, res MeowGPT2Result) {
	record := []string{
		strconv.Itoa(res.SeqLog),
		strconv.Itoa(res.SeqLen),
		res.Rho,
		strconv.Itoa(res.NumQueries),
		strconv.Itoa(res.NumClaims),
		strconv.Itoa(res.NumCommitGroups),
		strconv.Itoa(res.Constraints),
		formatSeconds(res.MatrixComputeTime),
		formatSeconds(res.SetupTime),
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
	appendCSV(writer, record, fmt.Sprintf("Meow GPT-2 medium layer: seq=2^%d, rho=%s, L=%d, claims=%d, constraints=%d", res.SeqLog, res.Rho, res.NumQueries, res.NumClaims, res.Constraints))
}

func InitFreivaldsGPT2CSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"SeqLog", "SeqLen", "NumClaims", "Constraints",
		"MatrixComputeTime(s)", "SetupTime(s)", "ProveTime(s)", "VerifyTime(s)",
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
	return fmt.Sprintf("%.2f", seconds)
}
