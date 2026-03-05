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
		log.Printf("⚠️ Failed to write record to CSV: %v", err)
	}
	writer.Flush()

	if err := writer.Error(); err != nil {
		log.Printf("⚠️ Error flushing csv writer: %v", err)
	} else {
		fmt.Printf("💾 Result saved to CSV: %s\n", successLog)
	}
}

type ReedSolomonResult struct { // RS Benchmark
	LogK        int
	Rho         string
	Precompute  float64
	Encoding    float64
	Constraints int
	Setup       float64
	Prove       float64
	Verify      float64
}

type MembershipResult struct {
	LogK                int
	Rho                 string
	N                   int
	Height              int
	NumQueries          int
	PedCommitTime       float64
	MerkleTreeBuildTime float64
	ProofSize           int
	ProveTime           float64
	VerifyTime          float64
}

type CpLinkResult struct {
	LogK            int
	NumCommitments  int
	CPLinkProveTime float64
	ProofSize       int
	VerifyTime      float64
}

type FreivaldsResult struct {
	LogK        int
	Compute     float64
	Constraints int
	SetupTime   float64
	ProveTime   float64
	VerifyTime  float64
}

// =============================================================================
// 3. 실험별 CSV 입출력 구현부 (API)
// =============================================================================

// --- RS Benchmark ---
func InitCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{"log(K)", "rho", "Precompute (s)", "Encoding (s)", "Constraint"})
}

func AppendResultToCSV(writer *csv.Writer, res ReedSolomonResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		fmt.Sprintf("%.3f", res.Precompute),
		fmt.Sprintf("%.3f", res.Encoding),
		strconv.Itoa(res.Constraints),
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d, rho=%s", res.LogK, res.Rho))
}

// --- Membership Benchmark ---
func InitMembershipCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "Rho", "N", "Height", "NumQueries", "PedCommitTime (s)",
		"MerkleTreeBuildTime (s)", "ProofSize (Bytes)", "ProveTime (s)", "VerifyTime (s)",
	})
}

func AppendMembershipResultToCSV(writer *csv.Writer, res MembershipResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		strconv.Itoa(res.N),
		strconv.Itoa(res.Height),
		strconv.Itoa(res.NumQueries),
		fmt.Sprintf("%.6f", res.PedCommitTime),
		fmt.Sprintf("%.6f", res.MerkleTreeBuildTime),
		strconv.Itoa(res.ProofSize),
		fmt.Sprintf("%.6f", res.ProveTime),
		fmt.Sprintf("%.6f", res.VerifyTime),
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d, rho=%s, N=%d", res.LogK, res.Rho, res.N))
}

// --- CP-LINK Benchmark ---
func InitCpLinkCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "NumCommitments", "CPLinkProveTime (s)", "ProofSize", "VerifyTime (s)",
	})
}

func AppendCpLinkResultToCSV(writer *csv.Writer, res CpLinkResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		strconv.Itoa(res.NumCommitments),
		fmt.Sprintf("%.6f", res.CPLinkProveTime),
		strconv.Itoa(res.ProofSize),
		fmt.Sprintf("%.6f", res.VerifyTime),
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d, L=%d", res.LogK, res.NumCommitments))
}

// --- Freivalds Benchmark ---
func InitFreivaldsCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"log(K)", "Compute (s)", "Constraint", "Setup (s)", "Prove (s)", "Verify (s)",
	})
}

func AppendFreivaldsResultToCSV(writer *csv.Writer, res FreivaldsResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		fmt.Sprintf("%.3f", res.Compute),
		strconv.Itoa(res.Constraints),
		fmt.Sprintf("%.3f", res.SetupTime),
		fmt.Sprintf("%.3f", res.ProveTime),
		fmt.Sprintf("%.3f", res.VerifyTime),
	}
	appendCSV(writer, record, fmt.Sprintf("logK=%d", res.LogK))
}

// -----------------------------------------------------------------------------
// [추가됨] Meow (Brakedown + CC-SNARK) 벤치마크
// -----------------------------------------------------------------------------
type MeowResult struct {
	LogK             int
	Rho              string
	N                int
	NumQueries       int     // L
	ComputeTime      float64 // C = A * B 계산 시간
	MatrixCommitTime float64 // A, B, C 인코딩 및 머클트리 생성 시간
	VectorCommitTime float64 // x, y, z 생성, 인코딩 및 머클트리 생성 시간
	CircuitProveTime float64 // Groth16 서킷 증명 시간
	CPLinkProveTime  float64 // 3*L 개의 CP-LINK 증명 시간
	TotalProveTime   float64 // CircuitProveTime + CPLinkProveTime
	TotalVerifyTime  float64 // Merkle + Groth16 + CPLink 전체 검증 시간
}

func InitMeowCSV(filename string) (*os.File, *csv.Writer) {
	return initCSV(filename, []string{
		"LogK", "Rho", "N", "NumQueries", "ComputeTime(s)",
		"MatrixCommitTime(s)", "VectorCommitTime(s)", "CircuitProveTime(s)",
		"CPLinkProveTime(s)", "TotalProveTime(s)", "TotalVerifyTime(s)",
	})
}

func AppendMeowResultToCSV(writer *csv.Writer, res MeowResult) {
	record := []string{
		strconv.Itoa(res.LogK),
		res.Rho,
		strconv.Itoa(res.N),
		strconv.Itoa(res.NumQueries),
		fmt.Sprintf("%.6f", res.ComputeTime),
		fmt.Sprintf("%.6f", res.MatrixCommitTime),
		fmt.Sprintf("%.6f", res.VectorCommitTime),
		fmt.Sprintf("%.6f", res.CircuitProveTime),
		fmt.Sprintf("%.6f", res.CPLinkProveTime),
		fmt.Sprintf("%.6f", res.TotalProveTime),
		fmt.Sprintf("%.6f", res.TotalVerifyTime),
	}
	appendCSV(writer, record, fmt.Sprintf("Meow Protocol: logK=%d, rho=%s, L=%d", res.LogK, res.Rho, res.NumQueries))
}
