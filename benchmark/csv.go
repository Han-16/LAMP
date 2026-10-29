package benchmark

import (
	"fmt"
	"os"
)

func EnsureDir(dir string) error {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, os.ModePerm)
	}
	return err
}

type FreivaldsResult struct {
	LogK              int
	MatrixComputeTime float64
	Constraints       int
	SetupTime         float64
	ProveTime         float64
	VerifyTime        float64
	ProofSize         int
	MatrixSource      string
	MatrixPath        string
	MatrixLoadTime    float64
	Repeat            int
	MatrixWorkers     int
	SetupMemory       Memory
	ProveMemory       Memory
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
	MatrixSource      string
	MatrixPath        string
	MatrixLoadTime    float64
	Repeat            int
	MatrixWorkers     int
	SetupMemory       Memory
	ProveMemory       Memory
}

type LAMPResult struct {
	VectorEncodingTime   float64
	Repeat               int
	Instances            int // Matrix products; defaults to one for square runs.
	PedersenCommitTime   float64
	MerkleCommitTime     float64
	MatrixWorkers        int
	SetupMemory          Memory
	CommitMemory         Memory
	ProveMemory          Memory
	LogK                 int
	Rho                  string
	Linker               string
	Merkle               string
	N                    int
	NumQueries           int // L
	Constraints          int
	MatrixComputeTime    float64
	SetupTime            float64
	ProtocolSetupTime    float64
	CircuitSetupTime     float64
	CPLinkSetupTime      float64
	MatrixCommitTime     float64
	VectorComputeTime    float64
	VectorCommitTime     float64
	EncodingTime         float64
	CommitTime           float64
	TotalCommitTime      float64
	MerkleProveTime      float64
	CircuitProveTime     float64
	CPLinkProveTime      float64
	TotalProveTime       float64
	CommitAndProveTime   float64
	CircuitVerifyTime    float64
	MerkleVerifyTime     float64
	CPLinkVerifyTime     float64
	TotalVerifyTime      float64
	MerkleProofSize      int
	Groth16ProofSize     int
	CPLinkProofSize      int
	QueryCommitmentsSize int
	TotalProofSize       int
	MatrixSource         string
	MatrixPath           string
	MatrixLoadTime       float64
}

type LAMPBATCHResult struct {
	VectorEncodingTime   float64
	Repeat               int
	PedersenCommitTime   float64
	MerkleCommitTime     float64
	MatrixWorkers        int
	SetupMemory          Memory
	CommitMemory         Memory
	ProveMemory          Memory
	LogK                 int
	Rho                  string
	Linker               string
	Merkle               string
	Batch                int
	N                    int
	NumQueries           int // L
	Constraints          int
	MatrixComputeTime    float64
	SetupTime            float64
	ProtocolSetupTime    float64
	CircuitSetupTime     float64
	CPLinkSetupTime      float64
	MatrixCommitTime     float64
	VectorComputeTime    float64
	VectorCommitTime     float64
	EncodingTime         float64
	CommitTime           float64
	TotalCommitTime      float64
	MerkleProveTime      float64
	CircuitProveTime     float64
	CPLinkProveTime      float64
	TotalProveTime       float64
	CommitAndProveTime   float64
	CircuitVerifyTime    float64
	MerkleVerifyTime     float64
	CPLinkVerifyTime     float64
	TotalVerifyTime      float64
	MerkleProofSize      int
	Groth16ProofSize     int
	CPLinkProofSize      int
	QueryCommitmentsSize int
	TotalProofSize       int
	MatrixSource         string
	MatrixPath           string
	MatrixLoadTime       float64
}

type LAMPGPT2Result struct {
	VectorEncodingTime       float64
	Repeat                   int
	MatrixSource, MatrixPath string
	MatrixLoadTime           float64
	PedersenCommitTime       float64
	MerkleCommitTime         float64
	MatrixWorkers            int
	SetupMemory              Memory
	CommitMemory             Memory
	ProveMemory              Memory
	SeqLog                   int
	SeqLen                   int
	Rho                      string
	Linker                   string
	Merkle                   string
	NumQueries               int
	NumClaims                int
	NumCommitGroups          int
	Constraints              int
	MatrixComputeTime        float64
	SetupTime                float64
	ProtocolSetupTime        float64
	CircuitSetupTime         float64
	CPLinkSetupTime          float64
	MatrixCommitTime         float64
	VectorComputeTime        float64
	VectorCommitTime         float64
	EncodingTime             float64
	CommitTime               float64
	TotalCommitTime          float64
	MerkleProveTime          float64
	CircuitProveTime         float64
	CPLinkProveTime          float64
	TotalProveTime           float64
	CommitAndProveTime       float64
	CircuitVerifyTime        float64
	MerkleVerifyTime         float64
	CPLinkVerifyTime         float64
	TotalVerifyTime          float64
	MerkleProofSize          int
	Groth16ProofSize         int
	CPLinkProofSize          int
	QueryCommitmentsSize     int
	TotalProofSize           int
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
	Repeat            int
	MatrixWorkers     int
	SetupMemory       Memory
	ProveMemory       Memory
	MatrixSource      string
	MatrixPath        string
	MatrixLoadTime    float64
}

func formatSeconds(seconds float64) string {
	return FormatDurationSeconds(seconds)
}

func FormatDurationSeconds(seconds float64) string {
	if seconds < 1 {
		return fmt.Sprintf("%.2f ms", seconds*1000)
	}
	return fmt.Sprintf("%.2f s", seconds)
}
