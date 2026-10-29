package benchmark

import (
	"math"
	"strconv"
)

// FreivaldsCSV shares LAMP's aligned files, append checks and raw-value averages.
type FreivaldsCSV = LAMPCSV

func InitFreivaldsCSV(path string) (*FreivaldsCSV, error) {
	return initExperimentCSV(path, nil, false, true)
}

func InitFreivaldsBatchCSV(path string) (*FreivaldsCSV, error) {
	return initExperimentCSV(path, []string{"batch"}, false, true)
}

func InitFreivaldsGPT2CSV(path string) (*FreivaldsCSV, error) {
	return initExperimentCSV(path, []string{"seq_log", "seq_len", "num_claims"}, true, true)
}

func (set *LAMPCSV) commitMode() string {
	if set.freivalds {
		return ""
	}
	// Encoded-column MSM commitments correspond to LED's legacy algorithm.
	return "legacy"
}

func (set *LAMPCSV) samples(res LAMPResult) string {
	if set.freivalds {
		return ""
	}
	return strconv.Itoa(res.NumQueries)
}

func (set *LAMPCSV) memoryPeaks(res LAMPResult) [4]Memory {
	if set.freivalds {
		// No external commitment phase: the commit/prove peak is the prove peak.
		return [4]Memory{res.SetupMemory, {}, res.ProveMemory, res.ProveMemory}
	}
	return res.memoryPeaks()
}

func freivaldsMetrics(res FreivaldsResult) LAMPResult {
	missing := math.NaN()
	r := LAMPResult{
		Repeat: res.Repeat, LogK: res.LogK, Constraints: res.Constraints,
		MatrixSource: res.MatrixSource, MatrixPath: res.MatrixPath,
		MatrixWorkers: res.MatrixWorkers, MatrixComputeTime: res.MatrixComputeTime,
		MatrixLoadTime: res.MatrixLoadTime, SetupMemory: res.SetupMemory, ProveMemory: res.ProveMemory,
		CircuitSetupTime: res.SetupTime, SetupTime: res.SetupTime,
		CircuitProveTime: res.ProveTime, TotalProveTime: res.ProveTime, CommitAndProveTime: res.ProveTime,
		CircuitVerifyTime: res.VerifyTime, TotalVerifyTime: res.VerifyTime,
		Groth16ProofSize: res.ProofSize, TotalProofSize: res.ProofSize,
		ProtocolSetupTime: missing, CPLinkSetupTime: missing,
		PedersenCommitTime: missing, MerkleCommitTime: missing, MatrixCommitTime: missing,
		VectorComputeTime: missing, VectorCommitTime: missing, CommitTime: missing,
		EncodingTime: missing, VectorEncodingTime: missing, TotalCommitTime: missing,
		CPLinkProveTime: missing, MerkleProveTime: missing,
		CPLinkVerifyTime: missing, MerkleVerifyTime: missing,
	}
	if res.MatrixSource == "compile" {
		r.CircuitSetupTime, r.SetupTime = missing, missing
		r.CircuitProveTime, r.TotalProveTime, r.CommitAndProveTime = missing, missing, missing
		r.CircuitVerifyTime, r.TotalVerifyTime = missing, missing
	}
	return r
}

func AppendFreivaldsResultToCSV(set *FreivaldsCSV, res FreivaldsResult) error {
	return set.append(freivaldsMetrics(res), nil)
}

func AppendFreivaldsBatchResultToCSV(set *FreivaldsCSV, res FreivaldsBatchResult) error {
	metrics := freivaldsMetrics(FreivaldsResult{
		Repeat: res.Repeat, LogK: res.LogK, Constraints: res.Constraints,
		MatrixSource: res.MatrixSource, MatrixPath: res.MatrixPath, MatrixWorkers: res.MatrixWorkers,
		MatrixComputeTime: res.MatrixComputeTime, MatrixLoadTime: res.MatrixLoadTime,
		SetupTime: res.SetupTime, ProveTime: res.ProveTime, VerifyTime: res.VerifyTime,
		ProofSize: res.ProofSize, SetupMemory: res.SetupMemory, ProveMemory: res.ProveMemory,
	})
	metrics.Instances = res.Batch
	return set.append(metrics, []string{strconv.Itoa(res.Batch)})
}

func AppendFreivaldsGPT2ResultToCSV(set *FreivaldsCSV, res FreivaldsGPT2Result) error {
	metrics := freivaldsMetrics(FreivaldsResult{
		Repeat: res.Repeat, Constraints: res.Constraints,
		MatrixSource: res.MatrixSource, MatrixPath: res.MatrixPath, MatrixWorkers: res.MatrixWorkers,
		MatrixComputeTime: res.MatrixComputeTime, MatrixLoadTime: res.MatrixLoadTime,
		SetupTime: res.SetupTime, ProveTime: res.ProveTime, VerifyTime: res.VerifyTime,
		ProofSize: res.ProofSize, SetupMemory: res.SetupMemory, ProveMemory: res.ProveMemory,
	})
	metrics.Instances = res.NumClaims
	return set.append(metrics, []string{strconv.Itoa(res.SeqLog), strconv.Itoa(res.SeqLen), strconv.Itoa(res.NumClaims)})
}
