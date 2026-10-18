package matrix

import (
	"fmt"
	"os"
	"time"
)

// Input holds one product; batch callers reuse its matrices as read-only inputs.
type Input struct {
	A, B, C       Matrix
	Source, Path  string
	Compute, Load time.Duration
}

// Prepare loads a complete dataset or computes one product on the CPU.
// Only a missing file triggers auto generation; malformed files are errors.
// Generated inputs stay in memory: cmd/matrices manages persistent datasets.
func Prepare(k int, source, dir string) (Input, error) {
	var input Input
	if k < 1 || k > 1<<27 {
		return input, fmt.Errorf("require 1 <= matrix dimension <= 2^27")
	}
	if source != "auto" && source != "file" && source != "generate" {
		return input, fmt.Errorf("matrix-source must be auto, file, or generate")
	}
	path := FilePath(dir, k)
	if source == "auto" {
		if _, err := os.Lstat(path); err == nil {
			source = "file"
		} else if os.IsNotExist(err) {
			source = "generate"
		} else {
			return input, fmt.Errorf("inspect matrix file %s: %w", path, err)
		}
	}
	input.Source = source
	if source == "file" {
		start := time.Now()
		var err error
		input.A, input.B, input.C, err = Load(path, k)
		input.Load = time.Since(start)
		input.Path = path
		if err != nil {
			return input, fmt.Errorf("load matrix file %s: %w; prepare it with cmd/matrices", path, err)
		}
		return input, nil
	}
	var err error
	input.A, err = Random(k)
	if err != nil {
		return input, err
	}
	input.B, err = Random(k)
	if err != nil {
		return input, err
	}
	start := time.Now()
	input.C = Multiply(input.A, input.B)
	input.Compute = time.Since(start)
	return input, nil
}
