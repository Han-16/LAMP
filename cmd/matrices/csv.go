package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"example.com/lamp/benchmark"
)

var csvHeader = []string{
	"backend", "device_name", "logk", "k", "matrix_workers", "matrix_path",
	"matrix_sample_time", "matrix_compute_time", "matrix_write_time", "gpu_setup_time", "gpu_kernel_time", "matrix_check_time",
}

type generationResult struct {
	Backend, Device            string
	GPUSetup, GPUKernel, Check time.Duration
	LogK, K, Workers           int
	Path                       string
	Sample, Compute, Write     time.Duration
}

func (r generationResult) record() []string {
	return []string{r.Backend, r.Device, strconv.Itoa(r.LogK), strconv.Itoa(r.K), strconv.Itoa(r.Workers), r.Path,
		formatDuration(r.Sample), formatDuration(r.Compute), formatDuration(r.Write), formatDuration(r.GPUSetup), formatDuration(r.GPUKernel), formatDuration(r.Check)}
}

func formatDuration(d time.Duration) string {
	return benchmark.FormatDurationSeconds(d.Seconds())
}

// Append creates the header once and refuses incompatible existing CSV files.
func appendGenerationCSV(path string, header, row []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if info.Size() == 0 {
		if err := w.Write(header); err != nil {
			return err
		}
	} else {
		// Do not silently mix incompatible benchmark formats in the same file.
		existing, err := csv.NewReader(f).Read()
		if err != nil {
			return err
		}
		if !slices.Equal(existing, header) {
			return fmt.Errorf("CSV header mismatch in %s; choose a new -csv path", path)
		}
	}
	if err := w.Write(row); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}
