// Prepare reusable dense A, B and C=AB datasets independently of LAMP setup.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"example.com/lamp/config"
	"example.com/lamp/matrix"
)

func main() {
	if err := config.LoadDotEnv(); err != nil {
		log.Fatal(err)
	}
	logK := flag.Int("log-k", 4, "matrix size exponent")
	min := flag.Int("log-k-min", 0, "first exponent (use with -log-k-max)")
	max := flag.Int("log-k-max", 0, "last exponent (inclusive)")
	step := flag.Int("log-k-step", 1, "exponent increment")
	dir := flag.String("matrix-dir", config.OutputDir("LAMP_MATRIX_DIR", "matrices"), "output directory")
	csvPath := flag.String("csv", config.OutputDir("LAMP_MATRIX_CSV", "benchmark/matrices/matrix_compute.csv"), "generation timing CSV; append one row per newly saved dataset")
	backend := flag.String("backend", "cpu", "matrix backend: cpu, metal, cuda (no fallback)")
	helper := flag.String("gpu-helper", "", "GPU helper binary; default bin/lamp-<backend>")
	gpuBlock := flag.Int("gpu-block-size", 2048, "GPU block dimension (1..4096); larger matrices use disk-backed multiplication")
	selfTest := flag.Bool("self-test", false, "test GPU against CPU and exit without creating datasets")
	workers := flag.Int("matrix-workers", 0, "multiplication workers; 0 uses GOMAXPROCS")
	flag.Parse()
	log.SetFlags(0)
	provided := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	first, last := *logK, *logK
	if provided["log-k-min"] || provided["log-k-max"] {
		if !provided["log-k-min"] || !provided["log-k-max"] || provided["log-k"] {
			log.Fatal("use both range bounds without -log-k")
		}
		first, last = *min, *max
	} else if provided["log-k-step"] {
		log.Fatal("log-k-step requires a range")
	}
	if first < 1 || last < first || last > 27 || *step < 1 || *workers < 0 {
		log.Fatal("require 1 <= min <= max <= 27, step >= 1, workers >= 0")
	}
	if *backend != "cpu" && *backend != "metal" && *backend != "cuda" {
		log.Fatal("backend must be cpu, metal, or cuda")
	}
	if *backend != "cpu" && provided["matrix-workers"] {
		log.Fatal("matrix-workers is only for the cpu backend")
	}
	if *gpuBlock < 1 || *gpuBlock > 4096 {
		log.Fatal("gpu-block-size must be between 1 and 4096")
	}
	if *backend == "cpu" && provided["gpu-block-size"] {
		log.Fatal("gpu-block-size is only for GPU backends")
	}
	if *selfTest {
		if *backend == "cpu" {
			log.Fatal("self-test requires metal or cuda")
		}
		if err := matrix.GPUSelfTest(*backend, *helper); err != nil {
			log.Fatal(err)
		}
		fmt.Println("GPU self-test: PASS")
		return
	}
	for exponent := first; exponent <= last; {
		if err := generate(*dir, exponent, *workers, *csvPath, *backend, *helper, *gpuBlock); err != nil {
			log.Fatal(err)
		}
		if *step > last-exponent {
			break
		}
		runtime.GC()
		exponent += *step
	}
}

func generate(dir string, logK, workers int, csvPath, backend, helper string, gpuBlock int) error {
	k := 1 << logK
	path := matrix.FilePath(dir, k)
	if _, err := os.Lstat(path); err == nil {
		fmt.Printf("Skip existing: %s (not revalidated)\n", path)
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	if workers > k {
		workers = k
	}
	if backend != "cpu" {
		workers = 0
	}
	fmt.Printf("Backend: %s\n", backend)
	fmt.Printf("Generate K=%d, workers=%d -> %s\n", k, workers, path)
	if backend != "cpu" && k > gpuBlock {
		stats, err := matrix.GenerateGPUFile(path, k, gpuBlock, backend, helper, os.Stdout)
		if err != nil {
			return err
		}
		return recordGeneration(csvPath, generationResult{
			LogK: logK, K: k, Workers: workers, Path: path,
			Backend: backend, Device: stats.GPU.Device,
			Sample: stats.Sample, Compute: stats.Compute, Write: stats.Write, Check: stats.Check,
			GPUSetup:  time.Duration(stats.GPU.SetupMS * float64(time.Millisecond)),
			GPUKernel: time.Duration(stats.GPU.KernelMS * float64(time.Millisecond)),
		})
	}
	start := time.Now()
	a, err := matrix.Random(k)
	if err != nil {
		return err
	}
	b, err := matrix.Random(k)
	if err != nil {
		return err
	}
	sampleTime := time.Since(start)
	fmt.Printf("Sample A,B: %s\n", formatDuration(sampleTime))
	start = time.Now()
	var c matrix.Matrix
	var stats matrix.GPUStats
	if backend == "cpu" {
		c = matrix.MultiplyWithWorkers(a, b, workers)
		stats.Device = "CPU (" + runtime.GOARCH + ")"
	} else {
		c, stats, err = matrix.MultiplyGPU(a, b, backend, helper)
		if err != nil {
			return err
		}
	}
	computeTime := time.Since(start)
	var checkTime time.Duration
	if backend != "cpu" {
		start = time.Now()
		if err := matrix.CheckProductRandom(a, b, c); err != nil {
			return err
		}
		checkTime = time.Since(start)
	}
	start = time.Now()
	if err := matrix.Save(path, a, b, c); err != nil {
		return err
	}
	writeTime := time.Since(start)
	result := generationResult{
		LogK: logK, K: k, Workers: workers, Path: path,
		Backend: backend, Device: stats.Device,
		Sample: sampleTime, Compute: computeTime, Write: writeTime, Check: checkTime,
		GPUSetup:  time.Duration(stats.SetupMS * float64(time.Millisecond)),
		GPUKernel: time.Duration(stats.KernelMS * float64(time.Millisecond)),
	}
	return recordGeneration(csvPath, result)
}

func recordGeneration(csvPath string, result generationResult) error {
	fmt.Printf("Device: %s; GPU setup: %.2f ms; kernel: %.2f ms; result check: %s\n", result.Device, float64(result.GPUSetup)/float64(time.Millisecond), float64(result.GPUKernel)/float64(time.Millisecond), formatDuration(result.Check))
	fmt.Printf("Compute C=AB: %s\n", formatDuration(result.Compute))
	fmt.Printf("Write file: %s\n", formatDuration(result.Write))
	if err := appendGenerationCSV(csvPath, csvHeader, result.record()); err != nil {
		return fmt.Errorf("dataset saved at %s, but CSV recording failed: %w", result.Path, err)
	}
	fmt.Printf("CSV saved: %s\n", csvPath)
	return nil
}
