# LAMP Quick Start

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22787398-blue.svg)](https://doi.org/10.5281/zenodo.22787398)

Go implementations of **LAMP: Linear Verification of Matrix Multiplication via
Proximity Testing** and Freivalds baselines using gnark/Groth16.

## Requirements

- Docker for the benchmark scripts.
- Go **1.25.6** for optional local execution and matrix generation.

## Setup

Run from the repository root:

```sh
cp .env.example .env
```

Edit `.env` to change defaults. Command-line flags override these settings.
The scripts build the Docker image and save results to the host `benchmark/`
directory.

## Running Benchmarks

```sh
# Square matrix multiplication
sh scripts/run_bench.sh lamp --K 10 --rho 1/2 --L 309
sh scripts/run_bench.sh freivalds --K 10

# Multiple matrix multiplications
sh scripts/run_bench.sh lamp_batch --K 7 --batch 5
sh scripts/run_bench.sh freivalds_batch --K 7 --batch 5

# GPT-2 medium: one matmul-only layer
sh scripts/run_gpt2_bench.sh lamp --seq 7
sh scripts/run_gpt2_bench.sh freivalds --seq 7
```

`--K 10` means matrix dimension `2^10 = 1024`; `--seq 7` means sequence
length `2^7 = 128`. `--batch` sets the number of matrix products.
Add `--repeat 3` for three repetitions; the default is **1**.
GPT-2 experiments cover matrix multiplications only.

For local execution:

```sh
go run ./cmd/lamp -K 7 -repeat 1
```

## Range Runs

```sh
# Matrix dimensions: logk = 7 through 13
sh scripts/run_bench.sh lamp --range --from 7 --to 13 --repeat 1

# Number of matrix products: 1 through 10, at logk = 7
sh scripts/run_bench.sh lamp_batch --K 7 \
  --batch-range --batch-from 1 --batch-to 10 --repeat 1

# GPT-2 sequence lengths: log2 length = 7 through 10
sh scripts/run_gpt2_bench.sh lamp --range --from 7 --to 10 --repeat 1
```

Use the corresponding `freivalds` or `freivalds_batch` target for the baseline.

## Reusable Matrix Inputs

Generate A/B/C once, then reuse them without computing the product during
benchmark runs:

```sh
go run ./cmd/matrices -log-k-min 7 -log-k-max 13 -backend cpu

sh scripts/run_bench.sh lamp --range --from 7 --to 13 \
  --matrix-source file --matrix-dir ./matrices --repeat 1
```

The files are named `matrices_k<K>.bin`. The default input mode is `auto`,
which loads an existing file or generates inputs in memory. Use `file` to require
saved inputs, or `generate` to compute fresh inputs. Batch runs reuse one A/B/C
product across all entries.

See [GPU matrix generation](docs/gpu.md) for Metal/CUDA instructions.

## Output

Results are saved under `benchmark/<target>/`, such as `benchmark/lamp/`.
For LAMP, `<stem>` is `lamp_benchmark_results`:

| File | Contents |
| --- | --- |
| `<stem>.csv` | Timings and proof sizes for each repetition |
| `<stem>_average.csv` | Mean results for each configuration |
| `<stem>_info.csv` | Matrix input information |
| `<stem>_memory.csv` | Stage RSS peaks |
| `<stem>_config.csv` | Run configuration |
| `system_info.json` | Execution environment |

Start with `_average.csv` when comparing results. Times use `ms` or `s`, proof
sizes use bytes, and memory uses `MiB` or `GiB`. `-` indicates an unavailable or
inapplicable value. Choose a new output directory to preserve earlier results.
