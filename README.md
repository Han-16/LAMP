# MeowGo Quick Start

This repository contains Go implementations of Meow-style matrix multiplication
proof experiments and Freivalds baselines over gnark/Groth16. It is intended as
a small artifact for reproducing comparison experiments.

The code currently provides:

- `meow`: square matrix multiplication benchmark.
- `freivalds`: square matrix multiplication Freivalds baseline.
- `rectmeow`: rectangular matrix multiplication benchmark.
- `meow_gpt2`: packed-QKV Meow benchmark for one GPT-2 medium matmul-only layer.
- `freivalds_gpt2`: Freivalds baseline for the same packed-QKV GPT-2 layer.

LayerNorm, activation functions, softmax, and tokenization are not included in
the GPT-2 benchmarks. The GPT-2 experiments only measure the matrix
multiplication structure.

## Requirements

Recommended:

- Docker

Optional local execution:

- Go `1.25.6`

The Docker path is preferred for reviewers because the scripts build the image
from the included `Dockerfile` and mount benchmark output back into this repo.

## Setup

Create a local environment file:

```sh
cp .env.example .env
```

The default values in `.env.example` are small enough for quick smoke tests.
Benchmark CSV files are written under `benchmark/`.

## Quick Smoke Tests

Compile-only runs are the fastest way to check that the artifact works.

```sh
sh scripts/run_bench.sh meow --K 10 --L 128 --compile
sh scripts/run_bench.sh freivalds --K 10 --compile
sh scripts/run_bench.sh rectmeow --rows 3 --inner 4 --cols 2 --L 2 --compile
```

For GPT-2 medium one-layer matmul-only benchmarks:

```sh
sh scripts/run_gpt2_bench.sh meow --seq 0 --rho 1/2 --L 1 --compile
sh scripts/run_gpt2_bench.sh freivalds --seq 0 --compile
```

Here `--seq 0` means sequence length `2^0 = 1`.

## Running Proof Benchmarks

Square Meow:

```sh
sh scripts/run_bench.sh meow --K 10 --rho 1/2 --L 128
```

Square Freivalds:

```sh
sh scripts/run_bench.sh freivalds --K 10
```

Rectangular Meow:

```sh
sh scripts/run_bench.sh rectmeow --rows 3 --inner 4 --cols 2 --rho 1/2 --L 2
```

For `rectmeow`, dimensions are log2 exponents:

```text
rows  = 2^--rows
inner = 2^--inner
cols  = 2^--cols
```

So `--rows 3 --inner 4 --cols 2` proves a multiplication of shapes:

```text
A: 8 x 16
B: 16 x 4
C: 8 x 4
```

GPT-2 Meow:

```sh
sh scripts/run_gpt2_bench.sh meow --seq 1 --rho 1/2 --L 1
```

GPT-2 Freivalds:

```sh
sh scripts/run_gpt2_bench.sh freivalds --seq 1
```

For GPT-2, `--seq s` means sequence length `2^s`. The model dimensions are
fixed to GPT-2 medium:

```text
embedding dimension D = 1024
number of heads       = 16
head dimension Dh     = 64
MLP dimension M       = 4096
```

## Range Runs

Square Meow and Freivalds:

```sh
sh scripts/run_bench.sh meow --range --compile
sh scripts/run_bench.sh freivalds --range --compile
sh scripts/run_bench.sh all --range --compile
```

GPT-2 Meow and Freivalds:

```sh
sh scripts/run_gpt2_bench.sh all --range --from 0 --to 4 --compile
```

If `MEOW_GPT2_L=128` is used, start the Meow GPT-2 range from `--from 6`
or higher because the score/value claims have sequence-length codeword
domains.

Remove `--compile` to run full proving and verification. Full proof runs can be
substantially slower, especially for GPT-2 Freivalds.

## Output Files

The scripts write CSV files to:

```text
benchmark/meow/meow_benchmark_results.csv
benchmark/freivalds/freivalds_benchmark_results.csv
benchmark/rectmeow/rectmeow_benchmark_results.csv
benchmark/meow_gpt2/meow_gpt2_benchmark_results.csv
benchmark/freivalds_gpt2/freivalds_gpt2_benchmark_results.csv
```

CSV timing columns place `MatrixComputeTime` before `SetupTime`.

## Running Without Docker

If Go `1.25.6` is available locally, commands can be run directly:

```sh
go test ./...
go run ./cmd/meow --K 10 --rho 1/2 --L 128 --compile
go run ./cmd/rectmeow --rows 3 --inner 4 --cols 2 --rho 1/2 --L 2 --compile
go run ./cmd/meow_gpt2 --seq 0 --rho 1/2 --L 1 --compile
```

## Notes for Reviewers

- `--compile` reports circuit size without Groth16 proving.
- Meow benchmarks include Groth16, Merkle membership, and CP-link checks in full
  runs.
- GPT-2 benchmarks use public input/output sequences and prove the matmul-only
  layer relation over generated random matrices.
- GPT-2 benchmarks use the packed-QKV computation graph by default:
  QKV is one projection, heads are concatenated, and the output projection is
  one matrix multiplication. The Meow variant uses a power-of-two packed QKV
  domain, so the actual 3D QKV columns are followed by a zero-padded 1D region.
- Benchmark defaults can be changed in `.env`.
