# MeowGo Quick Start

This repository contains Go implementations for Meow-style matrix
multiplication proof experiments and Freivalds baselines over gnark/Groth16.
It is intended as a lightweight artifact for reproducing comparison
experiments.

Implemented experiments:

- `meow`: square matrix multiplication with the Meow protocol.
- `freivalds`: square matrix multiplication Freivalds baseline.
- `rectmeow`: rectangular matrix multiplication with the Meow protocol.
- `meow_gpt2`: Meow benchmark for one GPT-2 medium matmul-only layer.
- `freivalds_gpt2`: Freivalds baseline for the same GPT-2 matmul-only layer.

The GPT-2 experiments only include matrix multiplications. LayerNorm,
activation functions, softmax, tokenization, and language-model inference are
outside the benchmark scope.

## Requirements

Recommended:

- Docker

Optional local execution:

- Go `1.25.6`

The scripts build the Docker image from the included `Dockerfile` and mount the
`benchmark/` directory back into this repository.

## Setup

Create a local environment file:

```sh
cp .env.example .env
```

The default values in `.env.example` can be changed, but command-line flags
override them.

## Smoke Tests

Use `--compile` for quick checks. This compiles the circuit and records the
constraint count without running Groth16 proving.

```sh
sh scripts/run_bench.sh meow --K 10 --rho 1/2 --L 128 --compile
sh scripts/run_bench.sh freivalds --K 10 --compile
sh scripts/run_bench.sh rectmeow --rows 3 --inner 4 --cols 2 --rho 1/2 --L 2 --compile
```

GPT-2 smoke tests:

```sh
sh scripts/run_gpt2_bench.sh meow --seq 0 --rho 1/2 --L 1 --compile
sh scripts/run_gpt2_bench.sh freivalds --seq 0 --compile
```

Here `--seq s` means sequence length `2^s`.

## Running Benchmarks

Square Meow:

```sh
sh scripts/run_bench.sh meow --K 10 --rho 1/2 --L 128
```

The square Meow benchmark supports two CP-link backends:

```sh
sh scripts/run_bench.sh meow --K 10 --rho 1/2 --L 128 --linker sigma
sh scripts/run_bench.sh meow --K 10 --rho 1/2 --L 128 --linker qa_nizk
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

So `--rows 3 --inner 4 --cols 2` proves:

```text
A: 8 x 16
B: 16 x 4
C: 8 x 4
```

GPT-2 Meow:

```sh
sh scripts/run_gpt2_bench.sh meow --seq 7 --rho 1/2 --L 128 --linker sigma
sh scripts/run_gpt2_bench.sh meow --seq 7 --rho 1/2 --L 128 --linker qa_nizk
```

GPT-2 Freivalds:

```sh
sh scripts/run_gpt2_bench.sh freivalds --seq 7
```

The GPT-2 dimensions are fixed to GPT-2 medium:

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
sh scripts/run_gpt2_bench.sh meow --range --from 7 --to 10 --rho 1/2 --L 128 --compile
sh scripts/run_gpt2_bench.sh freivalds --range --from 7 --to 10 --compile
sh scripts/run_gpt2_bench.sh all --range --from 7 --to 10 --compile
```

For Meow GPT-2 with `L=128`, use `--from 6` or higher. Smaller sequence
lengths do not have large enough score/value codeword domains for 128 sampled
queries.

Remove `--compile` to run full proving and verification. Full proof runs can be
substantially slower, especially for GPT-2 benchmarks.

## Output

Benchmark CSV files are written under:

```text
benchmark/meow/
benchmark/freivalds/
benchmark/rectmeow/
benchmark/meow_gpt2/
benchmark/freivalds_gpt2/
```

The main timing columns include matrix computation, setup, proving, and
verification times.

Each CSV output directory also contains `system_info.json`, which records the
CPU model, logical core count, RAM, OS, architecture, Go version, and timestamp
for the benchmark run.

## Local Go Commands

If Go `1.25.6` is available locally, the Docker scripts are not required:

```sh
go test ./...
go run ./cmd/meow --K 10 --rho 1/2 --L 128 --compile
go run ./cmd/rectmeow --rows 3 --inner 4 --cols 2 --rho 1/2 --L 2 --compile
go run ./cmd/meow_gpt2 --seq 7 --rho 1/2 --L 128 --compile
```
