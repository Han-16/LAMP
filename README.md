# LAMP Quick Start

This repository contains Go implementations for `LAMP: Linear Verification of
Matrix Multiplication via Proximity Testing`, along with Freivalds baselines over
gnark/Groth16.
It is intended as a lightweight artifact for reproducing comparison
experiments.

Implemented experiments:

- `lamp`: square matrix multiplication with the LAMP protocol.
- `freivalds`: square matrix multiplication Freivalds baseline.
- `lamp_gpt2`: LAMP benchmark for one GPT-2 medium matmul-only layer.
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
sh scripts/run_bench.sh lamp --K 10 --rho 1/2 --L 128 --compile
sh scripts/run_bench.sh freivalds --K 10 --compile
```

GPT-2 smoke tests:

```sh
sh scripts/run_gpt2_bench.sh lamp --seq 0 --rho 1/2 --L 1 --compile
sh scripts/run_gpt2_bench.sh freivalds --seq 0 --compile
```

Here `--seq s` means sequence length `2^s`.

## Running Benchmarks

Square LAMP:

```sh
sh scripts/run_bench.sh lamp --K 10 --rho 1/2 --L 128
```

The square LAMP benchmark uses the QA-batch CP-link backend and supports two Merkle opening modes:

```sh
sh scripts/run_bench.sh lamp --K 10 --rho 1/2 --L 128 --merkle multi
```

Square Freivalds:

```sh
sh scripts/run_bench.sh freivalds --K 10
```

GPT-2 LAMP:

```sh
sh scripts/run_gpt2_bench.sh lamp --seq 7 --rho 1/2 --L 128 --linker qa_nizk --merkle multi
sh scripts/run_gpt2_bench.sh lamp --seq 7 --rho 1/2 --L 128 --linker qa_batch --merkle multi
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

Square LAMP and Freivalds:

```sh
sh scripts/run_bench.sh lamp --range --compile
sh scripts/run_bench.sh freivalds --range --compile
sh scripts/run_bench.sh all --range --compile
```

GPT-2 LAMP and Freivalds:

```sh
sh scripts/run_gpt2_bench.sh lamp --range --from 7 --to 10 --rho 1/2 --L 128 --compile
sh scripts/run_gpt2_bench.sh freivalds --range --from 7 --to 10 --compile
sh scripts/run_gpt2_bench.sh all --range --from 7 --to 10 --compile
```

For LAMP GPT-2 with `L=128`, use `--from 6` or higher. Smaller sequence
lengths do not have large enough score/value codeword domains for 128 sampled
queries.

Remove `--compile` to run full proving and verification. Full proof runs can be
substantially slower, especially for GPT-2 benchmarks.

## Output

Benchmark CSV files are written under:

```text
benchmark/lamp/
benchmark/freivalds/
benchmark/lamp_gpt2/
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
go run ./cmd/lamp --K 10 --rho 1/2 --L 128 --compile
go run ./cmd/lamp_gpt2 --seq 7 --rho 1/2 --L 128 --compile
```
