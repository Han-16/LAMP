# LAMP Quick Start
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22787398-blue.svg)](https://doi.org/10.5281/zenodo.22787398)

This repository contains Go implementations for `LAMP: Linear Verification of
Matrix Multiplication via Proximity Testing`, along with Freivalds baselines over
gnark/Groth16.
It is intended as a lightweight artifact for reproducing comparison
experiments.

Implemented experiments:

- `lamp`: square matrix multiplication with the LAMP protocol.
- `lamp_batch`: random-linear-combination batch LAMP for multiple square
  matrix multiplications.
- `freivalds`: square matrix multiplication Freivalds baseline.
- `freivalds_batch`: batched Freivalds baseline for multiple square matrix
  multiplications in one Groth16 proof.
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
override them for ad-hoc runs. LAMP runs use the QA-batch CP-link backend and
Merkle multiproofs; these are fixed and are not configured through `.env` or
command-line flags. The default number of sampled queries is `L=309`.

To run a one-off experiment with different parameters, pass flags after the
target name:

```sh
sh scripts/run_bench.sh lamp --K 10 --rho 1/2 --L 309
sh scripts/run_bench.sh lamp_batch --K 10 --rho 1/2 --L 309 --batch 5
sh scripts/run_bench.sh lamp --range --from 7 --to 13
sh scripts/run_bench.sh lamp_batch --batch-range --batch-from 1 --batch-to 10
sh scripts/run_gpt2_bench.sh lamp --seq 7 --rho 1/2 --L 309
sh scripts/run_gpt2_bench.sh lamp --range --from 7 --to 10
```

Here `--K 10` means square matrix dimension `K=2^10`, and `--seq 7` means GPT-2
sequence length `2^7`.

Range scripts run one configuration per fresh container, sequentially. No CPU
or memory limit is applied, so each benchmark process can use all resources
available to Docker, and each CSV `PeakMemory(B)` value is an independent peak
RSS measurement.


## Running Benchmarks

Square LAMP:

```sh
sh scripts/run_bench.sh lamp
```

Square LAMP batch:

```sh
sh scripts/run_bench.sh lamp_batch
```

Square Freivalds:

```sh
sh scripts/run_bench.sh freivalds
sh scripts/run_bench.sh freivalds_batch
```

GPT-2 LAMP:

```sh
sh scripts/run_gpt2_bench.sh lamp
```

GPT-2 Freivalds:

```sh
sh scripts/run_gpt2_bench.sh freivalds
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

Set `LAMP_ALL=true`, `LAMP_BATCH_RANGE=true`, `FREIVALDS_ALL=true`, or
`FREIVALDS_BATCH_RANGE=true` in `.env` for range runs.

```sh
sh scripts/run_bench.sh lamp
sh scripts/run_bench.sh lamp_batch
sh scripts/run_bench.sh freivalds
sh scripts/run_bench.sh freivalds_batch
sh scripts/run_bench.sh all
```

GPT-2 LAMP and Freivalds:

Set `LAMP_GPT2_ALL=true` or `FREIVALDS_GPT2_ALL=true` in `.env`.

```sh
sh scripts/run_gpt2_bench.sh lamp
sh scripts/run_gpt2_bench.sh freivalds
sh scripts/run_gpt2_bench.sh all
```

Set the range bounds and batch-size ranges in `.env` before running these
commands.

## Output

Benchmark CSV files are written under:

```text
benchmark/lamp/
benchmark/lamp_batch/
benchmark/freivalds/
benchmark/freivalds_batch/
benchmark/lamp_gpt2/
benchmark/freivalds_gpt2/
```

The main timing columns include matrix computation, setup, proving, and
verification times.

Each CSV output directory also contains `system_info.json`, which records the
CPU model, logical core count, RAM, OS, architecture, Go version, and timestamp
for the benchmark run.
