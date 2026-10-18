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

## Reusable Matrix Inputs

Square experiments (`lamp`, `lamp_batch`, `freivalds`, `freivalds_batch`) default
to `-matrix-source auto`. For dimension K, they look for
`matrices/matrices_k<K>.bin`. If present, the experiment loads A, B, and C and
skips computing C=AB. If absent, it generates one random A/B pair and computes
C on the CPU without saving a file. A malformed or unreadable file is an error.

Prepare reusable inputs separately:

```sh
# K=1024; save matrices/matrices_k1024.bin
go run ./cmd/matrices -log-k 10 -backend cpu

# Prepare several dimensions, K=128 through K=8192
go run ./cmd/matrices -log-k-min 7 -log-k-max 13 -backend cpu

# Require a saved dataset; fail if it is missing
sh scripts/run_bench.sh lamp --K 10 --matrix-source file

# Prove the same saved A*B=C in five batch entries
sh scripts/run_bench.sh lamp_batch --K 10 --batch 5 --matrix-source file

# Use existing LED datasets without copying them
sh scripts/run_bench.sh lamp --K 10 --matrix-dir ../LED/matrices

# Explicitly compute fresh inputs on CPU, even when a file exists
sh scripts/run_bench.sh lamp --K 10 --matrix-source generate
```

`LAMP_MATRIX_SOURCE` and `LAMP_MATRIX_DIR` in `.env` set the shared defaults for
all four square experiments. Flags override these defaults. Relative paths in
the environment file are resolved from the project root; relative paths passed
as flags are resolved from the working directory. The Docker script mounts the
selected host directory read-only at `/workspace/matrices`. Datasets are excluded
from Docker images.

Both batch experiments prepare one product once and reuse the same read-only
A/B/C in every batch entry, including when inputs are generated on CPU. The
batch circuit, encoding, commitments, and proof still process all entries.
Their input memory and matrix computation therefore describe one shared product,
not independently sampled products.

The binary format is compatible with LED: `LEDMAT01`, a big-endian uint64 K,
then row-major A/B/C with canonical 32-byte BN254 scalar-field elements. Loading
checks the header, dimension, exact file length, and canonical encoding; it does
not recompute AB. Existing datasets are never overwritten by the generator.

Matrix generation supports Apple Metal and NVIDIA CUDA, including disk-backed
block multiplication for large inputs. See [GPU matrix generation](docs/gpu.md)
for build instructions, device self-tests, and memory limits. GPU acceleration
applies to input generation; the LAMP/Freivalds proofs use their existing CPU
implementations. GPT-2 experiments retain their existing input-generation flow.

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

The LAMP timing columns (`lamp`, `lamp_batch`, and `lamp_gpt2`) use the
same definitions as LED. Durations are formatted in ms/s:

- `abc_commit_time`: ABC encoding, Pedersen commitments, and Merkle tree
  construction. In GPT-2 this covers the tensor commitment groups.
- `vector_compute_time`: challenge/query derivation and intermediate-vector
  computation, including vector encoding and sampled proof-input selection/packing.
  GPT-2 also includes query/RS-batch
  preparation, excluding separately timed domain setup.
- `vector_commit_time`: intermediate-vector Pedersen commitments and Merkle
  tree construction.
- `commit_time` = `abc_commit_time` + `vector_commit_time`.
- `total_commit_time` = `abc_commit_time` + `vector_compute_time` +
  `vector_commit_time`.
- `total_prove_time` = `circuit_prove_time` + `merkle_prove_time` +
  `cplink_prove_time`; input commitments and vector computation are excluded.
- `commit_and_prove_time` = `total_commit_time` + `total_prove_time`.

`encoding_time` remains a diagnostic subtotal already included in the three
commitment phase timers; do not add it again. Setup, input generation/loading,
witness construction and untimed checks are excluded from these totals.
Sampled ABC/vector blocks, external commitments and blindings are selected
before the CP-Link proof timer and counted in `vector_compute_time`. This also
applies to GPT-2 group-input selection. Allocation, validation and cryptographic
operations inside proof functions remain in the corresponding proof timers.
These totals sum measured phases rather than full process wall time.
Timing headers and meanings have changed; write results to a new CSV directory.

Square-experiment CSVs also record `MatrixSource`, `MatrixPath`, and
`MatrixLoadTime(s/ms)`. File inputs have zero `MatrixComputeTime`; loading time
is recorded separately. Compile-only runs do not load or generate matrices.
The separate generator appends sampling, computation, writing, checking, device,
and GPU setup/kernel timings to `benchmark/matrices/matrix_compute.csv`
(`-csv` or `LAMP_MATRIX_CSV` overrides the path). The experiment's compute column
does not include a previously saved dataset's generation time.

The added columns change the square CSV headers. Appending to an incompatible
old CSV fails; use a new output directory or start a fresh non-append run.

Each CSV output directory also contains `system_info.json`, which records the
CPU model, logical core count, RAM, OS, architecture, Go version, and timestamp
for the benchmark run.
