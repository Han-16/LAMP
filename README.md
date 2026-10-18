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
available to Docker. All six targets record stage-specific sampled RSS peaks
in a companion memory CSV.


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

All six LAMP and Freivalds targets accept `-repeat` (default 1, minimum 1).
The environment defaults are `LAMP_REPEAT`, `LAMP_BATCH_REPEAT`,
`LAMP_GPT2_REPEAT`, `FREIVALDS_REPEAT`, `FREIVALDS_BATCH_REPEAT`, and
`FREIVALDS_GPT2_REPEAT`. For example:

```sh
# Three complete measurements per k; two k values produce six individual rows.
go run ./cmd/lamp -all -from 7 -to 8 -repeat 3 -matrix-source file

# Three per (k, batch) configuration, or per GPT-2 sequence length.
go run ./cmd/lamp_batch -K 7 -batch 5 -repeat 3
go run ./cmd/lamp_gpt2 -seq 0 -repeat 3

# Freivalds uses the same repetitions and four output files.
go run ./cmd/freivalds -all -from 7 -to 8 -repeat 3
go run ./cmd/freivalds_batch -K 7 -batch 5 -repeat 3
go run ./cmd/freivalds_gpt2 -seq 0 -repeat 3

# Docker wrappers forward --repeat to all targets, including all mode.
sh scripts/run_bench.sh lamp --range --repeat 3
sh scripts/run_gpt2_bench.sh lamp --repeat 3
```

Each configuration prepares its input matrices/tensors once and shares them
read-only across repetitions. Every repetition creates fresh compilation,
setup keys, commitments and proofs, and verifies the proof before saving its
individual rows. Compilation remains outside all setup timers. Garbage
collection runs between repetitions, outside timers. In compile-only mode,
only circuit compilation and constraint reporting are repeated.

After every requested configuration in a command succeeds, `<stem>_average.csv`
records one row per configuration, with `runs` as its actual measurement count.
Times, proof sizes and per-repetition memory peaks use arithmetic means of the
original numeric measurements, before display rounding. Proof-size means use
two decimal places in bytes. A phase's mean RSS is empty if any repetition
could not measure it; unmeasured phases and LAMP's unavailable verifier MSM
metrics also stay empty. Shared input computation/loading times are retained
as metadata rather than recomputed or averaged.

Averages use only this command's measurements. Append mode adds a new summary
under a new `run_id`, without mixing previous invocations. An interrupted or
failed command preserves completed individual rows and produces no summary for
that invocation. Docker range wrappers invoke one command per configuration,
so each successful configuration appends its own summary. The repeat option
applies to all six targets.

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

The LAMP outputs (`lamp`, `lamp_batch`, and `lamp_gpt2`) use LED's exact
36-column performance header and order, including `run_id`, `repeat`, and
`commit_mode` in every individual file. Each performance file also has
`<stem>_info.csv`, `<stem>_memory.csv`, and `<stem>_average.csv` companions. Corresponding data rows
in the three individual files describe the same experiment; keep them together
and use one writer per set. `run_id` identifies a command invocation; `repeat`
is the one-based repetition number.

The info CSV starts with LED's eleven columns: `run_id`, `repeat`,
`commit_mode`, `logk`, `rho`, `samples`, `matrix_source`, `matrix_path`,
`matrix_workers`, `matrix_compute_time`, `matrix_load_time`. LAMP-specific `linker`, `merkle`,
and `n` follow; batch adds `batch`, and GPT-2 adds `seq_log`, `seq_len`,
`num_claims`, and `num_commit_groups`. GPT-2 has no single square K/N, so
`logk` and `n` are empty. LAMP's encoded-column MSM commitments are recorded
as `commit_mode=legacy`, matching LED's algorithm naming. Generated square
inputs record the actual worker count; file inputs record zero.

Durations use LED's format: two decimal places, `ms` below one second and
`s` otherwise, with a space before the unit (for example `3.81 ms`, `1.23 s`).
The commit/prove timing definitions are:

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

`encoding_time` is the ABC/tensor encoding diagnostic already included in
`abc_commit_time`; vector encoding belongs to `vector_compute_time`.
`pedersen_commit_time` and `merkle_commit_time` split ABC/tensor commitments.
`commit_other_time` records residual bookkeeping outside these named timers
and is excluded from the commit totals. Do not add diagnostic subtotals again.
`circuit_setup_time` measures only `groth16.Setup()`, as in LED. Circuit
construction and compilation are not timed or included in `total_setup_time`.
The total remains protocol setup + circuit setup + CP-Link setup.
The LED-specific `d_agg_msm_time`, `q_h_msm_time`, and `verifier_msm_time`
columns are empty because LAMP has no corresponding separate verifier phases.

Setup, input generation/loading, witness construction and untimed checks are
excluded from the commit/prove totals.
Sampled ABC/vector blocks, external commitments and blindings are selected
before the CP-Link proof timer and counted in `vector_compute_time`. This also
applies to GPT-2 group-input selection. Allocation, validation and cryptographic
operations inside proof functions remain in the corresponding proof timers.
These totals sum measured phases rather than full process wall time.
Timing headers and meanings have changed; write results to a new CSV directory.

Square experiments record `matrix_source`, `matrix_path`, and
`matrix_load_time` in the info CSV. File inputs have zero `matrix_compute_time`;
loading time is recorded separately. Compile-only runs do not load or generate matrices.
The separate generator appends sampling, computation, writing, checking, device,
and GPU setup/kernel timings to `benchmark/matrices/matrix_compute.csv`
(`-csv` or `LAMP_MATRIX_CSV` overrides the path). The experiment's compute column
does not include a previously saved dataset's generation time.

Proof sizes follow LED's compressed payload accounting. `snark_proof_bytes`
is the native SNARK's `WriteTo(io.Discard)` byte count (serialization errors
are fatal). `merkle_proof_bytes` counts sibling hashes only.
`cplink_proof_bytes` counts each link's compressed G1 encoding (32 B), and
`query_commitments_bytes` separately counts all transmitted query commitments
at 32 B per point, preserving repeated entries. `total_proof_bytes` sums these
four components. Statement roots, setup keys, and transport framing are excluded.
LAMP retains its own proof structure: square and batch have two links and two
sets of queried commitments; GPT-2 counts the actual sampled groups.

The memory CSV has nine columns: `run_id`, `repeat`, `commit_mode`, `logk`,
`rho`, followed by the four RSS-only measurements `peak_setup`, `peak_commit`,
`peak_prove`, and `peak`. Heap memory is not measured. For each repetition,
`peak = max(peak_commit, peak_prove)`; setup is excluded even when it is larger.
The same four columns appear in the average CSV. Its `peak` is the arithmetic
mean of the individual repetitions' peaks, computed before display rounding.

RSS is sampled at phase boundaries and every 10 ms. Disjoint intervals of the
same phase are merged by their maxima; Prove includes vector computation and
vector commitments. Values are absolute process resident memory, not allocations
attributable only to a phase. Values use MiB below 1 GiB and GiB otherwise, to
two decimal places. RSS is supported on Linux. Unsupported or unmeasured phases
are empty (including compile-only runs). `peak` is empty if either Commit or
Prove lacks RSS; an average is empty if any repetition lacks that measurement.

Appending (`BENCHMARK_APPEND_CSV=true`) checks the three individual headers and
data-row counts plus the average header before writing. Old CSVs are
incompatible; use a new output directory. A non-append run replaces the three
individual files and clears the previous average file. Existing measurements cannot
be converted to the new timing and size conventions by renaming headers.

Each CSV output directory also contains `system_info.json`, which records the
CPU model, logical core count, RAM, OS, architecture, Go version, and timestamp
for the benchmark run.

### Freivalds CSVs

Freivalds, Freivalds batch and Freivalds GPT-2 use the same performance header
as LAMP, with `_info.csv`, `_memory.csv`, and `_average.csv` companions.
Input source/path/workers and input computation/loading times live in info.
Batch adds `batch`; GPT-2 adds `seq_log`, `seq_len`, and `num_claims` there.
Their averages use the same raw-value arithmetic, grouping, append validation,
and success-only summary behavior as LAMP.

Freivalds has no external commitment, Merkle or CP-Link phases. Their timing
cells, as well as `commit_mode`, `rho`, `samples`, `linker`, `merkle`, and `n`,
are empty. The corresponding proof components are zero bytes; `snark_proof_bytes`
and `total_proof_bytes` both count the compressed Groth16 `WriteTo` serialization.
`circuit_setup_time` and `total_setup_time` count only Groth16 setup, excluding
compilation. `commit_and_prove_time` equals `total_prove_time`.

The memory CSV uses `peak_setup`, `peak_commit`, `peak_prove`, and `peak`.
Setup RSS covers Groth16 setup; prove RSS covers witness assignment, witness
construction and proof generation. `peak_commit` is empty because that phase
does not exist; `peak` equals `peak_prove`. Each average uses the mean of the
individual RSS peaks. RSS currently requires Linux (including Docker); unavailable
measurements stay empty, with no heap or process-lifetime peak fallback.
Compile-only mode leaves all timing and RSS cells empty and counts constraints.

The previous single-file Freivalds schema cannot be appended to this format.
Choose a new output directory when retaining earlier results.
