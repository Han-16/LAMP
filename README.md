# LAMP

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.22787398-blue.svg)](https://doi.org/10.5281/zenodo.22787398)

Go implementations of **LAMP: Linear Verification of Matrix Multiplication via
Proximity Testing** and Freivalds baselines using gnark/Groth16. Experiments
cover square matrices, batches, and a GPT-2 medium matmul-only layer.

## Quick Start

Install Docker, then run from the repository root:

```sh
cp .env.example .env
sh scripts/run_bench.sh lamp --K 7 --repeat 3
```

Defaults are configured in [.env.example](.env.example); edit `.env` or override
them with command-line flags. `--K 7` means a matrix dimension of `2^7 = 128`.

To run **logk 7 through 13, three times each**, using saved A/B/C matrices:

```sh
sh scripts/run_bench.sh lamp \
  --range --from 7 --to 13 --repeat 3 \
  --matrix-source file --matrix-dir ./matrices
```

The directory must contain `matrices_k128.bin` through `matrices_k8192.bin`
for the seven powers of two. File mode loads A/B/C without recomputing the
product and stops if a required file is missing. LED matrix files are compatible;
use `--matrix-dir ../LED/matrices` to read them directly.

Other experiments use the same repetition option:

```sh
sh scripts/run_bench.sh freivalds --K 7 --repeat 3
sh scripts/run_bench.sh lamp_batch --K 7 --batch 5 --repeat 3
sh scripts/run_gpt2_bench.sh lamp --seq 7 --repeat 3
```

| Script | Targets |
| --- | --- |
| `scripts/run_bench.sh` | `lamp`, `lamp_batch`, `freivalds`, `freivalds_batch`, `all` |
| `scripts/run_gpt2_bench.sh` | `lamp`, `freivalds`, `all` |

`--seq` is the log2 sequence length. Batch experiments reuse one A/B/C product
across all batch entries. Each repetition uses the same inputs with fresh setup
keys and proofs, and verifies the proof before saving its result.

For local execution or CPU input generation, install Go **1.25.6**:

```sh
go run ./cmd/lamp -K 7 -repeat 3
go run ./cmd/matrices -log-k-min 7 -log-k-max 13 -backend cpu
```

Without `--matrix-source file`, square experiments default to `auto`: load an
existing dataset or generate inputs in memory. See [GPU matrix generation](docs/gpu.md)
for Metal/CUDA input generation.

## Input commitments and hashes

The square and batch ABC paths use the same RS encoding, Pedersen key derivation,
column MSMs, blinding generation, and SHA-256 Merkle primitives as LED's `legacy`
mode. The common source is `crypto/input_primitives.go`, mirrored in
`LED/protocol/input_primitives.go`; both use the same `gnark-crypto` version.
Each repository still builds independently.

Rows of all A/B/C matrices share one worker pool and write directly into the final
column layout. Each worker reuses its FFT buffer. Pedersen workers share the bases
and reuse their scalar buffers. Both pools are bounded by `GOMAXPROCS` and the
number of tasks, with one internal worker per FFT/MSM.

For input-stage comparisons over `m` products, use LED `--batch-size m` to match
LAMP's single combined batch. LED's default `b=1` performs separate group
commitments. LED `optimized` changes the order to commit original columns and
encode the resulting points; its point encoding is included in encoding time.

External Merkle hashes, query derivation, and QA-Link transcript hashes use
SHA-256. Merkle nodes and proof siblings retain the full 32-byte digest; G1/G2
transcript inputs use compressed point encodings. Only the final LAMP Merkle root
is reduced to a field element for the existing circuit interface. Circuit-linked
hashes remain MiMC, including the corresponding host computations.
Old keys, commitments, and proofs must be regenerated; saved A/B/C matrix files
can be reused.

Tests focus on proof relations, witness binding, Merkle/QA-Link tampering, and basic proof verification. Use the experiment commands above for performance measurements.

## Output

Results are saved in `benchmark/<target>/`, such as `benchmark/lamp/` or
`benchmark/freivalds_gpt2/`. Set the target's `*_OUTPUT_DIR` in `.env` to change
the location. A fresh run replaces previous outputs; use a new directory to
preserve earlier experiments.

For LAMP, `<stem>` is `lamp_benchmark_results`:

| File | Contents |
| --- | --- |
| `<stem>.csv` | Individual timings and proof sizes; 44 columns |
| `<stem>_info.csv` | Input source, path, workers, and computation/loading times; 15 columns |
| `<stem>_memory.csv` | Stage RSS peaks; 11 columns |
| `<stem>_average.csv` | One mean per configuration, with its `runs` count; 49 columns |
| `<stem>_config.csv` | Run IDs and LAMP/batch/GPT-2 settings, linked to result rows |
| `system_info.json` | CPU, RAM, OS, Go version, and timestamp |

The four result CSVs follow LED's header names and order. Corresponding rows in
the performance, info, and memory files describe the same measurement. Keep the
output files together. In config, `record_type` selects individual or average
results and `csv_row` is the one-based data-row number, excluding the header.

`m` records the number of matrix products: 1 for square runs, `batch` for
batch runs, and `num_claims` for GPT-2. LED's grouping parameters `b` and `g`
are `-`; they are not LAMP's batch size. `commit_mode=legacy` describes
LAMP's existing encoded-column MSM commitments. Freivalds has no external
commitment mode and records `-`.

The range example above produces **21 individual rows** in each of the three
measurement CSVs and **7 average rows**, excluding headers. Averages use raw
measurements before display rounding and do not mix earlier invocations.

- **Time:** `ms` or `s`. Circuit setup measures Groth16 setup only, excluding compilation.
- **Proof size:** compressed serialized payload sizes in bytes.
- **Memory:** RSS only, in `MiB` or `GiB`, supported on Linux/Docker.
  Headers are `setup_peak`, `commit_peak`, `prove_peak`, and `peak`, where
  `peak = max(commit_peak, prove_peak)`. The average uses each repetition's peak.
- **Missing values:** `-` means inapplicable or unmeasured, including LED-only
  folding, verifier MSM breakdowns, mid/cross commitments, unrecorded statement
  root sizes, distinct-query counts (`distinct_queries`), and transcript `context`.
  Real measured zeros remain numeric. Compile-only runs retain constraints
  but record `-` for unmeasured timings and proof sizes.
- **Input preparation:** file inputs record `-` for matrix workers and computation;
  generated inputs record `-` for file path and loading time.
- **Unavailable memory:** `-`, also in averages if any repetition lacks the metric.
  Freivalds has no external commit phase, so `commit_peak` is `-` and `peak = prove_peak`.

Older CSV schemas cannot be appended to the current format; use a new output directory.
