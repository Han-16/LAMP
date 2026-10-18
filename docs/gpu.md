# GPU matrix generation

The generator computes exact C=AB over the BN254 scalar field using the GPU
implementation ported from LED. Both GPU backends share `gpu/field.h` Montgomery
arithmetic and 8x8 tiled kernels. They do not use floating-point GEMM or Tensor
Cores. No additional Go dependency or GPU library is required by the experiments.

## Apple Metal

Run natively on macOS with Apple Command Line Tools and Python 3 installed:

```sh
bash scripts/build-gpu.sh metal
go run ./cmd/matrices -backend metal -self-test
go run ./cmd/matrices -backend metal -log-k 10
```

The build creates `bin/lamp-metal` and `bin/matmul-runtime.metal`. The helper
compiles the kernel through the Metal runtime. Full Xcode and offline
`metal`/`metallib` tools are not needed. Metal is unavailable in the Linux Docker
container; generate files on the host and let the experiment script mount them.

## NVIDIA CUDA

A compatible NVIDIA GPU, driver, and CUDA Toolkit (`nvcc`) are required:

```sh
bash scripts/build-gpu.sh cuda
go run ./cmd/matrices -backend cuda -self-test
go run ./cmd/matrices -backend cuda -log-k 10
```

The helper is `bin/lamp-cuda`; it uses visible device 0. Select a physical device
with `CUDA_VISIBLE_DEVICES`. `-gpu-helper` can specify a different helper path.
GPU errors stop generation; they do not silently switch the backend to CPU.
`-matrix-workers` controls the CPU backend only (0 uses GOMAXPROCS, capped at K).

## Large inputs

When K exceeds `-gpu-block-size` (default 2048, allowed 1..4096), the GPU path
keeps A/B/C on disk, multiplies padded blocks, and accumulates partial products.
Host working memory is O(block² + K), rather than O(K²).

```sh
go run ./cmd/matrices -backend metal \
  -log-k-min 7 -log-k-max 13 -gpu-block-size 2048
```

The file size is `16 + 96*K*K` bytes: about 6 GiB at K=8192 and 24 GiB at
K=16384. Block generation checks available disk space first. Smaller blocks
reduce memory use but increase helper launches and disk reads. Work remains
O(K³); GPU acceleration does not guarantee a speedup at every size.

The generator writes a temporary `.matrices-*.partial` file and publishes the
complete result without overwriting an existing dataset. Normal errors remove
the temporary file. A forced process termination can leave a partial file;
remove it only after confirming that its generator has stopped. Generation
cannot resume a partial file.

Block generation reduces preparation memory only. The experiment still loads
the full A/B/C and allocates encoding and proof data in memory.

## Validation and timings

`-self-test` compares actual GPU results against CPU products at K=1,7,8,9,17
and exercises disk-backed padding and block accumulation at K=9, block=4.
Each generated GPU product also passes an O(K²) CPU check using a fresh random
field vector before publication; it does not trigger a full CPU matrix product.

```sh
python3 scripts/test-field.py
GOCACHE=/tmp/lamp-go-build-cache go test ./matrix ./cmd/matrices
```

The Python check tests the shared arithmetic on the host. The Go tests exercise
the helper protocol and disk path with a host C++ reference helper. Actual device
execution requires the backend self-test; host tests do not validate CUDA/Metal
compilation or execution on their own.

The generator CSV records the backend, device, dataset path, sampling time,
computation time, writing time, checking time, and GPU setup/kernel time. Complete
computation time includes packing, process startup, transfers, synchronization,
and result conversion. Block computation also includes reading input blocks and
CPU accumulation. GPU setup/kernel columns are portions of the complete time.
Metal runtime compilation is included in setup and complete computation time.
Block sampling time includes writing A/B; writing time records C and publication.
