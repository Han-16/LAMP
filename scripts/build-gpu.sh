#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin
case "${1:-}" in
 metal)
  [[ "$(uname -s)" == Darwin ]] || { echo 'Metal must be built on macOS.' >&2; exit 1; }
  if ! xcrun --sdk macosx --find clang++ >/dev/null 2>&1; then
   echo 'Install Apple Command Line Tools with: xcode-select --install' >&2
   exit 1
  fi
  xcrun --sdk macosx clang++ -std=c++17 -O3 -fobjc-arc gpu/metal/main.mm -framework Foundation -framework Metal -o bin/lamp-metal
  # Package the shared arithmetic and kernel as one runtime-compilable source.
  # No offline metal/metallib tools, and no full Xcode app, are required.
  python3 - <<'METAL_SOURCE'
from pathlib import Path
field = Path('gpu/field.h').read_text().replace('#pragma once', '')
kernel = Path('gpu/metal/matmul.metal').read_text().replace('#include "field.h"', '')
Path('bin/matmul-runtime.metal').write_text(field + '\n' + kernel)
METAL_SOURCE
  ;;
 cuda)
  nvcc -std=c++17 -O3 gpu/cuda/matmul.cu -o bin/lamp-cuda
  ;;
 *) echo 'Usage: bash scripts/build-gpu.sh metal|cuda' >&2; exit 1;;
esac
