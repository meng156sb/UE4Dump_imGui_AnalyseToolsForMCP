#!/usr/bin/env bash
# Linux/aarch64 (and x86_64) counterpart of build_android.bat.
# Usage:
#   ./build_android.sh              incremental
#   ./build_android.sh clean        full rebuild
#   NDK_PATH=/path/to/ndk ./build_android.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
OUT_DIR="$ROOT/outputs/arm64-v8a"
CLEAN_FIRST=""

case "${1:-}" in
  clean|-c|rebuild) CLEAN_FIRST="--clean-first" ;;
esac

if [[ -z "${NDK_PATH:-}" ]]; then
  for candidate in \
      /root/android-ndk-r29 \
      /root/android-ndk-r27d \
      /root/sdk/android-ndk-r29 \
      /root/sdk/android-ndk-r27d \
      "$HOME/android-ndk-r29" \
      "$HOME/android-ndk-r27d"; do
    if [[ -f "$candidate/build/cmake/android.toolchain.cmake" ]]; then
      NDK_PATH="$candidate"
      break
    fi
  done
fi

if [[ -z "${NDK_PATH:-}" || ! -f "$NDK_PATH/build/cmake/android.toolchain.cmake" ]]; then
  echo "[ERROR] NDK not found. Set NDK_PATH to an Android NDK (r25+)." >&2
  echo "        Expected: \$NDK_PATH/build/cmake/android.toolchain.cmake" >&2
  exit 1
fi

CMAKE_BIN="${CMAKE:-$(command -v cmake)}"
NINJA_BIN="${NINJA:-$(command -v ninja)}"
if [[ -z "$CMAKE_BIN" ]]; then
  echo "[ERROR] cmake not on PATH" >&2
  exit 1
fi
if [[ -z "$NINJA_BIN" ]]; then
  echo "[ERROR] ninja not on PATH" >&2
  exit 1
fi

echo "============================================================"
echo " UMT Android Build (arm64-v8a)"
echo " Source : $ROOT"
echo " NDK    : $NDK_PATH"
echo " CMake  : $CMAKE_BIN"
echo " Ninja  : $NINJA_BIN"
if [[ -n "$CLEAN_FIRST" ]]; then
  echo " Mode   : FULL rebuild"
else
  echo " Mode   : incremental"
fi
echo "============================================================"

"$CMAKE_BIN" -S "$ROOT" -B "$BUILD_DIR" \
  -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA_BIN" \
  -DNDK_PATH="$NDK_PATH" \
  -DANDROID_STL=c++_static \
  -DUMT_GHIDRA=ON

"$CMAKE_BIN" --build "$BUILD_DIR" $CLEAN_FIRST -j"$(nproc)"

echo
echo "============================================================"
echo " BUILD SUCCESS!"
echo " Output: $OUT_DIR/UnrealMemoryTools"
file "$OUT_DIR/UnrealMemoryTools" || true
ls -lh "$OUT_DIR/UnrealMemoryTools"
echo "============================================================"
