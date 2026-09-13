#!/usr/bin/env bash
# Build UnrealMemoryTools with Termux clang while the full NDK tarball downloads.
# CMakeLists.txt always loads $NDK_PATH/build/cmake/android.toolchain.cmake, so
# we plant the Termux toolchain at that path via a stub tree.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build-termux}"
OUT_DIR="$ROOT/outputs/arm64-v8a"
CMAKE_BIN="$(command -v cmake)"
NINJA_BIN="$(command -v ninja)"

STUB="$ROOT/.termux-ndk-stub"
mkdir -p "$STUB/build/cmake" "$OUT_DIR"
cp -f "$ROOT/termux-android.toolchain.cmake" "$STUB/build/cmake/android.toolchain.cmake"

echo "============================================================"
echo " UMT Android Build (Termux clang fallback, arm64-v8a)"
echo " Source : $ROOT"
echo " StubNDK: $STUB"
echo "============================================================"

"$CMAKE_BIN" -S "$ROOT" -B "$BUILD_DIR" \
  -G Ninja \
  -DCMAKE_MAKE_PROGRAM="$NINJA_BIN" \
  -DNDK_PATH="$STUB" \
  -DUMT_GHIDRA=ON \
  -DCMAKE_BUILD_TYPE=Release

"$CMAKE_BIN" --build "$BUILD_DIR" -j"$(nproc)"

echo
echo "============================================================"
echo " BUILD SUCCESS (Termux clang fallback)"
echo " Output: $OUT_DIR/UnrealMemoryTools"
file "$OUT_DIR/UnrealMemoryTools" || true
ls -lh "$OUT_DIR/UnrealMemoryTools"
readelf -d "$OUT_DIR/UnrealMemoryTools" | grep NEEDED || true
echo "============================================================"
