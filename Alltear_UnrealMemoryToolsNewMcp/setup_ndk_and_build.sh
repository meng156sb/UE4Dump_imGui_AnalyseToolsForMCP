#!/usr/bin/env bash
# Extract the aarch64 NDK tarball (lzhiyong r29) then build UnrealMemoryTools.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SDK_DIR="${SDK_DIR:-/root/sdk}"
TARBALL="${TARBALL:-/data/data/com.termux/files/home/android-ndk-r29-aarch64.tar.xz}"
NDK_DIR="${NDK_PATH:-$SDK_DIR/android-ndk-r29}"

mkdir -p "$SDK_DIR"

if [[ ! -f "$NDK_DIR/build/cmake/android.toolchain.cmake" ]]; then
  if [[ ! -f "$TARBALL" ]]; then
    echo "[ERROR] NDK tarball not found: $TARBALL" >&2
    exit 1
  fi
  echo "[1/2] Extracting $(basename "$TARBALL") -> $SDK_DIR"
  tar -C "$SDK_DIR" -xJf "$TARBALL"
  # lzhiyong packs android-ndk-r29/ at the archive root; accept nearby names.
  if [[ ! -f "$NDK_DIR/build/cmake/android.toolchain.cmake" ]]; then
    found="$(find "$SDK_DIR" -maxdepth 2 -name android.toolchain.cmake | head -1 || true)"
    if [[ -n "$found" ]]; then
      NDK_DIR="$(cd "$(dirname "$found")/../.." && pwd)"
    fi
  fi
fi

if [[ ! -f "$NDK_DIR/build/cmake/android.toolchain.cmake" ]]; then
  echo "[ERROR] android.toolchain.cmake missing under $SDK_DIR" >&2
  ls -la "$SDK_DIR" >&2
  exit 1
fi

echo "NDK_PATH=$NDK_DIR"
export NDK_PATH="$NDK_DIR"
exec "$ROOT/build_android.sh" "$@"
