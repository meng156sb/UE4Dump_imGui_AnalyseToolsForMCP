#!/usr/bin/env bash
# Direct Termux-clang build that does not go through CMake's Android NDK modules.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$ROOT/outputs/arm64-v8a"
OBJ_DIR="$ROOT/build-termux/obj"
CLANG="${CLANG:-/data/data/com.termux/files/usr/bin/clang++}"
KHRONOS="/root/sdk/khronos"

mkdir -p "$OUT_DIR" "$OBJ_DIR"

INC=(
  -I"$KHRONOS/Vulkan-Headers/include"
  -I"$KHRONOS/EGL-Registry/api"
  -I"$KHRONOS/OpenGL-Registry/api"
  -I"$ROOT/deps"
  -I"$ROOT/KittyMemoryEx"
  -I"$ROOT/src/GUI"
  -I"$ROOT/src/GUI/Android_draw"
  -I"$ROOT/src/GUI/Android_Graphics"
  -I"$ROOT/src/GUI/Android_my_imgui"
  -I"$ROOT/src/GUI/Android_touch"
  -I"$ROOT/src/GUI/ImGui"
  -I"$ROOT/src/GUI/ImGui/backends"
  -I"$ROOT/src/GUI/ImGui/misc/freetype"
  -I"$ROOT/src/GUI/ImGui/misc/git_freetype"
  -I"$ROOT/src/GUI/My_Utils"
  -I"$ROOT/src/GUI/native_surface"
  -I"$ROOT/third_party/ghidra_decomp"
  -I"$ROOT/third_party/ghidra_decomp/include"
  -I"$ROOT/include"
  -I"$ROOT/src"
)

DEFS=(
  -DkEXECUTABLE
  -DkNO_KEYSTONE
  -DNDEBUG
  -DUMT_GHIDRA=1
  -DVK_USE_PLATFORM_ANDROID_KHR
  -DIMGUI_IMPL_VULKAN_NO_PROTOTYPES
  -DIMGUI_ENABLE_FREETYPE
  -DIMGUI_DISABLE_DEBUG_TOOLS
)

mapfile -t SRCS < <(find \
  "$ROOT/KittyMemoryEx" \
  "$ROOT/src/UE" \
  "$ROOT/src/AutoFix" \
  "$ROOT/src/mcp" \
  "$ROOT/src/GUI/Android_draw" \
  "$ROOT/src/GUI/Android_Graphics" \
  "$ROOT/src/GUI/Android_my_imgui" \
  "$ROOT/src/GUI/Android_touch" \
  "$ROOT/src/GUI/ImGui" \
  "$ROOT/src/GUI/My_Utils" \
  -name '*.cpp' | grep -v '/zip/' | sort)

SRCS+=(
  "$ROOT/third_party/ghidra_decomp/GhidraDecompiler.cpp"
  "$ROOT/src/executable.cpp"
  "$ROOT/src/Dumper.cpp"
  "$ROOT/src/UPackageGenerator.cpp"
  "$ROOT/src/SDKExplorer.cpp"
  "$ROOT/deps/fmt/format.cc"
  "$ROOT/src/Utils/BufferFmt.cpp"
  "$ROOT/src/Utils/KittyCmdln.cpp"
  "$ROOT/src/Utils/ProgressUtils.cpp"
)

# ImGui GLOB does not recurse into misc/ except freetype; backends already included.
# Drop imgui examples if any leaked.
FILTERED=()
for s in "${SRCS[@]}"; do
  case "$s" in
    */examples/*|*/misc/fonts/*|*/misc/cpp/*) continue ;;
  esac
  FILTERED+=("$s")
done
SRCS=("${FILTERED[@]}")

echo "Compiling ${#SRCS[@]} translation units with $CLANG"
FAIL=0
PIDS=()
MAXJOBS="$(nproc)"
compile_one() {
  local src="$1"
  local rel="${src#$ROOT/}"
  local obj="$OBJ_DIR/${rel//\//_}.o"
  mkdir -p "$(dirname "$obj")"
  if [[ -f "$obj" && "$obj" -nt "$src" ]]; then
    return 0
  fi
  if ! "$CLANG" --target=aarch64-linux-android30 -c -O2 -std=c++20 -fPIC -fexceptions -fPIE \
      "${DEFS[@]}" "${INC[@]}" -w "$src" -o "$obj"; then
    echo "FAIL $rel" >&2
    return 1
  fi
  echo "OK   $rel"
}

running=0
for src in "${SRCS[@]}"; do
  compile_one "$src" &
  running=$((running+1))
  if (( running >= MAXJOBS )); then
    wait -n || FAIL=1
    running=$((running-1))
  fi
done
wait || FAIL=1

if (( FAIL != 0 )); then
  echo "compile failed" >&2
  exit 1
fi

mapfile -t OBJS < <(find "$OBJ_DIR" -name '*.o' | sort)
echo "Linking ${#OBJS[@]} objects"
"$CLANG" --target=aarch64-linux-android30 -O2 -fPIC -pie -o "$OUT_DIR/UnrealMemoryTools" \
  "${OBJS[@]}" \
  "$ROOT/src/GUI/ImGui/misc/git_freetype/arm64-v8a/libfreetype.a" \
  "$ROOT/third_party/ghidra_decomp/libdecomp.a" \
  -llog -landroid -lEGL -lGLESv3 -lvulkan -lz -ldl

echo
file "$OUT_DIR/UnrealMemoryTools"
ls -lh "$OUT_DIR/UnrealMemoryTools"
readelf -d "$OUT_DIR/UnrealMemoryTools" | grep NEEDED || true
echo "BUILD SUCCESS $OUT_DIR/UnrealMemoryTools"
