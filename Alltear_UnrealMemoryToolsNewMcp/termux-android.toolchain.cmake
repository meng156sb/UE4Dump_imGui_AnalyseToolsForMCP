# Fallback toolchain: Termux clang + ndk-sysroot + Khronos headers.
# Used when a full aarch64-hosted NDK is not extracted yet.
# Produces an Android ELF (linker64). STL is Termux libc++_shared unless
# the NDK static STL is available.

set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 30)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(ANDROID TRUE)
set(ANDROID_ABI arm64-v8a)

set(TERMUX_PREFIX "/data/data/com.termux/files/usr")
set(KHRONOS_ROOT "/root/sdk/khronos")

set(CMAKE_C_COMPILER   "${TERMUX_PREFIX}/bin/clang")
set(CMAKE_CXX_COMPILER "${TERMUX_PREFIX}/bin/clang++")
set(CMAKE_ASM_COMPILER "${TERMUX_PREFIX}/bin/clang")
set(CMAKE_AR           "${TERMUX_PREFIX}/bin/llvm-ar")
set(CMAKE_RANLIB       "${TERMUX_PREFIX}/bin/llvm-ranlib")
set(CMAKE_STRIP        "${TERMUX_PREFIX}/bin/llvm-strip")
set(CMAKE_LINKER       "${TERMUX_PREFIX}/bin/ld.lld")
set(CMAKE_NM           "${TERMUX_PREFIX}/bin/llvm-nm")
set(CMAKE_OBJCOPY      "${TERMUX_PREFIX}/bin/llvm-objcopy")
set(CMAKE_OBJDUMP      "${TERMUX_PREFIX}/bin/llvm-objdump")

set(CMAKE_C_COMPILER_TARGET   aarch64-linux-android30)
set(CMAKE_CXX_COMPILER_TARGET aarch64-linux-android30)
set(CMAKE_ASM_COMPILER_TARGET aarch64-linux-android30)

set(_KHR_INC
  "-I${KHRONOS_ROOT}/Vulkan-Headers/include"
  "-I${KHRONOS_ROOT}/EGL-Registry/api"
  "-I${KHRONOS_ROOT}/OpenGL-Registry/api")
string(JOIN " " _KHR_INC_STR ${_KHR_INC})

set(CMAKE_C_FLAGS_INIT   "${_KHR_INC_STR} -fPIC -fPIE")
set(CMAKE_CXX_FLAGS_INIT "${_KHR_INC_STR} -fPIC -fPIE")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-pie -Wl,-rpath-link,/system/lib64 -L/system/lib64")

set(CMAKE_FIND_ROOT_PATH "${TERMUX_PREFIX}" "/system")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

# Pretend we have an NDK so existing CMakeLists ANDROID_ABI usage still works.
if(NOT DEFINED ANDROID_PLATFORM)
  set(ANDROID_PLATFORM 30)
endif()
