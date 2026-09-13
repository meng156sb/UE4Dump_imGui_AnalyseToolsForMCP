cmake_minimum_required(VERSION 3.10)
# 允许构建时覆盖：-DNDK_PATH=D:/ProgramerDevelop/ndk23
if(NOT DEFINED NDK_PATH)
    set(NDK_PATH E:/ndk/android-ndk-r29)
endif()
set(CMAKE_TOOLCHAIN_FILE ${NDK_PATH}/build/cmake/android.toolchain.cmake)
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_SYSTEM_VERSION 30)
set(ANDROID_PLATFORM 30)
set(ANDROID_ABI arm64-v8a)
# Match the release ELF (no libc++_shared.so). Must be set before project().
set(ANDROID_STL c++_static)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/outputs/${ANDROID_ABI})
# 导出 compile_commands.json：clangd / IDE 靠它拿到全部 -I 与宏定义。
# 不开的话编辑器只能用编译器的默认搜索路径，于是 deps/ 下的 nlohmann/json.hpp、
# KittyMemoryMgr.hpp 等一律报 "file not found"，满屏假错误（实际 ninja 构建是好的）。
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
project(UnrealMemoryTools)

option(UMT_GHIDRA "Enable ghidra-native ARM64 decompiler" ON)

set(KITTYMEMORY_PATH KittyMemoryEx)
file(GLOB KITTYMEMORY_SRC ${KITTYMEMORY_PATH}/*.cpp)

set(DEPS_PATH deps)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -O0 -g -std=c++20 -fexceptions -DDEBUG -DkNO_KEYSTONE -w")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O2 -s -std=c++20 -fexceptions -DNDEBUG -DkNO_KEYSTONE -w ")

file(GLOB UE_SRC src/UE/*.cpp)
file(GLOB UE_PROFILE_SRC src/UE/UEGameProfiles/*.cpp)
file(GLOB AUTOFIX_SRC src/AutoFix/*.cpp)
# MCP 命令服务（服务端）
file(GLOB MCP_SRC src/mcp/*.cpp)
file(GLOB MCP_ANALYSIS_SRC src/mcp/analysis/*.cpp)
list(APPEND MCP_SRC third_party/ghidra_decomp/GhidraDecompiler.cpp)
file(GLOB GUI_SRC
        src/GUI/Android_draw/*.cpp
        src/GUI/Android_Graphics/*.cpp
        src/GUI/Android_my_imgui/*.cpp
        src/GUI/Android_touch/*.cpp
        src/GUI/ImGui/*.cpp
        src/GUI/ImGui/backends/*.cpp
        src/GUI/ImGui/misc/freetype/*.cpp
        src/GUI/My_Utils/*.cpp)

include_directories(
        ${DEPS_PATH}
        ${KITTYMEMORY_PATH}
        src/GUI
        src/GUI/Android_draw
        src/GUI/Android_Graphics
        src/GUI/Android_my_imgui
        src/GUI/Android_touch
        src/GUI/ImGui
        src/GUI/ImGui/backends
        src/GUI/ImGui/misc/freetype
        src/GUI/ImGui/misc/git_freetype
        src/GUI/My_Utils
        src/GUI/native_surface)
if(UMT_GHIDRA)
    # libdecomp.hh and the Ghidra public headers live in the bundled include tree.
    include_directories(third_party/ghidra_decomp third_party/ghidra_decomp/include include)
endif()
link_libraries(-llog -landroid -lEGL -lGLESv3 -lvulkan -lz -ldl)

add_executable(UnrealMemoryTools ${UE_SRC} ${UE_PROFILE_SRC} ${AUTOFIX_SRC} ${MCP_SRC} ${MCP_ANALYSIS_SRC} ${GUI_SRC} src/executable.cpp src/Dumper.cpp src/UPackageGenerator.cpp src/SDKExplorer.cpp ${KITTYMEMORY_SRC} ${DEPS_PATH}/fmt/format.cc
        src/Utils/BufferFmt.cpp
        src/Utils/KittyCmdln.cpp
        src/Utils/ProgressUtils.cpp)

target_compile_definitions(UnrealMemoryTools PRIVATE
        kEXECUTABLE
        VK_USE_PLATFORM_ANDROID_KHR
        IMGUI_IMPL_VULKAN_NO_PROTOTYPES
        IMGUI_ENABLE_FREETYPE
        IMGUI_DISABLE_DEBUG_TOOLS)

target_link_libraries(UnrealMemoryTools PRIVATE
        ${CMAKE_SOURCE_DIR}/src/GUI/ImGui/misc/git_freetype/${ANDROID_ABI}/libfreetype.a)
if(UMT_GHIDRA)
    target_link_libraries(UnrealMemoryTools PRIVATE
        ${CMAKE_SOURCE_DIR}/third_party/ghidra_decomp/libdecomp.a)
    target_compile_definitions(UnrealMemoryTools PRIVATE UMT_GHIDRA=1)
endif()
