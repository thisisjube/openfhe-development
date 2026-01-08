# ============================================================
# Toolchain file for Raspberry Pi Zero 2
# Target: AArch64 (64-bit Raspberry Pi OS)
# Use-case: OpenFHE, static build, cross-compilation
# ============================================================

# ----------------------------
# Target system
# ----------------------------
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Tell CMake we are cross-compiling
set(CMAKE_CROSSCOMPILING TRUE)

# Avoid try-run executables during configure
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

# ----------------------------
# Compilers (exactly yours)
# ----------------------------
set(CMAKE_C_COMPILER   /usr/bin/aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER /usr/bin/aarch64-linux-gnu-g++)

# ----------------------------
# Architecture flags (exact)
# ----------------------------
set(CMAKE_C_FLAGS_INIT   "-mcpu=cortex-a53")
set(CMAKE_CXX_FLAGS_INIT "-mcpu=cortex-a53")

# ----------------------------
# Native integer size (OpenFHE)
# ----------------------------
set(NATIVE_SIZE 64 CACHE STRING "Native backend size for OpenFHE" FORCE)

# ----------------------------
# Build configuration defaults
# (can still be overridden from CLI)
# ----------------------------
set(BUILD_STATIC      ON  CACHE BOOL "Build static libraries" FORCE)
set(BUILD_SHARED      OFF CACHE BOOL "Disable shared libraries" FORCE)
set(BUILD_EXAMPLES    ON  CACHE BOOL "Build examples" FORCE)
set(BUILD_UNITTESTS   OFF CACHE BOOL "Disable unit tests" FORCE)
set(BUILD_BENCHMARKS  ON  CACHE BOOL "Build benchmarks" FORCE)
set(WITH_OPENMP       ON  CACHE BOOL "Enable OpenMP" FORCE)
set(BUILD_SERIAL      ON  CACHE BOOL "Enable Serial" FORCE)
# ----------------------------
# Status output (debug sanity)
# ----------------------------
message(STATUS "=== OpenFHE AArch64 Toolchain ===")
message(STATUS "C compiler:   ${CMAKE_C_COMPILER}")
message(STATUS "CXX compiler: ${CMAKE_CXX_COMPILER}")
message(STATUS "C flags:      ${CMAKE_C_FLAGS_INIT}")
message(STATUS "CXX flags:    ${CMAKE_CXX_FLAGS_INIT}")
message(STATUS "Native size:  ${NATIVE_SIZE}")
message(STATUS "Static build: ${BUILD_STATIC}")
message(STATUS "OpenMP:       ${WITH_OPENMP}")
message(STATUS "================================")
