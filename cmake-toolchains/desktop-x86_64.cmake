# ============================================================
# Toolchain file for Desktop (x86_64 Linux)
# Purpose: Native OpenFHE build compatible with Pi build
# ============================================================

# ----------------------------
# Target system (native)
# ----------------------------
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Not cross-compiling
set(CMAKE_CROSSCOMPILING FALSE)

# ----------------------------
# Compilers (explicit, for reproducibility)
# ----------------------------
set(CMAKE_C_COMPILER   /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/bin/g++)

# ----------------------------
# Language standard
# ----------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----------------------------
# Native integer size (MUST match Pi build!)
# ----------------------------
set(NATIVE_SIZE 64 CACHE STRING "Native backend size for OpenFHE" FORCE)

# ----------------------------
# Default build options
# (override from CLI if needed)
# ----------------------------
set(BUILD_STATIC      OFF CACHE BOOL "Disable static libraries" FORCE)
set(BUILD_SHARED      ON  CACHE BOOL "Enable shared libraries" FORCE)
set(BUILD_EXAMPLES    ON CACHE BOOL "Enable examples" FORCE)
set(BUILD_BENCHMARKS  ON CACHE BOOL "Enable benchmarks" FORCE)
set(BUILD_UNITTESTS   ON CACHE BOOL "Enable unit tests" FORCE)
set(WITH_OPENMP       ON CACHE BOOL "Enable OpenMP" FORCE)
set(BUILD_SERIAL      ON CACHE BOOL "Enable serial" FORCE)
# ----------------------------
# Optional: mild optimizations
# (keep ABI-compatible with Pi)
# ----------------------------
set(CMAKE_C_FLAGS_INIT   "-O2")
set(CMAKE_CXX_FLAGS_INIT "-O2")

# ----------------------------
# Status output
# ----------------------------
message(STATUS "=== Desktop OpenFHE Toolchain ===")
message(STATUS "Compiler:     ${CMAKE_CXX_COMPILER}")
message(STATUS "NATIVE_SIZE:  ${NATIVE_SIZE}")
message(STATUS "Shared libs:  ${BUILD_SHARED}")
message(STATUS "================================")
