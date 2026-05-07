cmake_minimum_required(VERSION 3.16)
project(virtual-device C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Path to libzcash-orchard-c source tree
set(LIBZCASH_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../libzcash-orchard-c"
    CACHE PATH "Path to libzcash-orchard-c source directory")

# Build libzcash-orchard-c in-tree without tests.
#
# audit C-2: starting with libzcash-orchard-c >= 5da4a77, the library
# defaults to USE_PLATFORM_RNG=1 — every integration MUST link a
# `random_buffer()` from a CSPRNG. The virtual device is a test fixture
# (not a real signer), so we opt into the LCG fallback to avoid pulling
# in an OS-RNG dependency. Determinism is acceptable here because the
# Rust integration tests assert on signature validity (which is
# deterministic given fixed scalars), not unpredictability.
add_compile_definitions(USE_PLATFORM_RNG=0 ZORCHARD_INSECURE_LCG=1)

set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${LIBZCASH_SOURCE_DIR} libzcash EXCLUDE_FROM_ALL)

add_executable(virtual-device
    virtual_device.c
    tcp_transport.c
    wallet_test.c
)

target_link_libraries(virtual-device PRIVATE zcash-orchard-c)

target_include_directories(virtual-device PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBZCASH_SOURCE_DIR}/include
    ${LIBZCASH_SOURCE_DIR}/src       # sinsemilla_s.h
    ${LIBZCASH_SOURCE_DIR}/tests     # test_vectors.h
)
