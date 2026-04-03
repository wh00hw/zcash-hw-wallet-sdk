cmake_minimum_required(VERSION 3.16)
project(virtual-device C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Path to libzcash-orchard-c source tree
set(LIBZCASH_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../libzcash-orchard-c"
    CACHE PATH "Path to libzcash-orchard-c source directory")

# Build libzcash-orchard-c in-tree without tests
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
