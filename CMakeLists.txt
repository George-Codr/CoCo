cmake_minimum_required(VERSION 3.16)
project(auth_loader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# ────────────────────────────────────────────────────────────────
# Fetch BLAKE3 (C implementation) ── pinned to latest stable release
# ────────────────────────────────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG        1.8.3
)

FetchContent_MakeAvailable(blake3)

# Add the C subdirectory explicitly (where the real CMake logic lives)
add_subdirectory(${blake3_SOURCE_DIR}/c ${blake3_BINARY_DIR}/c)

# ────────────────────────────────────────────────────────────────
# Existing dependencies
# ────────────────────────────────────────────────────────────────
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(auth main.cpp)

target_include_directories(auth PRIVATE 
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    # Usually not needed — blake3 target already propagates include dirs
    # ${blake3_SOURCE_DIR}/c
)

target_link_libraries(auth PRIVATE 
    Boost::system 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    nlohmann_json::nlohmann_json 
    Threads::Threads
    blake3               # ← this is the key addition
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(auth PRIVATE -O3 -s -DNDEBUG)
endif()
