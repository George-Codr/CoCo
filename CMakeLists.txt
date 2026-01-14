cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0167 NEW)
project(auth_loader LANGUAGES C CXX)   # ← Add C here! Critical for mixed C/C++ FetchContent

# Force CMake to accept the compilers early (band-aid for corrupted detection)
set(CMAKE_C_COMPILER_WORKS   TRUE CACHE INTERNAL "Bypass compiler test")
set(CMAKE_CXX_COMPILER_WORKS TRUE CACHE INTERNAL "Bypass compiler test")

# Optional: If you still see policy/deprecation warnings from FetchContent
# cmake_policy(SET CMP0169 OLD)   # only if you see CMP0169 errors

# ────────────────────────────────────────────────────────────────
# Fetch BLAKE3
# ────────────────────────────────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG        1.8.3
)

FetchContent_MakeAvailable(blake3)

# Explicitly bring in the C subdirectory (where CMakeLists.txt lives)
add_subdirectory(${blake3_SOURCE_DIR}/c ${blake3_BINARY_DIR}/c EXCLUDE_FROM_ALL)

# ────────────────────────────────────────────────────────────────
# Rest of your file remains the same
# ────────────────────────────────────────────────────────────────
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(auth main.cpp)

target_include_directories(auth PRIVATE 
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(auth PRIVATE 
    Boost::system 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    nlohmann_json::nlohmann_json 
    Threads::Threads
    blake3   # ← links the static lib from BLAKE3's c/ dir
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(auth PRIVATE -O3 -DNDEBUG)
endif()
