cmake_minimum_required(VERSION 3.16)
if(APPLE)
    cmake_policy(SET CMP0167 OLD)
else()
    cmake_policy(SET CMP0167 NEW)
endif()
project(auth_loader LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_COMPILER_WORKS TRUE CACHE INTERNAL "")
set(CMAKE_CXX_COMPILER_WORKS TRUE CACHE INTERNAL "")
include(FetchContent)
FetchContent_Declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG 1.8.3
)
FetchContent_MakeAvailable(blake3)
add_subdirectory(${blake3_SOURCE_DIR}/c ${blake3_BINARY_DIR}/c EXCLUDE_FROM_ALL)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Boost CONFIG REQUIRED)
add_executable(auth main.cpp)
target_link_libraries(auth PRIVATE
    Boost::boost
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    Threads::Threads
    blake3
)
if(APPLE)
    target_link_libraries(auth PRIVATE
        "-framework IOKit"
        "-framework CoreFoundation"
    )
endif()
if(UNIX AND NOT APPLE)
    target_link_libraries(auth PRIVATE
        dl
        pthread
    )
endif()
if(WIN32)
    target_compile_definitions(auth PRIVATE _WIN32_WINNT=0x0A00)
    target_link_libraries(auth PRIVATE
        setupapi
        advapi32
        iphlpapi
        wbemuuid
        bcrypt
        ole32
        oleaut32
        crypt32
        user32
    )
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM|aarch64")
    target_compile_definitions(auth PRIVATE ARCH_ARM)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    target_compile_definitions(auth PRIVATE ARCH_X86_64)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686|x86")
    target_compile_definitions(auth PRIVATE ARCH_X86)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(auth PRIVATE -O3 -DNDEBUG)
endif()
