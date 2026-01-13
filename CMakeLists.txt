cmake_minimum_required(VERSION 3.16)
project(auth_loader LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(CMAKE_CXX_COMPILER clang++)
endif()

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(auth main.cpp)

target_include_directories(auth PRIVATE ${Boost_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

target_link_libraries(auth PRIVATE Boost::system OpenSSL::SSL OpenSSL::Crypto nlohmann_json::nlohmann_json Threads::Threads)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(auth PRIVATE -O3 -s -DNDEBUG)
endif()
