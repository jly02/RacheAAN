cmake_minimum_required(VERSION 3.13)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake)

project(RacheAL VERSION 0.0.1 LANGUAGES CXX)

# Import Microsoft SEAL
find_package(SEAL 4.1.1 EXACT REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

set(DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF)

add_executable(benchmarks)
target_sources(benchmarks 
    PRIVATE 
        utils.h
        bench.cpp
        CKKSTest.cpp 
        BFVTest.cpp
        BGVTest.cpp
        CipherStream.cpp
        DataSetRunner.cpp
        racheal.cpp
        inche.cpp 
)
if(TARGET SEAL::seal)
    target_link_libraries(benchmarks PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(benchmarks PRIVATE SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()

add_subdirectory(test)