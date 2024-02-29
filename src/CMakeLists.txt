cmake_minimum_required(VERSION 3.13)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake)

project(RacheAAN VERSION 0.0.1 LANGUAGES CXX)

# Import Microsoft SEAL
find_package(SEAL 4.1.1 EXACT REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

add_executable(RacheAAN)
target_sources(RacheAAN 
    PRIVATE 
        CKKSTest.cpp 
        racheaan.cpp
)
if(TARGET SEAL::seal)
    target_link_libraries(RacheAAN PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(RacheAAN PRIVATE SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()