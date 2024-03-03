cmake_minimum_required(VERSION 3.13)

# Find GoogleTest package
find_package(GTest REQUIRED)
find_package(SEAL 4.1.1 EXACT REQUIRED)

# Set up test executable
add_executable(test_suite)

# Add test source files
target_sources(test_suite 
    PRIVATE 
        testrunner.cpp
        rache_test.cpp
        ${CMAKE_SOURCE_DIR}/racheal.cpp
)

# Link with GoogleTest and any other necessary libraries
target_link_libraries(test_suite PRIVATE GTest::GTest GTest::Main)
target_link_libraries(test_suite PRIVATE SEAL::seal)

# Include necessary directories for header files
target_include_directories(test_suite PRIVATE ${CMAKE_SOURCE_DIR})

# Optionally, you can add a custom command to run your tests after build
add_custom_command(
    TARGET test_suite
    POST_BUILD
    COMMAND ${CMAKE_BINARY_DIR}/bin/test_suite
)
