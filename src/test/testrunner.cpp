#include "gtest/gtest.h"

/**
 * Entry point for Google Test unit tests.
 */
int main(int argc, char **argv) 
{
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}