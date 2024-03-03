#include "gtest/gtest.h"
#include "racheal.h"

using namespace racheal;

namespace rachetest {
    // tests encryption of small values works without errors
    TEST(RacheEncryptionTest, HandlesSmallValues) 
    {
        Rache rache(seal::scheme_type::ckks);
        seal::Ciphertext destination;
        EXPECT_NO_THROW(rache.encrypt(   1, destination));
        EXPECT_NO_THROW(rache.encrypt(  10, destination));
        EXPECT_NO_THROW(rache.encrypt( 500, destination));
        EXPECT_NO_THROW(rache.encrypt(1023, destination));
    }

    // test that Rache works with larger cache sizes
    TEST(RacheEncryptionTest, HandlesLargerCacheSize){
        Rache rache(seal::scheme_type::ckks, 16);
        seal::Ciphertext destination;
        EXPECT_NO_THROW(rache.encrypt(    1, destination));
        EXPECT_NO_THROW(rache.encrypt( 1000, destination));
        EXPECT_NO_THROW(rache.encrypt(10000, destination));
        EXPECT_NO_THROW(rache.encrypt(65535, destination));
    }

    // test that Rache throws exceptions properly
    TEST(RacheEncryptionTest, ThrowsExceptions){
        Rache rache(seal::scheme_type::ckks);
        seal::Ciphertext destination;
        EXPECT_THROW(rache.encrypt(1024, destination), std::invalid_argument);
    }
} // namespace rachetest