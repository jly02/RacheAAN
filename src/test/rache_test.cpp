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
} // namespace rachetest