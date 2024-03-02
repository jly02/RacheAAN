#include "gtest/gtest.h"
#include "racheal.h"

using namespace racheal;

namespace rachetest {
    // tests encryption of small values works without errors
    TEST(RacheEncryptionTest, HandlesSmallValues) 
    {
        Rache rache;
        seal::Ciphertext destination;
        EXPECT_NO_THROW(rache.encrypt(   1, destination));
        EXPECT_NO_THROW(rache.encrypt(  10, destination));
        EXPECT_NO_THROW(rache.encrypt( 500, destination));
        EXPECT_NO_THROW(rache.encrypt(1024, destination));
    }
} // namespace rachetest