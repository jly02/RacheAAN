#include <stddef.h>
#include <complex>
#include "seal/seal.h"

#ifndef RACHEAAN_H
#define RACHEAAN_H

namespace racheaan
{
    /**
     * Rache allows the user to customize the poly_modulus_degree and scale
     * of the encryption scheme. Note that the poly_modulus_degree that is 
     * chosen has a great effect on the performance of the scheme. 
     */
    class Rache
    {
    public:
        /**
         * @brief Constructs a new RacheAAN encryption scheme object.
         * 
         * @param poly_modulus_degree the degree of the polynomial modulus
         * @param init_cache_size the initial number of ciphertexts to be cached
         */
        Rache(size_t poly_modulus_degree = 8192, int init_cache_size = 10);

        /**
         * @brief Encrypts a value using the Rache scheme.
         * 
         * @param value the value to be encrypted 
         */
        seal::Ciphertext encrypt(double value);
    private:
        std::vector<seal::Ciphertext> ctxt;
        seal::Encryptor* enc;
        seal::Evaluator* eval;
        seal::Decryptor* dec;
        seal::CKKSEncoder* encoder;
        double scale;
    };
}

#endif