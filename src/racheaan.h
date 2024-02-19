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
         * @brief Construct a new RacheAAN encryption scheme object.
         * 
         * @param poly_modulus_degree the degree of the polynomial modulus (8192 by default)
         * @param init_cache_size the initial number of ciphertexts to be cached (10 by default)
         */
        Rache(size_t poly_modulus_degree = 8192, int init_cache_size = 10);

        /**
         * @brief Construct a new RacheAAN encryption scheme object with default 8192 polynomial modulus.
         * 
         * @param init_cache_size the initial number of ciphertexts to be cached
         */
        Rache(int init_cache_size);

        /**
         * @brief Encrypts a value using the Rache scheme, storing the result in the destination parameter.
         * 
         * @param value the value to be encrypted 
         * @param destination the ciphertext to overwrite with encrypted value
         */
        void encrypt(double value, seal::Ciphertext &destination);

        /**
         * @brief Decrypts a ciphertext, storing the result in the destination parameter.
         * 
         * @param encrypted the ciphertext to be decrypted
         * @param destination the plaintext to be overwritten with the decrypted ciphertext
         */
        void decrypt(seal::Ciphertext &encrypted, seal::Plaintext &destination);

    private:
        std::vector<seal::Ciphertext> radixes;
        seal::Encryptor* enc;
        seal::Evaluator* eval;
        seal::Decryptor* dec;
        seal::CKKSEncoder* encoder;
        double scale;
    };
}

#endif