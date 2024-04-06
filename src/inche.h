#ifndef INCHE_H
#define INCHE_H

#include <stddef.h>
#include <complex>
#include "seal/seal.h"

namespace iheal {
    /**
     * Rache allows the user to customize the poly_modulus_degree and scale
     * of the encryption scheme. Note that the poly_modulus_degree that is 
     * chosen has a great effect on the performance of the scheme. 
     */
    class Inche {
    public:
        /**
         * @brief Construct a new RacheAL encryption scheme object.
         * 
         * @param scheme the encryption scheme to be used (BFV, BGV, CKKS)
         * @param init_cache_size the initial number of ciphertexts to be cached (default 10)
         * @param radix the radix to be used for ciphertext construction (default 2)
         */
        Inche(seal::scheme_type scheme, size_t init_cache_size = 10, uint32_t radix = 2);

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
        // stores plaintexts for base ctxt construction
        std::vector<seal::Plaintext> radixes_plain;

        // these ciphertexts are used for randomization
        std::vector<seal::Ciphertext> radixes;

        // starting number of radixes to be cached
        size_t cache_size;

        // the radix to be used, for practical reasons shouldn't be made too large
        uint32_t r;

        // the scheme being used for this Rache object
        seal::scheme_type scheme;

        // should be set in every scheme
        seal::Encryptor* enc;
        seal::Evaluator* eval;
        seal::Decryptor* dec;

        // base cipher used to construct new ctxts
        seal::Ciphertext zero;

        // only used when scheme set to CKKS
        seal::CKKSEncoder* encoder;
        double scale;
    };
} // namespace iheal

#endif