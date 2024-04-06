#ifndef INCHE_H
#define INCHE_H

#include <stddef.h>
#include <complex>
#include "seal/seal.h"

namespace inche {
    /**
     * IncHE is a simple encryption idea that is based on a basic
     * incremental operation.
     */
    class Inche {
    public:
        /**
         * @brief Construct a new IncHE encryption scheme object.
         * 
         * @param scheme the encryption scheme to be used (BFV, BGV, CKKS)
         */
        Inche(seal::scheme_type scheme);

        /**
         * @brief Encrypts a value using the IncHE scheme, storing the result in the destination parameter.
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
        // the scheme being used for this Rache object
        seal::scheme_type scheme;

        // should be set in every scheme
        seal::Encryptor* enc;
        seal::Evaluator* eval;
        seal::Decryptor* dec;

        // base encryption is (m - 1) + one
        seal::Ciphertext one;

        // only used when scheme set to CKKS
        seal::CKKSEncoder* encoder;
        double scale;
    };
} // namespace inche

#endif