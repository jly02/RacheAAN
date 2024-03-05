#ifndef RACHEAL_H
#define RACHEAL_H

#include <stddef.h>
#include <complex>
#include "seal/seal.h"

namespace racheal {
    /**
     * Rache allows the user to customize the poly_modulus_degree and scale
     * of the encryption scheme. Note that the poly_modulus_degree that is 
     * chosen has a great effect on the performance of the scheme. 
     */
    class Rache {
    public:
        /**
         * @brief Construct a new RacheAAN encryption scheme object.
         * 
         * @param scheme the encryption scheme to be used (BFV, BGV, CKKS)
         * @param init_cache_size the initial number of ciphertexts to be cached (default 10)
         * @param radix the radix to be used for ciphertext construction (default 2)
         */
        Rache(seal::scheme_type scheme, size_t init_cache_size = 10, uint32_t radix = 2);

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
} // namespace racheal

/**
 * @brief Parallelize a basic for loop, should not be used for anything
 *        requiring concurrent access to the same object in any way.
 * 
 * @param nb_elements size of your for loop
 * @param functor(start,end)
 * your function processing a sub chunk of the for loop.
 * "start" is the first index to process (included) until the index "end"
 * (excluded)
 * @param use_threads enable / disable threads.
 */
static void parallel_for(unsigned nb_elements,
                         std::function<void (int start, int end)> functor,
                         bool use_threads = true) {
    // -------
    unsigned nb_threads_hint = std::thread::hardware_concurrency();
    unsigned nb_threads = nb_threads_hint == 0 ? 8 : (nb_threads_hint);

    unsigned batch_size = nb_elements / nb_threads;
    unsigned batch_remainder = nb_elements % nb_threads;

    std::vector<std::thread> my_threads(nb_threads);

    if(use_threads) {
        // Multithread execution
        for(unsigned i = 0; i < nb_threads; ++i) {
            int start = i * batch_size;
            my_threads[i] = std::thread(functor, start, start+batch_size);
        }
    } else {
        // Single thread execution (for easy debugging)
        for(unsigned i = 0; i < nb_threads; ++i) {
            int start = i * batch_size;
            functor(start, start + batch_size);
        }
    }

    // Deform the elements left
    int start = nb_threads * batch_size;
    functor(start, start + batch_remainder);

    // Wait for the other thread to finish their task
    if(use_threads) {
        std::for_each(my_threads.begin(), my_threads.end(), std::mem_fn(&std::thread::join));
    }
}

/**
 * Helper function: computes a logarithm base r
 */
inline double log_base_r(double r, double x) {
    return std::log(x) / std::log(r);
}

/**
 * Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
 */
inline std::string uint64_to_hex_string(std::uint64_t value) {
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

#endif