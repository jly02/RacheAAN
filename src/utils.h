#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <complex>
#include <seal/seal.h>

namespace che_utils {
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
} // namespace che_utils


#endif