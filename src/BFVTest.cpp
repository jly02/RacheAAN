#include <iostream>
#include "seal/seal.h"
#include "bench.h"

using namespace std;
using namespace seal;

// print randomized array values + after decryption
const bool PRINT = false;

// size of random array to benchmark
const int SIZE = 20;

// minimum size of values to be benchmarked
// Inv: MIN_VAL > 0
const int MIN_VAL = 1;

// maximum size of values to be benchmarked
const int MAX_VAL = 1024;

/**
 * Some benchmarks to test performance differences.
 */
void bfv_bench()
{
    // set up params
    EncryptionParameters params(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_plain_modulus(1024);
}

