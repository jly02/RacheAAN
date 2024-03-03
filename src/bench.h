#ifndef BENCH_H
#define BENCH_H

#include "seal/seal.h"

void ckks_bench();

void bfv_bench();

void cipher_stream();

// initializes an array with random values
inline void initialize(int arr[], int size, int MIN_VAL, int MAX_VAL, bool PRINT) {
    srand(time(0));

    for(int i = 0; i < size; i++) {
        if(MIN_VAL == MAX_VAL) {
            arr[i] = MIN_VAL;
        } else {
            arr[i] = (rand() + MIN_VAL) % MAX_VAL;
        }
    }

    if(PRINT) {
        for(int i = 0; i < size; i++) {
            std::cout << arr[i] << " ";
        }
    }

    std::cout << std::endl;
}

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
inline std::string uint64_to_hex_string(std::uint64_t value) {
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

#endif