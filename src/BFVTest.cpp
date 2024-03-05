#include <iostream>
#include "seal/seal.h"
#include "bench.h"
#include "racheal.h"

using namespace std;
using namespace seal;
using namespace racheal;

// print randomized array values + after decryption
const bool PRINT = false;

// size of random array to benchmark
const int SIZE = 50;

// number of initial ciphertexts to be cached
const int INIT_CACHE_SIZE = 16;

// minimum size of values to be benchmarked
// Inv: MIN_VAL > 0
const uint64_t MIN_VAL = 1;

// maximum size of values to be benchmarked
const uint64_t MAX_VAL = 399;

/**
 * Some benchmarks to test performance differences.
 */
void bfv_bench() {
    // set up params
    EncryptionParameters params(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    params.set_poly_modulus_degree(poly_modulus_degree);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    params.set_plain_modulus(1024);

    // gather context
    SEALContext context(params);

    // generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // set up encryptor, evaluator, decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // array of random integers to be encoded
    cout << "Generating random array of integers..." << endl;
    int random_arr[SIZE];
    initialize(random_arr, SIZE, MIN_VAL, MAX_VAL, PRINT);

    cout << "========================================" << endl;
    cout << "Encrypting random array with pure BFV..." << endl;
    cout << "========================================" << endl;

    Ciphertext cipher;
    auto start = chrono::high_resolution_clock::now();
    // encode and encrypt small batch of numbers
    for (int i = 0; i < SIZE; i ++) {   
        Plaintext plain(uint64_to_hex_string(random_arr[i]));
        encryptor.encrypt(plain, cipher);
    }
    // timing this small test
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Encryption of " << SIZE << " numbers in BFV took " << duration.count() << " microseconds." << endl;

    // saving for later calculation
    int encrypt_time = duration.count();

        // Rache timing
    cout << endl;
    cout << "================================" << endl;
    cout << "Testing same array with Rache..." << endl;
    cout << "================================" << endl;

    // timing initialization
    start = chrono::high_resolution_clock::now();
    Rache rache(scheme_type::bfv, INIT_CACHE_SIZE);
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Initialization of cache took " << duration.count() << " microseconds." << endl;
    
    // Store ciphertexts to check output later
    Ciphertext ctxt[SIZE];

    cout << "Encrypting random array with Rache..." << endl;
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < SIZE; i ++) {
        rache.encrypt(random_arr[i], ctxt[i]);
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Encryption of " << SIZE << " numbers in Rache took " << duration.count() << " microseconds ("
         << ((double) duration.count() / encrypt_time) * 100 << "\% of BFV encryption time)." << endl;

    if(PRINT) {
        // print decrypted ciphertexts
        vector<double> output(SIZE);
        for (int i = 0; i < SIZE; i++) {
            Plaintext rache_plain;
            rache.decrypt(ctxt[i], rache_plain);
            output[i] = stoi(rache_plain.to_string());
        }

        for (int i = 0; i < SIZE; i++) {
            cout << output[i] << " ";
        }

        cout << endl;
    }
}

