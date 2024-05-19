#include <iostream>
#include "seal/seal.h"
#include "racheal.h"
#include "inche.h"
#include "bench.h"

#define TEST_RACHE false

using namespace std;
using namespace seal;
using namespace racheal;
using namespace inche;

// print randomized array values + after decryption
const bool PRINT = true;

// size of random array to benchmark
const int SIZE = 50;

// number of initial ciphertexts to be cached
const int INIT_CACHE_SIZE = 30;

// minimum size of values to be benchmarked
// Inv: MIN_VAL > 0
const int MIN_VAL = 1;

// maximum size of values to be benchmarked
// If n = INIT_CACHE_SIZE, then should have something like MAX_VAL < 2^n
const int MAX_VAL = 100000;

// polynomial modulus degree to be kept consistent between pure CKKS and Rache
const size_t POLY_MODULUS_DEGREE = 32768;

/**
 * Some benchmarks to test performance differences for CKKS.
 */
void ckks_bench() {
    // set up params
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);

    // choose 60 bit primes for first and last (last should just be at least as large as first)
    // also choose intermediate primes to be close to each other
    params.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));

    // scale stabilization close to the intermediate primes
    double scale = pow(2.0, 55);

    // context gathers params
    SEALContext context(params);

    // generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
   
    // encryptor, evalutator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // encoder for ckks scheme
    CKKSEncoder encoder(context);

    // array of random integers to be encoded
    cout << "Generating random array of integers..." << endl;
    int random_arr[SIZE];
    initialize(random_arr, SIZE, MIN_VAL, MAX_VAL, PRINT);

    cout << "=========================================" << endl;
    cout << "Encrypting random array with pure CKKS..." << endl;
    cout << "=========================================" << endl;

    Plaintext plain;
    Ciphertext cipher;
    auto start = chrono::high_resolution_clock::now();
    // encode and encrypt small batch of numbers
    for (int i = 0; i < SIZE; i ++) {
        encoder.encode(random_arr[i], scale, plain);
        encryptor.encrypt(plain, cipher);
    }
    // timing this small test
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Encryption of " << SIZE << " numbers in CKKS took " << duration.count() 
         << " microseconds (" << duration.count() / SIZE << " us per operation" << ")." << endl;

    // saving for later calculation
    int encrypt_time = duration.count();

    // timing some number of additions
    Plaintext plain_one;
    encoder.encode(1, scale, plain_one);
    Ciphertext cipher_one;
    encryptor.encrypt(plain_one, cipher_one);

    // fully homomorphic additions
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < SIZE; i++) {
        evaluator.add_inplace(cipher_one, cipher_one);
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << SIZE << " fully-homomorphic additions in CKKS took " << duration.count() << " microseconds (" 
         << ((double) duration.count() / encrypt_time) * 100 << "\% of encryption time, " 
         << duration.count() / SIZE << " us per operation" << ")." << endl;

    // ctxt - ptxt additions
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < SIZE; i++) {
        evaluator.add_plain_inplace(cipher_one, plain_one);
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << SIZE << " ctxt-ptxt additions in CKKS took " << duration.count() << " microseconds (" 
         << ((double) duration.count() / encrypt_time) * 100 << "\% of encryption time, " 
         << duration.count() / SIZE << " us per operation" << ")." << endl;

    // one fully homomorphic multiplication
    start = chrono::high_resolution_clock::now();
    evaluator.multiply_inplace(cipher_one, cipher_one);
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "One fully-homomorphic multiplication in CKKS took " << duration.count() << " microseconds." << endl;

    // one ctxt - ptxt multiplication
    start = chrono::high_resolution_clock::now();
    evaluator.multiply_plain_inplace(cipher_one, plain_one);
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "One ctxt-ptxt multiplication in CKKS took " << duration.count() << " microseconds." << endl;

#if TEST_RACHE
    // Rache timing
    cout << endl;
    cout << "================================" << endl;
    cout << "Testing same array with Rache..." << endl;
    cout << "================================" << endl;

    // timing initialization
    start = chrono::high_resolution_clock::now();
    Rache rache(scheme_type::ckks, INIT_CACHE_SIZE);
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Initialization of Rache took " << duration.count() << " microseconds." << endl;
    
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
         << ((double) duration.count() / encrypt_time) * 100 << "\% of CKKS encryption time)." << endl;

    if(PRINT) {
        // print decrypted ciphertexts
        vector<double> output(SIZE);
        for (int i = 0; i < SIZE; i++) {
            Plaintext rache_plain;
            rache.decrypt(ctxt[i], rache_plain);
            vector<double> rache_decoded;
            encoder.decode(rache_plain, rache_decoded);
            output[i] = rache_decoded[0];
        }

        for (int i = 0; i < SIZE; i++) {
            cout << output[i] << " ";
        }

        cout << endl;
    }
#endif

    // Inche timing
    cout << endl;
    cout << "================================" << endl;
    cout << "Testing same array with Inche..." << endl;
    cout << "================================" << endl;

    // timing initialization
    start = chrono::high_resolution_clock::now();
    Inche inche(scheme_type::ckks);
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Initialization of Inche took " << duration.count() << " microseconds." << endl;
    
    // Store ciphertexts to check output later
    Ciphertext ctxti[SIZE];

    cout << "Encrypting random array with Inche..." << endl;
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < SIZE; i++) {
        inche.encrypt(random_arr[i], ctxti[i]);
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Encryption of " << SIZE << " numbers in Inche took " << duration.count() << " microseconds ("
         << ((double) duration.count() / encrypt_time) * 100 << "\% of CKKS encryption time)." << endl;
    
    if(PRINT) {
        // print decrypted ciphertexts
        vector<double> output(SIZE);
        for (int i = 0; i < SIZE; i++) {
            Plaintext inche_plain;
            inche.decrypt(ctxti[i], inche_plain);
            vector<double> inche_decoded;
            encoder.decode(inche_plain, inche_decoded);
            output[i] = inche_decoded[0];
        }

        for (int i = 0; i < SIZE; i++) {
            cout << output[i] << " ";
        }

        cout << endl;
    }
}



