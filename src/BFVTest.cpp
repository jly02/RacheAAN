#include <iostream>
#include "seal/seal.h"
#include "bench.h"

using namespace std;
using namespace seal;

// print randomized array values + after decryption
const bool PRINT = false;

// size of random array to benchmark
const int SIZE = 50;

// minimum size of values to be benchmarked
// Inv: MIN_VAL > 0
const uint64_t MIN_VAL = 1;

// maximum size of values to be benchmarked
const uint64_t MAX_VAL = 399;

/**
 * Some benchmarks to test performance differences.
 */
void bfv_bench()
{
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

    cout << "Encrypting random array with pure BFV..." << endl;

    Ciphertext cipher;
    auto start = chrono::high_resolution_clock::now();
    // encode and encrypt small batch of numbers
    for (int i = 0; i < SIZE; i ++) 
    {   
        Plaintext plain(uint64_to_hex_string(random_arr[i]));
        encryptor.encrypt(plain, cipher);
    }
    // timing this small test
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop - start);
    cout << "Encryption of " << SIZE << " numbers in BFV took " << duration.count() << " milliseconds." << endl;

    // set up test for some number of additions
    Plaintext plain_zero("0");
    Plaintext plain_plus("2");
    Ciphertext cipher_zero;
    Ciphertext cipher_plus;
    encryptor.encrypt(plain_zero, cipher_zero);
    encryptor.encrypt(plain_plus, cipher_plus);

    cout << "cipher_zero noise budget before additions: " 
         << decryptor.invariant_noise_budget(cipher_zero) << " bits." << endl;

    // perform large number of additions
    start = chrono::high_resolution_clock::now();
    for (int i = 0; i < SIZE; i++)
    {
        evaluator.add_plain_inplace(cipher_zero, plain_plus);
    }
    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::milliseconds>(stop - start);
    cout << SIZE << " homomorphic additions in BFV took " << duration.count() << " milliseconds." << endl;

    cout << "cipher_zero noise budget after " << SIZE << " plaintext additions: " 
         << decryptor.invariant_noise_budget(cipher_zero) <<  " bits." << endl;

    // check decrypted value is OK
    Plaintext decrypted;
    decryptor.decrypt(cipher_zero, decrypted);
    cout << "Decryption result of " << SIZE << " additions: 0x" << decrypted.to_string() << endl;
}

