#include <iostream>
#include "seal/seal.h"
#include "racheal.h"
#include "bench.h"

using namespace std;
using namespace seal;
using namespace racheal;

// print randomized array values + after decryption
const bool PRINT = true;

// size of random array to benchmark
const int SIZE = 20;

// number of initial ciphertexts to be cached
const int INIT_CACHE_SIZE = 16;

// minimum size of values to be benchmarked
// Inv: MIN_VAL > 0
const int MIN_VAL = 1;

// maximum size of values to be benchmarked
// If n = INIT_CACHE_SIZE, then should have something like MAX_VAL < 2^n
const int MAX_VAL = 20000;

// polynomial modulus degree to be kept consistent between pure CKKS and Rache
const size_t POLY_MODULUS_DEGREE = 8192;

/**
 * Looking at Ciphertext data.
 */
void cipher_stream()
{
    // set up params
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);

    // choose 60 bit primes for first and last (last should just be at least as large as first)
    // also choose intermediate primes to be close to each other
    params.set_coeff_modulus(CoeffModulus::Create(POLY_MODULUS_DEGREE, { 60, 40, 40, 60 }));

    // scale stabilization with 2^40 scale, close to the intermediate primes
    double scale = pow(2.0, 40);

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

    // encrypt a few numbers
    Plaintext plain_one;
    encoder.encode(1, scale, plain_one);
    Ciphertext one;
    encryptor.encrypt(plain_one, one);

    Plaintext plain_two;
    encoder.encode(2, scale, plain_two);
    Ciphertext two;
    encryptor.encrypt(plain_two, two);

    Plaintext plain_four;
    encoder.encode(4, scale, plain_four);
    Ciphertext four;
    encryptor.encrypt(plain_four, four);

    // create sevens two different ways
    Ciphertext seven_one;
    Ciphertext seven_two;

    // first seven, add some "randomness" by
    // 7 = 1 + 2 + 4 + 2 - 1 - 1
    evaluator.add(one, two, seven_one);
    evaluator.add_inplace(seven_one, four);
    evaluator.add_inplace(seven_one, two);
    evaluator.sub_inplace(seven_one, one);
    evaluator.sub_inplace(seven_one, one);

    // second seven, add some "randomness" by
    // 7 = 1 + 2 + 4 + 4 - 2 - 2
    evaluator.add(one, two, seven_two);
    evaluator.add_inplace(seven_two, four);
    evaluator.add_inplace(seven_two, four);
    evaluator.sub_inplace(seven_two, two);
    evaluator.sub_inplace(seven_two, two);

    // grab underlying ciphertext (polynomial coefficients)
    auto arr1 = seven_one.dyn_array();
    auto arr2 = seven_two.dyn_array();

    // print coefficients
    for (int i = 0; i < arr1.size(); i++) 
    {
        cout << arr1[i] - arr2[i] << " ";
    }

    cout << endl;
}



