#include <iostream>
#include "seal/seal.h"
#include "seal/util/rlwe.h"
#include "seal/util/polyarithsmallmod.h"
#include "racheal.h"
#include "bench.h"

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace racheal;

// print randomized array values + after decryption
const bool PRINT = false;

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
void cipher_stream() {
    // set up params
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);

    // choose 60 bit primes for first and last (last should just be at least as large as first)
    // also choose intermediate primes to be close to each other
    params.set_coeff_modulus(CoeffModulus::Create(POLY_MODULUS_DEGREE, { 60, 40, 40, 60 }));

    auto coeffs = CoeffModulus::Create(POLY_MODULUS_DEGREE, { 60, 40, 40, 60 });
    for (auto coeff : coeffs) {
        cout << *(coeff.data()) << " ";
    }

    cout << endl;

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

    // grab underlying ciphertext (polynomial coefficients)
    auto arr1 = seven_one.dyn_array();

    size_t iters = arr1.size();
    cout << "Size of CTXT is " << iters << endl;

    // print first few coefficients
    for (int i = 0; i < iters; i++) {
        if (PRINT) {
            cout << arr1[i] << " ";
        }
    }

    cout << endl;

    Plaintext result;
    vector<double> res;
    decryptor.decrypt(seven_one, result);
    encoder.decode(result, res);
    cout << "Decrypted result before noise addition: " << res[0] << endl;

    srand(time(0));

    int rand_max = 1;
    int rand_min = 1;

    // generate some stuff
    for(int i = 0; i < 10; i++) {
        cout << (rand() % rand_max) + rand_min << " ";
    }

    cout << endl;

    Ciphertext::ct_coeff_type* data = seven_one.data();

    // testing SEAL stuff
    auto prng = UniformRandomGeneratorFactory::DefaultFactory()->create();

    auto &coeff_modulus = params.coeff_modulus();
    auto &plain_modulus = params.plain_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = params.poly_modulus_degree();

    auto c0 = seven_one.data(0);
    auto c1 = seven_one.data(1);

    auto noise(allocate_poly(coeff_count, coeff_modulus_size, MemoryManager::GetPool()));
    for (int i = 0; i < 2; i++) {
        SEAL_NOISE_SAMPLER(prng, params, noise.get());
        RNSIter gaussian_iter(noise.get(), coeff_count);
        RNSIter dst_iter(seven_one.data(i), coeff_count);
        add_poly_coeffmod(gaussian_iter, dst_iter, coeff_modulus_size, coeff_modulus, dst_iter);
    }

    cout << endl;

    decryptor.decrypt(seven_one, result);
    encoder.decode(result, res);
    cout << "Decrypted result after noise addition: " << res[0] << endl;
}



