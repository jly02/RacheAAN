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
const size_t POLY_MODULUS_DEGREE = 32768;

/**
 * Looking at Ciphertext data.
 */
void cipher_stream() {
    // set up params
    EncryptionParameters params(scheme_type::ckks);
    params.set_poly_modulus_degree(POLY_MODULUS_DEGREE);

    // choose 60 bit primes for first and last (last should just be at least as large as first)
    // also choose intermediate primes to be close to each other
    params.set_coeff_modulus(CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE));

    auto coeffs = CoeffModulus::BFVDefault(POLY_MODULUS_DEGREE);
    for (auto coeff : coeffs) {
        cout << *(coeff.data()) << " ";
    }

    cout << endl;

    cout << "Max bit count: " << CoeffModulus::MaxBitCount(POLY_MODULUS_DEGREE) << endl;

    // scale stabilization with 2^40 scale, close to the intermediate primes
    double scale = pow(2.0, log2(*(coeffs[2].data())));

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

    // create seven
    Ciphertext seven_one;

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

    Ciphertext::ct_coeff_type* data = seven_one.data();

    for (int i = 0; i < 10; i++) {
        cout << data[i] << " ";
    }
    cout << endl;

    // testing SEAL stuff
    auto prng = UniformRandomGeneratorFactory::DefaultFactory()->create();

    auto &parms = context.get_context_data(result.parms_id())->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    auto &plain_modulus = parms.plain_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    size_t coeff_count = parms.poly_modulus_degree();
    auto &context_data = *context.get_context_data(parms.parms_id());
    auto ntt_tables = context_data.small_ntt_tables();
    size_t encrypted_size = public_key.data().size();

    cout << coeff_modulus_size << " " << coeff_count << endl;

    cout << endl;

    auto start = chrono::high_resolution_clock::now();
    auto u(allocate_poly(coeff_count, coeff_modulus_size, MemoryManager::GetPool()));
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(stop - start);
    cout << "Allocating polynomial space: " << duration.count() << " microseconds." << endl;

    for (size_t j = 0; j < encrypted_size; j++) {
        cout << "===== ROUND " << j << " =====" << endl;

        start = chrono::high_resolution_clock::now();
        SEAL_NOISE_SAMPLER(prng, params, u.get());
        stop = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        cout << "Sampling noise: " << duration.count() << " microseconds." << endl;

        start = chrono::high_resolution_clock::now();
        RNSIter gaussian_iter(u.get(), coeff_count);
        stop = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        cout << "Seting up error iterator: " << duration.count() << " microseconds." << endl;

        start = chrono::high_resolution_clock::now();
        ntt_negacyclic_harvey(gaussian_iter, coeff_modulus_size, ntt_tables);
        stop = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        cout << "NTT: " << duration.count() << " microseconds." << endl;

        start = chrono::high_resolution_clock::now();
        RNSIter dst_iter(seven_one.data(j), coeff_count);
        stop = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        cout << "Seting up dest iterator: " << duration.count() << " microseconds." << endl;
        
        start = chrono::high_resolution_clock::now();
        add_poly_coeffmod(gaussian_iter, dst_iter, coeff_modulus_size, coeff_modulus, dst_iter);
        stop = chrono::high_resolution_clock::now();
        duration = chrono::duration_cast<chrono::microseconds>(stop - start);
        cout << "Polynomial additions: " << duration.count() << " microseconds." << endl;
    }

    cout << endl;

    cout << "Is valid for parameters: " << is_valid_for(seven_one, context) << endl;
    cout << "Is buffer valid: " << is_buffer_valid(seven_one) << endl;
    cout << "Is metadata valid: " << is_metadata_valid_for(seven_one, context) << endl;
    cout << "Is data valid: " << is_data_valid_for(seven_one, context) << endl;

    decryptor.decrypt(seven_one, result);
    encoder.decode(result, res);
    cout << "Decrypted result after noise addition: " << res[0] << endl;

    for (int i = 0; i < 10; i++) {
        cout << data[i] << " ";
    }
    cout << endl;

    cout << "Root: " << ntt_tables->get_root() << endl;
}



