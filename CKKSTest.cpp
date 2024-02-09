#include <iostream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

/**
 * Small test file for initial commit.
 */
int main()
{
    // set up params
    EncryptionParameters params(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    params.set_poly_modulus_degree(poly_modulus_degree);

    // choose 60 bit primes for first and last (last should just be at least as large as first)
    // also choose intermediate primes to be close to each other
    params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    // scale stabilization with 2^40 scale, close to the intermediate primes
    double scale = pow(2.0, 40);

    // context gathers params
    SEALContext context(params);

    // generate keys
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // not necessary right now 
    /*
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    */
   
    // encryptor, evalutator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // encoder for ckks scheme
    CKKSEncoder encoder(context);

    Plaintext plain;
    Ciphertext cipher;
    auto start = chrono::high_resolution_clock::now();
    // encode and encrypt small batch of numbers
    for (int i = 1; i <= 5; i ++) {
        encoder.encode((double) i, scale, plain);
        encryptor.encrypt(plain, cipher);
    }
    // timing this small test
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop - start);
    cout << "Encryption of 5 numbers in CKKS took " << duration.count() << " milliseconds." << endl;


    vector<Ciphertext> ctxt;
    // encrypt small powers of 2
    for (int i = 0; i < 3; i++) {
        Plaintext radix_plain;
        encoder.encode(pow(2, i), scale, radix_plain);
        Ciphertext radix_cipher;
        encryptor.encrypt(radix_plain, radix_cipher);
        ctxt.push_back(radix_cipher);
    }

    // ensure encryption was correctly handled
    for (int i = 0; i < 3; i++) {
        Plaintext plain_result;
        decryptor.decrypt(ctxt.at(i), plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);
        cout << result.at(0) << " ";
    }

    cout << endl;

    // Manually construct some numbers [5, 4, 3, 2, 1]
    vector<Ciphertext> ctxt_constructed;
    Ciphertext constructed;

    start = chrono::high_resolution_clock::now();

    evaluator.add(ctxt.at(2), ctxt.at(0), constructed);
    ctxt_constructed.push_back(constructed);

    evaluator.add(ctxt.at(1), ctxt.at(1), constructed);
    ctxt_constructed.push_back(constructed);

    evaluator.add(ctxt.at(1), ctxt.at(0), constructed);
    ctxt_constructed.push_back(constructed);

    evaluator.add(ctxt.at(0), ctxt.at(0), constructed);
    ctxt_constructed.push_back(constructed);

    evaluator.add(ctxt.at(0), ctxt.at(0), constructed);
    evaluator.sub_inplace(constructed, ctxt.at(0));
    ctxt_constructed.push_back(constructed);

    cout << "First radix cipher scale: " << log2(ctxt.at(2).scale()) << " bits." << endl;
    cout << "Constructed cipher scale: " << log2(constructed.scale()) << " bits." << endl;

    stop = chrono::high_resolution_clock::now();
    duration = chrono::duration_cast<chrono::milliseconds>(stop - start);
    cout << "Encryption of 5 numbers with radix addition took " << duration.count() << " milliseconds." << endl;

    // ensure encryption was correctly handled
    for (int i = 0; i < 5; i++) {
        Plaintext plain_result;
        decryptor.decrypt(ctxt_constructed.at(i), plain_result);
        vector<double> result;
        encoder.decode(plain_result, result);
        cout << result.at(0) << " ";
    }

    cout << endl;

    // performing many additions to test scaling
    Plaintext scale_test_ptxt;
    encoder.encode(200.505, scale, scale_test_ptxt);
    Ciphertext scale_test_ctxt;
    encryptor.encrypt(scale_test_ptxt, scale_test_ctxt);
    cout << "Scale test initial: " << log2(scale_test_ctxt.scale()) << " bits." << endl;
    for (int i = 0; i < 1000; i++) {
        evaluator.add_inplace(scale_test_ctxt, ctxt.at(2));
    }

    cout << "Scale test after 1000 additions: " << log2(scale_test_ctxt.scale()) << " bits." << endl;
    decryptor.decrypt(scale_test_ctxt, scale_test_ptxt);
    vector<double> scale_test_dec;
    encoder.decode(scale_test_ptxt, scale_test_dec);
    cout << "Decoding scale test: " << scale_test_dec.at(0) << endl;

    return 0;
}

