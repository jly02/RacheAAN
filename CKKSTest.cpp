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
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);

    // encryptor, evalutator, and decryptor
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    // encoder for ckks scheme
    CKKSEncoder encoder(context);
    
    // poly_modulus_degree / 2, # of slots, each slot encodes a single real/complex number
    size_t slot_count = encoder.slot_count();

    // this gets implicitly padded with 0's to poly_modulus_degree / 2 when encoding
    vector<double> input{ 1.0, 2.0, 4.0, 8.0 };

    // make a Plaintext object for your input
    Plaintext plain_radices, plain_add1;
    encoder.encode(input, scale, plain_radices);
    encoder.encode(1.0, scale, plain_add1);

    // and a Ciphertext object holds the encrypted values
    Ciphertext enc_radices, enc_add1;
    encryptor.encrypt(plain_radices, enc_radices);
    encryptor.encrypt(plain_add1, enc_add1);

    // then we evaluate each of { 1.0, 2.0, 3.0, 4.0 } + 1.0, store in another ciphertext
    Ciphertext enc_result;
    evaluator.add(enc_radices, enc_add1, enc_result);

    // and decrypt using decryptor object
    Plaintext plain_result;
    decryptor.decrypt(enc_result, plain_result);

    // decoding back into normal
    vector<double> result;
    encoder.decode(plain_result, result);

    // print result
    for (auto i = 0; i < 4; i++) {
        cout << result.at(i) << ' ';
    }

    cout << endl;
    return 0;
}
