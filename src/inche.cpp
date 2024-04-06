#include "inche.h"
#include "utils.h"

using namespace seal;
using namespace che_utils;

namespace iheal {
    Inche::Inche(scheme_type scheme) {
        EncryptionParameters params(scheme);
        size_t poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // branch based on scheme type
        switch (scheme) {
            case scheme_type::ckks:
                params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
                scale = pow(2, 40);
                break;

            case scheme_type::bfv: case scheme_type::bgv:
                params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
                params.set_plain_modulus(1024);
                break;
        }

        // gather params
        SEALContext context(params);

        // generate keys
        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();
        PublicKey public_key;
        keygen.create_public_key(public_key);

        // create the encryption objects
        enc  = new Encryptor(context, public_key);
        eval = new Evaluator(context);
        dec  = new Decryptor(context, secret_key);

        // set the encoder object, if using CKKS, then
        // encrypt the base ciphertext he(0)
        if (scheme == scheme_type::ckks) {
            Plaintext one_plain;
            encoder = new CKKSEncoder(context);
            encoder->encode(0, scale, one_plain);
            enc->encrypt(one_plain, one);
        } else {
            Plaintext one_plain(uint64_to_hex_string(0));
            enc->encrypt(one_plain, one);
        }
    }

    void Inche::encrypt(double value, seal::Ciphertext &destination) {
        destination = one;
        if (scheme == scheme_type::ckks) {
            Plaintext plain;
            encoder->encode(value - 1, scale, plain);
            eval->add_plain_inplace(destination, plain);
        } else {
            Plaintext plain(uint64_to_hex_string(value - 1));
            eval->add_plain_inplace(destination, plain);
        }
    }

    void Inche::decrypt(seal::Ciphertext &encrypted, seal::Plaintext &destination) {
        dec->decrypt(encrypted, destination);
    }
} // namespace iheal