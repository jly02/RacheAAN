#include "racheal.h"

using namespace seal;
using namespace racheal;

namespace racheal {
    Rache::Rache(scheme_type scheme, size_t init_cache_size, uint32_t radix) {
        // save radix and scheme type first for later operations
        this->scheme = scheme;
        r = radix;

        // vector should be initialized with a size so we can parallelize
        radixes = std::vector<Plaintext>(init_cache_size);
        cache_size = init_cache_size;

        EncryptionParameters params(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // branch based on scheme type
        switch (scheme) {
            case scheme_type::ckks:
                params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
                scale = pow(r, 40);
                break;

            case scheme_type::bfv: case scheme_type::bgv:
                params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
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
            Plaintext zero_plain;
            encoder = new CKKSEncoder(context);
            encoder->encode(0, scale, zero_plain);
            enc->encrypt(zero_plain, zero);
        } else {
            Plaintext zero_plain(uint64_to_hex_string(0));
            enc->encrypt(zero_plain, zero);
        }

        // parallelize initialization, not necessary but minor
        // performance benefits can be gained
        parallel_for(init_cache_size, [&](int start, int end) {
            // encrypt powers of 2 up to init_cache_size 
            for(int i = start; i < end; i++) {
                if (scheme == scheme_type::ckks) {
                    Plaintext radix_plain;
                    encoder->encode(pow(r, i), scale, radix_plain);
                    radixes[i] = radix_plain;
                } else {
                    Plaintext radix_plain(uint64_to_hex_string(pow(r, i)));
                    radixes[i] = radix_plain;
                }
            }
        });
    }

    void Rache::encrypt(double value, Ciphertext &destination) {
        // shouldn't encrypt anything larger than 2^cache_size - 1
        if (value > pow(r, cache_size) - 1) {
            throw std::invalid_argument(
                "Value to encrypt cannot be larger than " + std::to_string(pow(r, cache_size) - 1) + 
                    ", got: " + std::to_string(value)
            );
        }

        // setting up indexed radixes
        int digits = floor(log_base_r(r, value));
        int idx[digits];
        parallel_for(digits + 1, [&](int start, int end) {
            for (int j = start; j < end; j++) {
                idx[j] = ((int) (value / pow(r, j))) % r;
            }
        });

        // start with he(0)
        destination = zero;
        for (int k = 0; k <= digits; k++) {   
            for (int j = 1; j <= idx[k]; j++) {
                eval->add_plain_inplace(destination, radixes[k]);
            }
        }

        // randomization should eventually go here
    }

    void Rache::decrypt(Ciphertext &encrypted, Plaintext &destination) {
        dec->decrypt(encrypted, destination);
    }
} // namespace racheal