#include "racheal.h"
#include "utils.h"

using namespace seal;
using namespace racheal;
using namespace che_utils;

namespace racheal {
    Rache::Rache(scheme_type scheme, size_t init_cache_size, uint32_t radix) {
        // save radix and scheme type first for later operations
        this->scheme = scheme;
        r = radix;

        // vector should be initialized with a size so we can parallelize
        radixes_plain = std::vector<Plaintext>(init_cache_size);
        radixes  = std::vector<Ciphertext>(init_cache_size);
        cache_size = init_cache_size;

        EncryptionParameters params(scheme);
        size_t poly_modulus_degree = 16384;
        params.set_poly_modulus_degree(poly_modulus_degree);
        
        // branch based on scheme type
        switch (scheme) {
            case scheme_type::ckks:
                params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
                scale = sqrt(static_cast<double>(params.coeff_modulus().back().value()));
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
                    radixes_plain[i] = radix_plain;
                    enc->encrypt(radix_plain, radixes[i]);
                } else {
                    Plaintext radix_plain(uint64_to_hex_string(pow(r, i)));
                    radixes_plain[i] = radix_plain;
                    enc->encrypt(radix_plain, radixes[i]);
                }
            }
        });

        radixes.push_back(zero);
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
                eval->add_plain_inplace(destination, radixes_plain[k]);
            }
        }

        // randomizing the constructed ciphertext
        bool isSwap = rand() % 2;
        if (isSwap) {
            eval->add_inplace(destination, zero);
        }

        for (int j = 1; j < digits; j++) {
            isSwap = rand() % 2;
            if (isSwap) {
                eval->add_inplace(destination, radixes[j]);
                for (int k = 0; k < r; k++) {
                    eval->sub_inplace(destination, radixes[j - 1]);
                }
            }
        }
    }

    void Rache::decrypt(Ciphertext &encrypted, Plaintext &destination) {
        dec->decrypt(encrypted, destination);
    }
} // namespace racheal