#include "racheaan.h"
#include "seal/seal.h"

using namespace seal;
using namespace racheaan;

namespace racheaan 
{
    Rache::Rache(size_t poly_modulus_degree, int init_cache_size) 
    {
        EncryptionParameters params(scheme_type::ckks);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
        scale = pow(2.0, 40);

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

        // and the encoder object
        encoder = new CKKSEncoder(context);

        // encrypt powers of 2 up to init_cache_size
        for (int i = 0; i < init_cache_size; i++) {
            Plaintext radix_plain;
            encoder->encode(pow(2, i), scale, radix_plain);
            Ciphertext radix_cipher;
            enc->encrypt(radix_plain, radix_cipher);
            radixes.push_back(radix_cipher);
        }
    }

    void Rache::encrypt(double value, Ciphertext &destination) 
    {
        // setting up indexed radixes
        int digits = floor(log2(value));
        int idx[digits];
        for (int j = 0; j <= digits; j++) 
        {
            idx[j] = ((int) (value / pow(2.0, j))) % 2;
        }

        // start with he(1)
        destination = radixes[0];
        for (int k = 0; k <= digits; k++) 
        {
            for (int j = 1; j <= idx[k]; j++) 
            {
                eval->add_inplace(destination, radixes[k]);
            }
        }

        // subtract he(1)
        eval->sub_inplace(destination, radixes[0]);
    }

    void Rache::decrypt(Ciphertext &encrypted, Plaintext &destination) {
        dec->decrypt(encrypted, destination);
    }
}