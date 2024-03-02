#include "racheaan.h"

using namespace seal;
using namespace racheaan;

namespace racheaan 
{
    Rache::Rache(int init_cache_size) 
    {
        // vector should be initialized with a size so we can parallelize
        radixes = std::vector<Plaintext>(init_cache_size);

        EncryptionParameters params(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
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

        // generate base cipher and subtraction cipher
        Plaintext one_plain;
        encoder->encode(1, scale, one_plain);
        enc->encrypt(one_plain, one_base);
        enc->encrypt(one_plain, one_sub);

        // parallelize initialization, not necessary but minor
        // performance benefits can be gained
        parallel_for(init_cache_size, [&](int start, int end)
        {
            // encrypt powers of 2 up to init_cache_size 
            for(int i = start; i < end; i++) 
            {
                Plaintext radix_plain;
                encoder->encode(pow(2, i), scale, radix_plain);
                radixes[i] = radix_plain;
            }
        });
    }

    void Rache::encrypt(double value, Ciphertext &destination) 
    {
        // setting up indexed radixes
        int digits = floor(log2(value));
        int idx[digits];
        parallel_for(digits + 1, [&](int start, int end)
        {
            for (int j = start; j < end; j++) 
            {
                idx[j] = ((int) (value / pow(2.0, j))) % 2;
            }
        });

        // start with he(1)
        destination = one_base;
        for (int k = 0; k <= digits; k++) 
        {   
            for (int j = 1; j <= idx[k]; j++) 
            {
                eval->add_plain_inplace(destination, radixes[k]);
            }
        }

        // subtract he(1)
        eval->sub_inplace(destination, one_sub);
    }

    void Rache::decrypt(Ciphertext &encrypted, Plaintext &destination) 
    {
        dec->decrypt(encrypted, destination);
    }
} // namespace racheaan