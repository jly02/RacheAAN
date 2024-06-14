#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "inche.h"
#include "racheal.h"

using namespace inche;
using namespace racheal;

void datasets() {
    // Define the file name
    std::string filename;
    std::cout << "Enter file name: ";
    std::cin >> filename;
    std::ifstream infile(filename);
    
    // Check if the file was opened successfully
    if (!infile.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
    }

    std::cout << "Reading file... ";
    
    // Read the file line by line
    std::string line;
    std::vector<double> vals;
    while (std::getline(infile, line)) {
        vals.push_back(std::stod(line));
    }
    
    infile.close();

    std::cout << "Done." << std::endl;
    auto size = vals.size();
    std::cout << "Size of dataset: " << size << " objects." << std::endl;

    std::cout << "Choose scheme: [1] CKKS; [2] RacheCKKS; [3] Zinc: ";
    int scheme;
    std::cin >> scheme;

    // Test setup
    std::cout << "Setting up encryption objects... ";
    seal::Ciphertext ctxt;
    std::chrono::seconds duration;
    switch (scheme)
    {
    case 1:
    {
        seal::EncryptionParameters params(seal::scheme_type::ckks);
        params.set_poly_modulus_degree(32768);
    
        // choose 60 bit primes for first and last (last should just be at least as large as first)
        // also choose intermediate primes to be close to each other
        auto coeffs = seal::CoeffModulus::BFVDefault(32768);
        params.set_coeff_modulus(coeffs);
    
        // scale stabilization close to the intermediate primes
        double scale = pow(2.0, log2(*(coeffs[2].data())));
    
        // context gathers params
        seal::SEALContext context(params);
        
        // generate keys
        seal::KeyGenerator keygen(context);
        seal::SecretKey secret_key = keygen.secret_key();
        seal::PublicKey public_key;
        keygen.create_public_key(public_key);

        // encryptor
        seal::Encryptor encryptor(context, public_key);
        // encoder for ckks scheme
        seal::CKKSEncoder encoder(context);

        std::cout << "Running data... " << std::endl;
        seal::Plaintext plain;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < size; i++) {
            encoder.encode(vals[i], plain);
            encryptor.encrypt(plain, ctxt);
        }
        auto stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::seconds>(stop - start);
        break;
    }
    case 2:
    {
        Rache rache(seal::scheme_type::ckks, 32);

        std::cout << "Running data... " << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < size; i++) {
            rache.encrypt(vals[i], ctxt);
        }
        auto stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::seconds>(stop - start);
        break;
    }
    case 3:
    {
        Inche inche(seal::scheme_type::ckks);

        std::cout << "Running data... " << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < size; i++) {
            inche.encrypt(vals[i], ctxt);
        }
        auto stop = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::seconds>(stop - start);
        break;
    }
    default:
        break;
    }

    std::cout << "Done." << std::endl;
    std::cout << "Took " << duration.count() << " seconds." << std::endl;
}