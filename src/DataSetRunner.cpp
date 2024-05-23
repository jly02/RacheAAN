#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "inche.h"

using namespace inche;

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

    // Test setup
    std::cout << "Setting up encryption objects... ";
    Inche inche(seal::scheme_type::ckks);
    seal::Ciphertext ctxts[size];
    std::cout << "Done." << std::endl;

    std::cout << "Running data... ";
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < size; i++) {
        inche.encrypt(vals[i], ctxts[i]);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(stop - start);

    std::cout << "Done." << std::endl;
    std::cout << "Took " << duration.count() << " seconds." << std::endl;
}