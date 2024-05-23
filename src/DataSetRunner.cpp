#include <iostream>
#include <fstream>
#include <string>

void datasets() {
    // Define the file name
    std::string filename = "covid19";
    
    // Create an ifstream object to read from the file
    std::ifstream infile(filename);
    
    // Check if the file was opened successfully
    if (!infile.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
    }
    
    // String to hold each line
    std::string line;
    
    // Read the file line by line
    while (std::getline(infile, line)) {
        // Process the line (for demonstration, we'll just print it)
        std::cout << line << std::endl;
    }
    
    // Close the file
    infile.close();
}