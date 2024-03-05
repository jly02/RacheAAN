# RacheAL
Rache is a radix-based homomorphic encryption algorithm that utilizes a base scheme, leveraging the fact that in practical usage, homomorphic operations have far lower performance overhead than the encryption itself. Rache uses caching of certain "interesting" pre-computed ciphertexts (_which happen to be powers of a particular number, hence_ **_radices_**) in order to gain performance benefits over naively encrypting new values, using homomorphic operations. 

The [Rache paper](https://dl.acm.org/doi/10.1145/3588920) that premiered in SIGMOD'23 uses two schemes, [Paillier](https://link.springer.com/content/pdf/10.1007/3-540-48910-X_16.pdf) and [Symmetria](https://dl.acm.org/doi/10.14778/3389133.3389144), and shows that great performance benefits can be gained in systems using Rache over purely one or the other. This project aims to apply the functionality of Rache to schemes implemented by the [Microsoft SEAL](https://github.com/microsoft/SEAL) library. 

**IMPORTANT DISCLAIMER:** This project is for research purposes, _it is not secure_! Do not use this in production.

## Steps to Build
### Dependencies: 
- CMake 3.13+
- A C++ compiler meeting the C++17 standard

### Steps:
1. Clone this repository and move into the source directory with
  ```shell
  # Download source code and switch into directory
  $ git clone https://github.com/jly02/RacheAL.git
  $ cd RacheAL/src
  ```
2. Run `git submodule init`, and then `git submodule update`. This will install vcpkg, which is required to build this repository.
3. Run `cmake .` to setup the project, and `make` to build the repository and/or run tests.
4. A benchmarking executable is provided. To run this, simply use `./bin/benchmarks`. You may also notice that `test_suite` is also generated, you may use this to re-run the tests for the version at your compilation time.
