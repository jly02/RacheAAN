# RacheAL
Rache is a radix-based homomorphic encryption algorithm that utilizes a base scheme, leveraging the fact that in practical usage, homomorphic operations have far lower performance overhead than the encryption itself. Rache uses caching of certain "interesting" pre-computed ciphertexts (_which happen to be powers of a particular number, hence_ **_radices_**) in order to gain performance benefits over naively encrypting new values, using homomorphic operations. 

The [Rache paper](https://dl.acm.org/doi/10.1145/3588920) that premiered in SIGMOD'23 uses two schemes, [Paillier](https://link.springer.com/content/pdf/10.1007/3-540-48910-X_16.pdf) and [Symmetria](https://dl.acm.org/doi/10.14778/3389133.3389144), and shows that great performance benefits can be gained in systems using Rache over purely one or the other. This project aims to 

1. Apply the functionality of Rache to schemes implemented by the [Microsoft SEAL](https://github.com/microsoft/SEAL) library. 
2. Implement a novel encryption scheme, Inche, that utilizes only a single addition to construct a new ciphertext.

**IMPORTANT DISCLAIMER:** This project is for research purposes, _it is not secure_! Do not use this in production.

## Steps to Build
### Dependencies: 
- CMake 3.13+
- A C++ compiler meeting the C++17 standard (Microsoft SEAL states that `clang++` results in faster binaries than `g++`)
- Microsoft SEAL ([more here](#installing-microsoft-seal))

### Steps to build this project:
1. Clone this repository and move into the source directory with
  ```shell
  # Download source code and switch into directory
  $ git clone https://github.com/jly02/RacheAL.git
  $ cd RacheAL/src
  ```
2. Run `git submodule init`, and then `git submodule update`. This will install vcpkg, which is required for building unit tests with `gtest`.
3. Run `cmake .` to setup the project, and `make` to build the repository and/or run tests.
4. A benchmarking executable is provided. To run this, simply use `./bin/benchmarks`. You may also notice that `test_suite` is also generated, you may use this to re-run the tests for the version at your compilation time.

## Installing Microsoft SEAL

You have two options for installing Microsoft SEAL. The method you choose will greatly impact the performance of these encryption methods.

### Installing from Source

Head over to the [SEAL repo](https://github.com/microsoft/SEAL?tab=readme-ov-file#building-microsoft-seal), clone the repository, and follow the instructions in the repository to install SEAL locally or globally on your device.

### Installing with `vcpkg` (Slower)

Alternatively, you can install SEAL using `vcpkg`. After step 2 and before step 3, open the file `vcpkg.json`, which should currently look like this
```json
{
  "dependencies": [
    "gtest"
  ]
}
```
After `"gtest"`, add `"seal"` so it now looks like
```json
{
  "dependencies": [
    "gtest",
    "seal"
  ]
}
```
And then you'll be able to continue from step 3 like normal. It should be noted that this method results in everything running far slower than it would by installing from source, and is not recommended.
