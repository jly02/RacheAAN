#!/bin/bash

# update repositories and install cmake
sudo apt update
sudo apt install cmake

# install seal
cd ..
git clone https://github.com/microsoft/SEAL.git
cd SEAL
cmake -S . -B build
cmake --build build
sudo cmake --install build

# install dependencies
sudo apt-get install curl zip unzip tar pkg-config

# build new schemes
cd ../RacheAL/src
git submodule init
git submodule update
cmake .
make
