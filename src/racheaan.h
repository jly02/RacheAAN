#include <stddef.h>
#include <complex>
#include "seal/seal.h"

#ifndef RACHEAAN_H
#define RACHEAAN_H

using namespace std;

class RacheAAN
{
private:
    /* data */
public:
    RacheAAN(size_t poly_modulus_degree = 8192, double scale = pow(2.0, 40));
};

#endif