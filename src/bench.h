#include "seal/seal.h"

void ckks_bench();

void bfv_bench();

// initializes an array with random values
inline void initialize(int arr[], int size, int MIN_VAL, int MAX_VAL, bool PRINT) 
{
    srand(time(0));

    for(int i = 0; i < size; i++)
    {
        if(MIN_VAL == MAX_VAL) 
        {
            arr[i] = MIN_VAL;
        }
        else
        {
            arr[i] = (rand() + MIN_VAL) % MAX_VAL;
        }
    }

    if(PRINT) 
    {
        for(int i = 0; i < size; i++)
        {
            std::cout << arr[i] << " ";
        }
    }

    std::cout << std::endl;
}