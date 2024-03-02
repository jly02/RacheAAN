#include "bench.h"

using namespace std;

int main()
{
    int selection = 0;
    cout << "Choose a scheme to benchmark." << endl;
    cout << "[1 - CKKS | 2 - BFV | 3 - Stream]: ";
    cin >> selection;
    switch(selection) 
    {
        case 1:
            ckks_bench();
            break;

        case 2:
            bfv_bench();
            break;

        case 3:
            cipher_stream();
            break;

        default:
            return 0;
    }

    return 0;
}