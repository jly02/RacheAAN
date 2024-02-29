#include "bench.h"

using namespace std;

int main()
{
    int selection = 0;
    cout << "Choose a scheme to benchmark. 1 for CKKS, 2 for BFV." << endl;
    cin >> selection;
    switch(selection) 
    {
        case 1:
            ckks_bench();
            break;

        case 2:
            bfv_bench();
            break;

        default:
            return 0;
    }

    return 0;
}