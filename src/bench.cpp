#include "bench.h"

using namespace std;

int main() {
    int selection = 0;

    do {
        cout << endl;
        cout << "Choose a demo." << endl;
        cout << "| 1 - CKKS Benchmark |" << endl
             << "| 2 -- BFV Benchmark |" << endl
             << "| 3 - Noise Gen Test |" << endl
             << "| 0 ----- Exit Demos |" << endl 
             << "| Selection: ";
        cin >> selection;
        switch(selection) {
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
    } while (selection != 0);

    return 0;
}