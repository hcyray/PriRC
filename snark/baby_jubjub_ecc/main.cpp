#include <iostream>

#include "prc.h"
using namespace std;

int main () {
    prc_initialize();
    cout << "intialize sucess--------------------------------------" << endl;
    unsigned char proof [312];
    char* comm_x = "7916061937171219682591368294088513039687205273691143098332585753343424131937";
    char* comm_y = "14035240266687799601661095864649209771790948434046947201833777492504781204499";
    prc_prove_hpc(proof, 1, 1, comm_x, comm_y);
    cout << "prove sucess--------------------------------------" << endl;
    bool verify_result = prc_verify_hpc_with_commit(proof, comm_x, comm_y);
    cout << "verification result : " << verify_result << endl;
    cout << "verify sucess--------------------------------------" << endl;
    return 0;
}

