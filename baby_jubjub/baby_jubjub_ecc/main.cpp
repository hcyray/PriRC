#include <prc.h>
#include <iostream>
using namespace std;


int main () {
    prc_initialize();
    cout << "intialize sucess--------------------------------------" << endl;
    unsigned char proof [312];
    char *comm_x;
    char *comm_y;
    prc_prove_hpc(proof, 1, 1, comm_x, comm_y);
    cout << "prove sucess--------------------------------------" << endl;
    cout << comm_x << endl;
    cout << comm_y << endl;
    bool verify_result = prc_verify_hpc_with_commit(proof, comm_x, comm_y);
    cout << "verification result : " << verify_result << endl;
    cout << "verify sucess--------------------------------------" << endl;
    return 0;
}

