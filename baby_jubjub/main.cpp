#include <iostream>
#include <string.h>
#include "prc.h"
using namespace std;

int main () {
    prc_initialize();
    cout << "intialize sucess--------------------------------------" << endl;
    unsigned char proof [312];
    char comm_x[80];
    char comm_y[80];
    int len_x;
    int len_y;
    prc_prove_hpc(proof, 1, 1, comm_x, &len_x, comm_y,&len_y);
    cout << "prove sucess--------------------------------------" << endl;
    cout << "actual commit value x :" << comm_x << endl;
    cout << "actual commit value Y :"<< comm_y << endl;
    cout << "actual commit value x :" << len_x << endl;
    cout << "actual commit value Y :"<< len_y << endl;
    bool verify_result = prc_verify_hpc_with_commit(proof, comm_x, comm_y);
    cout << "verification result : " << verify_result << endl;
    cout << "verify sucess--------------------------------------" << endl;
    return 0;
}

