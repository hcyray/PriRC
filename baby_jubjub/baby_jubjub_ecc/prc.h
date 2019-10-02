
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>


void prc_initialize();
void prc_prove_hpc(
        void *output_proof_ptr,
        ulong m_ulong,
        ulong r_ulong,
        char *&comm_x,
        char *&comm_y
        );

bool prc_verify_hpc_with_commit(
        void *proof_ptr,
        char *comm_x,
        char *comm_y
        );
