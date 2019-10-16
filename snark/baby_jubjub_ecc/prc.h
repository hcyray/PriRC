#ifndef _HPC_H_
#define _HPC_H_

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void prc_initialize();
void prc_prove_hpc(
        void *output_proof_ptr,
        ulong m_ulong,
        ulong r_ulong,
        char *comm_x,
        char *comm_y
);

bool prc_verify_hpc_with_commit(
        void *proof_ptr,
        char *comm_x,
        char *comm_y
);

#ifdef __cplusplus
}
#endif

#endif