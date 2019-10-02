#include <prc.h>
#include <fstream>
#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include "baby_jubjub.hpp"
#include "eddsa.hpp"
#include "pedersen_commitment.hpp"
#include <iostream>
#include <string.h>
#include <depends/libsnark/libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
using namespace std;
using namespace libsnark;
using namespace libff;



// test inputs taken from ../test/test_pedersen.py



template<typename ppT>
struct real_commit_value{
    libff::Fr<ppT> x;
    libff::Fr<ppT> y;
};

template<typename ppT>
void loadFromFile(std::string path, ppT& objIn) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);
    ss << fh.rdbuf();
    fh.close();
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);
    ss >> objIn;
}

template<typename T>
void saveToFile(std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}




template<typename ppT>
libff::Fr<ppT> get_field_element_from_bits(pb_variable_array<libff::Fr<ppT>> *x, const protoboard<libff::Fr<ppT>> &pb) {
    typedef libff::Fr<ppT> FieldT;
    FieldT result = FieldT::zero();
    for (size_t i = 0; i < 253; ++i)
    {
        /* push in the new bit */
        const FieldT v = pb.val((*x)[i]);
        assert(v == FieldT::zero() || v == FieldT::one());
        result += result + v;
    }
    return result;
}

libff::bit_vector setbits(ulong x){
    libff::bit_vector bits(253,0);
    int i = 252;
    while (x > 0) {
        bits[i] = x & 1;
        x = x >> 1;
        i--;
    }
    return bits;
}


bool prc_verify_hpc_with_commit(void *proof_ptr, char *comm_x, char *comm_y) {
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    unsigned char *proof = reinterpret_cast<unsigned char *>(proof_ptr);
    //input proof
    std::vector<unsigned char> proof_v(proof, proof+312);
    std::stringstream proof_data;
    for (int i = 0; i < 312; i++) {
        proof_data << proof_v[i];
    }
    assert(proof_data.str().size() == 312);
    proof_data.rdbuf()->pubseekpos(0, std::ios_base::in);
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof_obj;
    proof_data >> proof_obj;
    // Add commitment value
    r1cs_primary_input<FieldT> witness_map;
    witness_map.insert(witness_map.end(), FieldT(comm_x));
    witness_map.insert(witness_map.end(), FieldT(comm_y));

    r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> verification_key;
    loadFromFile("hpc.vk", verification_key);

    if (!r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(verification_key, witness_map, proof_obj)) {
        return false;
    } else {
        return true;
    }
}

template<typename ppT>
void prc_prove_hpc_with_commit(void *output_proof_ptr, ulong m_ulong, ulong r_ulong, bool get_commit, real_commit_value<ppT> &real_commit){
    typedef libff::Fr<ppT> FieldT;
    protoboard<FieldT> pb;
    std::shared_ptr<pedersen_commitment<FieldT>> jubjub_pedersen_commitment;
    unsigned char *output_proof = reinterpret_cast<unsigned char *>(output_proof_ptr);

    pb_variable<FieldT> commitment_x;
    pb_variable<FieldT> commitment_y;
    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> r;


    commitment_x.allocate(pb, "r_x");
    commitment_y.allocate(pb, "r_y");
    m.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    r.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));

    pb.set_input_sizes(2);

    if (!get_commit){
        pb.val(commitment_x) = FieldT("8010604480252997578874361183087746053332521656016812693508547791817401879458");
        pb.val(commitment_y) = FieldT("15523586168823793714775329447481371860621135473088351041443641753333446779329");
    } else {
        pb.val(commitment_x) = real_commit.x;
        pb.val(commitment_y) = real_commit.y;
    }

    m.fill_with_bits(pb, setbits(m_ulong));
    r.fill_with_bits(pb, setbits(r_ulong));


    jubjub_pedersen_commitment.reset(new pedersen_commitment<FieldT> (pb, commitment_x, commitment_y, m, r));
    jubjub_pedersen_commitment->generate_r1cs_constraints();
    jubjub_pedersen_commitment->generate_r1cs_witness();
    if (!get_commit){
        real_commit.x = pb.val(jubjub_pedersen_commitment->get_res_x());
        real_commit.y = pb.val(jubjub_pedersen_commitment->get_res_y());
    } else {
        r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
        r1cs_ppzksnark_proving_key<ppT> proving_key;
        r1cs_ppzksnark_keypair<ppT> keypair = r1cs_ppzksnark_generator<ppT>(constraint_system);


        saveToFile("hpc.pk", keypair.pk);
        saveToFile("hpc.vk", keypair.vk);

        r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
        std::stringstream proof_data;
        proof_data << proof;
        auto proof_str = proof_data.str();
        assert(proof_str.size() == 312);
        for (int i = 0; i < 312; i++) {
            output_proof[i] = proof_str[i];
        }
    }
}

template <typename ppT>
void read_commit_value(char*& comm, libff::Fr<ppT> x){
    std::stringstream comm_data;
    comm_data << x;
    std::string comm_str = comm_data.str();
    char* pTemp = new char[comm_str.size()+1];
    for (int i = 0; i < comm_str.size()+1; i++) {
        pTemp[i] = comm_str[i];
    }
    comm = pTemp;

}

void prc_prove_hpc(void *output_proof_ptr, ulong m_ulong, ulong r_ulong, char* &comm_x, char* &comm_y){
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;

    real_commit_value<libff::alt_bn128_pp> real_commit;
    prc_prove_hpc_with_commit<libff::alt_bn128_pp>(output_proof_ptr, m_ulong, r_ulong, false, real_commit);
    read_commit_value<libff::alt_bn128_pp>(comm_x, real_commit.x);
    read_commit_value<libff::alt_bn128_pp>(comm_y, real_commit.y);
    prc_prove_hpc_with_commit<libff::alt_bn128_pp>(output_proof_ptr, m_ulong, r_ulong, true, real_commit);

    //cout << real_commit.x << endl;
    //cout << real_commit.y << endl;
}


void prc_initialize(){
    libff::alt_bn128_pp::init_public_params();
}


/*
template<typename ppT>
void prc_paramgen_hpc()
{
    typedef libff::Fr<ppT> FieldT;
    protoboard<FieldT> pb;
    pb_variable<FieldT> commitment_x;
    pb_variable<FieldT> commitment_y;
    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> r;


    commitment_x.allocate(pb, "r_x");
    commitment_y.allocate(pb, "r_y");
    m.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    r.allocate(pb, 256, FMT("annotation_prefix", " scaler to multiply by"));
    pb.val(commitment_x) = FieldT("8010604480252997578874361183087746053332521656016812693508547791817401879458");
    pb.val(commitment_y) = FieldT("15523586168823793714775329447481371860621135473088351041443641753333446779329");
    m.fill_with_bits(pb,
                     {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0});
    r.fill_with_bits(pb,
                     {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0});

    pedersen_commitment<FieldT> g(pb, commitment_x, commitment_y, m, r);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    const r1cs_ppzksnark_keypair<ppT> crs = r1cs_ppzksnark_generator<ppT>(constraint_system);

    saveToFile("hpc.pk", crs.pk);
    saveToFile("hpc.vk", crs.vk);
    *//*
    cout << "saving key" <<endl;
    cout << "proving key size:"<<crs.pk.size_in_bits() <<endl; *//*
    cout << "verification key size:"<<crs.vk <<endl;

}*/