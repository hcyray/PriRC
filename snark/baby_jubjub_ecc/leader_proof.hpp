//
// Created by hcy_ray on 10/29/19.
//

#ifndef LEADER_PROOF_HPP_
#define LEADER_PROOF_HPP_

#include <cassert>
#include <memory>
#include "pedersen_hash.hpp"
#include <libsnark/gadgetlib1/gadget.hpp>
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"

using namespace libsnark;

template<typename FieldT>
class leader_proof:public gadget<FieldT> {

private:
    int n; // for comparison
    pb_variable<FieldT> less;
    pb_variable<FieldT> less_or_eq;
    pb_variable<FieldT> rep; // rep score
    pb_variable<FieldT> ran; // a random number

    pb_variable_array<FieldT> sn_m;
    pb_variable_array<FieldT> sn_r;
    pb_variable_array<FieldT> rep_m;
    pb_variable_array<FieldT> rep_r;

    pb_variable<FieldT> repRN;
    std::shared_ptr<pedersen_commitment<FieldT>> snCommit;
    std::shared_ptr<pedersen_commitment<FieldT>> repCommit;
    std::shared_ptr<pedersen_hash<FieldT>> randomCommit;
    std::shared_ptr<comparison_gadget<FieldT>> rangeProof;

public:
    pb_variable<FieldT> block_hash;
    pb_variable<FieldT> sl;
    pb_variable<FieldT> T;
    pb_variable<FieldT> sn_x;
    pb_variable<FieldT> sn_y;
    pb_variable<FieldT> rep_x;
    pb_variable<FieldT> rep_y;


    leader_proof(protoboard<FieldT> &pb, const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness(const FieldT &in_sn_m, const FieldT &in_sn_r,
                               const FieldT &sn_commit_x, const FieldT &sn_commit_y,
                               const FieldT &in_T, const FieldT &in_rep_m, const FieldT &in_rep_r,
                               const FieldT &rep_commit_x, const FieldT &rep_commit_y,
                               const FieldT &in_block_hash, const FieldT &in_sl);

    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;
        acc += 253; // block_hash
        acc += 253; // slot
        acc += 253; // threshold T
        acc += 253; // sn commitment x
        acc += 253; // sn commitment y
        acc += 253; // rep x
        acc += 253; // rep y

        return acc;
    }
};


#include "leader_proof.cpp"

#endif //BABY_JUBJUB_ECC_LEADER_PROOF_HPP
