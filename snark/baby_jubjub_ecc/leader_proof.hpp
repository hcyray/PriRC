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
    size_t difficulty;
    pb_variable<FieldT> less;
    pb_variable<FieldT> less_or_eq;
    pb_variable<FieldT> less_avg_rep;
    pb_variable<FieldT> less_or_eq_avg_rep;
    pb_variable<FieldT> rep; // rep score
    pb_variable<FieldT> full_rn_pack; // a random number
    pb_variable<FieldT> rn; // a random number with length of difficulty;
    pb_variable<FieldT> rnc_x; // randomCommit x
    pb_variable<FieldT> rnc_y; // randomCommit y
    pb_variable<FieldT> rn_commitment_x; // random hash commitment x
    pb_variable<FieldT> rn_commitment_y; // random hash commitment y
    pb_variable<FieldT> repDiff; // rep times 2^(n-difficulty)
    pb_variable_array<FieldT> sn_m;
    pb_variable_array<FieldT> sn_r;
    pb_variable_array<FieldT> rep_m;
    pb_variable_array<FieldT> rep_r;
    pb_variable_array<FieldT> full_rn;
    pb_variable<FieldT> avg_rep;
    pb_variable<FieldT> repRN;
    std::shared_ptr<pedersen_commitment<FieldT>> snCommit;
    std::shared_ptr<pedersen_commitment<FieldT>> repCommit;
    std::shared_ptr<pedersen_hash<FieldT>> randomCommit;
    std::shared_ptr<comparison_gadget<FieldT>> rangeProof;
    std::shared_ptr<comparison_gadget<FieldT>> rangeProof_avg_rep;
    std::shared_ptr<packing_gadget<FieldT> > pack_full_rn;
    std::shared_ptr<packing_gadget<FieldT> > pack_rn;
    std::shared_ptr<pedersen_hash<FieldT>> outRNCommit;
public:
    pb_variable<FieldT> block_hash;
    pb_variable<FieldT> sl;
    pb_variable<FieldT> sn_x;
    pb_variable<FieldT> sn_y;
    pb_variable<FieldT> rep_x;
    pb_variable<FieldT> rep_y;
    pb_variable<FieldT> total_rep;
    pb_variable<FieldT> rn_x;
    pb_variable<FieldT> rn_y;

    leader_proof(protoboard<FieldT> &pb, const size_t &in_difficulty,
            const size_t &in_n, const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness(const FieldT &in_sn_m, const FieldT &in_sn_r,
                               const FieldT &sn_commit_x, const FieldT &sn_commit_y,
                               const FieldT &in_total_rep, const FieldT &in_rep_m, const FieldT &in_rep_r,
                               const FieldT &rep_commit_x, const FieldT &rep_commit_y,
                               const FieldT &in_block_hash, const FieldT &in_sl,
                               const FieldT &in_rn_x, const FieldT &in_rn_y, const FieldT & in_avg_rep);

    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;
        acc += 253; // block_hash
        acc += 253; // slot
        acc += 253; // total rep
        acc += 253; // sn commitment x
        acc += 253; // sn commitment y
        acc += 253; // rep x
        acc += 253; // rep y
        acc += 253; // rn x
        acc += 253; // rn y
        acc += 253; // avg rep
        return acc;
    }
};


#include "leader_proof.cpp"

#endif //BABY_JUBJUB_ECC_LEADER_PROOF_HPP
