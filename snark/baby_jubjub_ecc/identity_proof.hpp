#ifndef BABY_JUBJUB_MERKLE_TREE_HPP_
#define BABY_JUBJUB_MERKLE_TREE_HPP_

#include "baby_jubjub_ecc.hpp"
#include "pedersen_hash.hpp"
#include <memory>
#include <cassert>
/**
* Depending on the address bit, output the correct left/right inputs
* for the merkle path authentication hash
*
* 0 = left
* 1 = right
*
* There are two variables which make up each element of the path,
* the `input` and the `pathvar`, the input is the leaf or the
* output from the last hash, and the path var is part of the merkle
* tree path.
*
* The `is_right` parameter decides if the `input` is on the left or
* right of the hash. These are decided in-circuit using the following
* method:
*
* Left:
*  ((1-is_right) * input) + (is_right * pathvar)
*
* Right:
*  (is_right * input) + ((1 - is_right) * pathvar)
*
* Each component is split into a & b sides, then added together
* so the correct variable ends up in the right or left hand side.
*/
using namespace libsnark;
using namespace std;

class merkle_path_selector : public GadgetT
{
public:
    VariableT m_input_x;
    VariableT m_input_y;
    VariableT m_pathvar_x;
    VariableT m_pathvar_y;
    VariableT m_is_right;

    VariableT m_left_a_x;
    VariableT m_left_b_x;
    VariableT m_left_x;

    VariableT m_left_a_y;
    VariableT m_left_b_y;
    VariableT m_left_y;

    VariableT m_right_a_x;
    VariableT m_right_b_x;
    VariableT m_right_x;

    VariableT m_right_a_y;
    VariableT m_right_b_y;
    VariableT m_right_y;

    merkle_path_selector(
        ProtoboardT &in_pb,
        const VariableT& in_input_x,
        const VariableT& in_input_y,
        const VariableT& in_pathvar_x,
        const VariableT& in_pathvar_y,
        const VariableT& in_is_right,
        const std::string &in_annotation_prefix
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness() const;

    const VariableT& left_x() const;
    const VariableT& left_y() const;
    const VariableT& right_x() const;
    const VariableT& right_y() const;
};






class merkle_path_compute : public GadgetT
{
private:
    std::vector<merkle_path_selector> m_selectors;
    std::vector<std::shared_ptr <pedersen_hash<FieldT>>> m_hashers;
    VariableArrayT m_address_bits;
    VariableT m_leaf_x;
    VariableT m_leaf_y;
    VariableArrayT m_path;

public:
    VariableT m_expected_root_x;
    VariableT m_expected_root_y;
    size_t m_depth;



    merkle_path_compute(
        ProtoboardT &in_pb,
        const size_t &in_depth,
        const std::string &in_annotation_prefix
    );

    VariableT result_x();

    VariableT result_y();

    void generate_r1cs_constraints();

    void generate_r1cs_witness(
            const vector<FieldT>& in_address_bits,
            const FieldT& in_leaf_x,
            const FieldT& in_leaf_y,
            const vector<FieldT>& in_path,
            const VariableT& in_expected_root_x,
            const VariableT& in_expected_root_y
            );

};


/**
* Merkle path authenticator, verifies computed root matches expected result
*/

class identity_update_proof : public GadgetT
{
private:
    /*
    VariableT   id_leaf_x;
    VariableT   id_leaf_y;
    VariableArrayT  id_address_bits;
    VariableArrayT  id_path;
    VariableT   rep_leaf_x;
    VariableT   rep_leaf_y;
    VariableArrayT  rep_address_bits;
    VariableArrayT  rep_path;
    */
    std::shared_ptr<merkle_path_compute> old_id_merkle_tree;
    std::shared_ptr<merkle_path_compute> old_rep_merkle_tree;
    std::shared_ptr<pedersen_commitment<FieldT>> new_id_pedersen_comm;
    std::shared_ptr<pedersen_commitment<FieldT>> new_rep_pedersen_comm;

    VariableArrayT new_id_m;
    VariableArrayT new_id_r;

    VariableArrayT new_rep_m;
    VariableArrayT new_rep_r;
public:
    VariableT   old_id_expected_root_x;
    VariableT   old_id_expected_root_y;
    VariableT   old_rep_expected_root_x;
    VariableT   old_rep_expected_root_y;
    VariableT   new_id_comm_x;
    VariableT   new_id_comm_y;
    VariableT   new_rep_comm_x;
    VariableT   new_rep_comm_y;

    identity_update_proof(
        ProtoboardT &in_pb,
        const size_t& in_depth,
        const std::string &in_annotation_prefix
    );

    //bool is_valid();

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
            const vector<FieldT> &in_id_address_bits, const FieldT &in_id_leaf_x, const FieldT &in_id_leaf_y,
            const FieldT &in_id_expected_root_x, const FieldT &in_id_expected_root_y, const vector<FieldT> &in_id_path,
            const vector<FieldT> &in_rep_address_bits, const FieldT &in_rep_leaf_x, const FieldT &in_rep_leaf_y,
            const FieldT &in_rep_expected_root_x, const FieldT &in_rep_expected_root_y, const vector<FieldT> &in_rep_path,
            const FieldT &in_new_id_m, const FieldT &in_new_id_r, const FieldT &in_new_id_x, const FieldT &in_new_id_y,
            const FieldT &in_new_rep_m, const FieldT &in_new_rep_r, const FieldT &in_new_rep_x, const FieldT &in_new_rep_y
            );
    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;
        acc += 253; // old id expected root commitment x
        acc += 253; // old id expected root commitment y
        acc += 253; // old rep expected root commitment x
        acc += 253; // old rep expected root commitment y
        acc += 253; // new id commitment x
        acc += 253; // new id commitment y
        acc += 253; // new rep commitment x
        acc += 253; // new rep commitment y
        return acc;
    }
};



#include<identity_proof.cpp>

#endif
