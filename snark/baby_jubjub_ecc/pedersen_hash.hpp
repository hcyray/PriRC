//
// Created by hcy_ray on 10/23/19.
//
#ifndef PEDSEN_HASH_HPP_
#define PEDSEN_HASH_HPP_
#include <cassert>
#include <memory>
#include "pedersen_commitment.hpp"
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>



using namespace libsnark;

template<typename FieldT>
class  pedersen_hash : public gadget<FieldT> {

private:
    size_t n;
    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> r;
    pb_variable_array<FieldT> m_reverse;
    pb_variable_array<FieldT> r_reverse;
    pb_variable<FieldT> m_var;
    pb_variable<FieldT> r_var;
    pb_variable<FieldT> a;
    pb_variable<FieldT> d;
    std::shared_ptr<pedersen_commitment<FieldT>> commit;
    std::shared_ptr<pointAddition<FieldT>> hash_pointAddition;
    std::shared_ptr<packing_gadget<FieldT> > pack_m;
    std::shared_ptr<packing_gadget<FieldT> > pack_r;

    //pb_variable<FieldT> res_x;
    //pb_variable<FieldT> res_y;
public:
    pb_variable<FieldT> left_x;
    pb_variable<FieldT> left_y;
    pb_variable<FieldT> right_x;
    pb_variable<FieldT> right_y;
    pedersen_hash(protoboard<FieldT> &pb, const std::string &annotation_prefix, const bool &outlayer=false);

    void generate_r1cs_constraints();
    void generate_r1cs_witness(
            const pb_variable<FieldT> &left_x,
            const pb_variable<FieldT> &left_y,
            const pb_variable<FieldT> &right_x,
            const pb_variable<FieldT> &right_y
            );
    pb_variable<FieldT> get_res_x();
    pb_variable<FieldT> get_res_y();
    static size_t verifying_field_element_size() {
        return libff::div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 253; // left x
        acc += 253; // left y
        acc += 253; // right x
        acc += 253; // right y

        return acc;
    }
};



template<typename FieldT>
class out_pedersen_hash:public pedersen_hash<FieldT> {
public:
    out_pedersen_hash(
            protoboard<FieldT> &in_pb,
            const std::string &in_annotation_prefix
            );
    void generate_r1cs_witness(
            const FieldT &left_x,
            const FieldT &left_y,
            const FieldT &right_x,
            const FieldT &right_y
    );
};


#include "pedersen_hash.cpp"
#endif