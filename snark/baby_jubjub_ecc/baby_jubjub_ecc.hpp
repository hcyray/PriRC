#ifndef BABY_JUBJUB_ECC_HPP_
#define BABY_JUBJUB_ECC_HPP_

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>




typedef libff::alt_bn128_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef libsnark::r1cs_constraint<FieldT> ConstraintT;
typedef libsnark::protoboard<FieldT> ProtoboardT;
typedef libsnark::pb_variable<libff::Fr<ppT>> VariableT;
typedef libsnark::pb_variable_array<FieldT> VariableArrayT;
typedef libsnark::gadget<libff::Fr<ppT>> GadgetT;


template<typename FieldT>
void fill_with_bits_of_field_element_baby_jubjub(libsnark::protoboard<FieldT> &pb, libsnark::pb_variable_array<FieldT> &x, const FieldT &r)
{
    const libff::bigint<FieldT::num_limbs> rint = r.as_bigint();
    for (size_t i = 0; i < x.size(); ++i)
    {
        pb.val((x)[x.size()- i - 1]) = rint.test_bit(i) ? FieldT::one() : FieldT::zero();
    }
}



#endif
