//
// Created by hcy_ray on 10/11/19.
//




#include <cassert>
#include <memory>

#include <libsnark/gadgetlib1/gadget.hpp>

using namespace libsnark;

template<typename FieldT>
class mul_cmp_gadget : public gadget<FieldT> {
private:
    /* no internal variables */
    int n_cmp;
    int n;

    pb_variable_array<FieldT> T_low;
    pb_variable_array<FieldT> T_high;
    pb_variable_array<FieldT> relation;
    pb_variable_array<FieldT> conj_result;

    std::vector<std::shared_ptr<comparison_gadget<FieldT>>> cmp_stat;
    //std::shared_ptr<comparison_gadget<FieldT>> cmp_2;
    std::shared_ptr<disjunction_gadget<FieldT>> disj;
    std::vector<std::shared_ptr<conjunction_gadget<FieldT>>> conj_vec;

public:

    pb_variable<FieldT> x;

    pb_variable<FieldT> disj_result;


    mul_cmp_gadget(protoboard<FieldT> &pb,
                  const pb_variable<FieldT> &x,
                    const pb_variable<FieldT> &disj_result,
                  const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


#include "mul_cmp.cpp"
