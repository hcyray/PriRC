//
// Created by hcy_ray on 10/23/19.


#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include <gmp.h>

using namespace libff;
using namespace libsnark;

template<typename FieldT>
pedersen_hash<FieldT>:: pedersen_hash(protoboard<FieldT> &pb,const std::string &annotation_prefix, const bool &outlayer):
        gadget<FieldT>(pb, annotation_prefix)
{

    left_x.allocate(pb,  FMT(annotation_prefix, " left x"));
    left_y.allocate(pb, FMT(annotation_prefix, " left y"));
    right_x.allocate(pb,  FMT(annotation_prefix, " right x"));
    right_y.allocate(pb,  FMT(annotation_prefix, " right y"));
    if (outlayer){
        pb.set_input_sizes(verifying_field_element_size());
    }



    m.allocate(pb, 253,  FMT(annotation_prefix, " scaler to multiply by"));
    r.allocate(pb, 253,  FMT(annotation_prefix, " scaler to multiply by"));
    m_var.allocate(pb, "m_var");
    r_var.allocate(pb, "r_var");
    a.allocate(pb, "hash_a");
    d.allocate(pb, "hash_d");
    hash_pointAddition.reset( new pointAddition <FieldT> (pb, a, d, left_x, left_y , right_x , right_y, m_var, r_var , "rhs addition"));
    commit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, "Pedersen Commitment")));
}



template<typename FieldT>
void  pedersen_hash<FieldT>::generate_r1cs_constraints()
{
    hash_pointAddition -> generate_r1cs_constraints();
    commit -> generate_r1cs_constraints(false);
}


template<typename FieldT>
void  pedersen_hash<FieldT>::generate_r1cs_witness(
        const pb_variable<FieldT> &left_x, const pb_variable<FieldT> &left_y,
        const pb_variable<FieldT> &right_x, const pb_variable<FieldT> &right_y)
{
    this->pb.val(a) = FieldT("168700");
    this->pb.val(d) = FieldT("168696");
    this->pb.val(this->left_x) = this->pb.val(left_x);
    this->pb.val(this->left_y) = this->pb.val(left_y);
    this->pb.val(this->right_x) = this->pb.val(right_x);
    this->pb.val(this->right_y) = this->pb.val(right_y);
    hash_pointAddition -> generate_r1cs_witness();
    FieldT temp_m = this->pb.val(m_var);
    FieldT temp_r = this->pb.val(r_var);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this->pb, m,this->pb.val(m_var));
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this->pb, r,this->pb.val(r_var));
    commit -> generate_r1cs_witness(a, d, m, r);
    /*
    std::stringstream comm_data_m, comm_data_r;
    comm_data_m << temp_m;
    std::string comm_str_m = comm_data_m.str();

    comm_data_r << temp_r;
    std::string comm_str_r = comm_data_r.str();


    mpz_t m_mpz, r_mpz;
    mpz_init(m_mpz);
    mpz_init(r_mpz);
    mpz_set_str(m_mpz,comm_str_m.c_str(), 10);
    mpz_set_str(r_mpz,comm_str_r.c_str(), 10);


    unsigned long int rm_mpz, rr_mpz;
    int i = 252;
    bool flagm = true;
    bool flagr = true;
    while(i >= 0) {
        if (flagm){
            rm_mpz = mpz_tdiv_q_ui(m_mpz, m_mpz, 2);
            if (rm_mpz == 0){
                this -> pb.val(m[i]) = FieldT::zero();
            } else {
                this -> pb.val(m[i]) = FieldT::one();
            }
        } else {
            this -> pb.val(m[i]) = FieldT::zero();
        }

        if (mpz_cmp_ui(m_mpz, 0) == 0) {
            flagm = false;
        }
        if (flagr){
            rr_mpz = mpz_tdiv_q_ui(r_mpz, r_mpz, 2);
            if (rr_mpz == 0){
                this -> pb.val(r[i]) = FieldT::zero();
            } else {
                this -> pb.val(r[i]) = FieldT::one();
            }
        } else {
            this -> pb.val(r[i]) = FieldT::zero();
        }

        if (mpz_cmp_ui(r_mpz, 0) == 0) {
            flagr = false;
        }
        i--;
    }
    */

    /* Debug
    std::cout << flagm << std::endl;
    std::cout << flagr << std::endl;
    std::cout << "m:";
    for (int j =0; j <= 252; j++){
        std::cout << this->pb.val(m[j]);
    }
    std::cout<< " "<< std::endl;
    std::cout << "r:";
    for (int j =0; j <= 252; j++){
        std::cout <<this->pb.val(r[j]);
    }
    std::cout<< " "<< std::endl;

    std::cout<< this->pb.val(commit->get_res_x())<< std::endl;
    std::cout<< this->pb.val(commit->get_res_y())<< std::endl;*/
}
template<typename FieldT>
pb_variable<FieldT>  pedersen_hash<FieldT>::get_res_x(){
    return this->commit->get_res_x();

}
template<typename FieldT>
pb_variable<FieldT>  pedersen_hash<FieldT>::get_res_y(){
    return this->commit->get_res_y();

}



template<typename FieldT>
out_pedersen_hash<FieldT>::out_pedersen_hash(
        protoboard<FieldT> &in_pb,
        const std::string &in_annotation_prefix
): pedersen_hash<FieldT>::pedersen_hash(in_pb, in_annotation_prefix, true){
}

template<typename FieldT>
void out_pedersen_hash<FieldT>::generate_r1cs_witness(const FieldT &left_x, const FieldT &left_y, const FieldT &right_x,
                                              const FieldT &right_y) {
    this->pb.val(this->left_x) = left_x;
    this->pb.val(this->left_y) = left_y;
    this->pb.val(this->right_x) = right_y;
    this->pb.val(this->right_y) = right_y;
    pedersen_hash<FieldT>::generate_r1cs_witness(this->left_x, this->left_y, this-> right_x, this->right_y);
}