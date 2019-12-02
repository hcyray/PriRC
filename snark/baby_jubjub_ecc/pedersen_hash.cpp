//
// Created by hcy_ray on 10/23/19.



using namespace libff;
using namespace libsnark;

template<typename FieldT>
pedersen_hash<FieldT>:: pedersen_hash(protoboard<FieldT> &pb,const std::string &annotation_prefix, const bool &outlayer):
        gadget<FieldT>(pb, annotation_prefix)
{
    n = 253;
    left_x.allocate(pb,  FMT(annotation_prefix, " left x"));
    left_y.allocate(pb, FMT(annotation_prefix, " left y"));
    right_x.allocate(pb,  FMT(annotation_prefix, " right x"));
    right_y.allocate(pb,  FMT(annotation_prefix, " right y"));
    if (outlayer){
        pb.set_input_sizes(verifying_field_element_size());
    }

    m.allocate(pb, n,  FMT(annotation_prefix, " scaler to multiply by"));
    r.allocate(pb, n,  FMT(annotation_prefix, " scaler to multiply by"));
    m_reverse.allocate(pb, n + 1,  FMT(annotation_prefix, " scaler to multiply by"));
    r_reverse.allocate(pb, n + 1,  FMT(annotation_prefix, " scaler to multiply by"));
    m_var.allocate(pb, "m_var");
    r_var.allocate(pb, "r_var");
    a.allocate(pb, "hash_a");
    d.allocate(pb, "hash_d");
    hash_pointAddition.reset( new pointAddition <FieldT> (pb, a, d, left_x, left_y , right_x , right_y, m_var, r_var , "rhs addition"));
    pack_m.reset(new packing_gadget<FieldT>(pb, m_reverse, m_var, FMT(this->annotation_prefix, " pack_m")));
    pack_r.reset(new packing_gadget<FieldT>(pb, r_reverse, r_var, FMT(this->annotation_prefix, " pack_r")));
    commit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, " Pedersen Commitment")));
}



template<typename FieldT>
void  pedersen_hash<FieldT>::generate_r1cs_constraints()
{
    hash_pointAddition -> generate_r1cs_constraints();
    pack_m -> generate_r1cs_constraints(true);
    pack_r -> generate_r1cs_constraints(true);
    for(int i = 0 ; i < n ; i++){
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, m_reverse[n - i - 1], m[i]), FMT(this->annotation_prefix, " m_reverse %zu", i));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, r_reverse[n - i - 1], r[i]), FMT(this->annotation_prefix, " r_reverse %zu", i));
    }
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
    pack_m -> generate_r1cs_witness_from_packed();
    pack_r -> generate_r1cs_witness_from_packed();
    for(int i = 0 ; i < n ; i++){
        this -> pb.val(m[i]) = this->pb.val(m_reverse[n - i - 1]);
        this -> pb.val(r[i]) = this->pb.val(r_reverse[n - i - 1]);
    }
//    FieldT temp_m = this->pb.val(m_var);
//    FieldT temp_r = this->pb.val(r_var);
//
//    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this->pb, test_m,this->pb.val(m_var));
//    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this->pb, test_r,this->pb.val(r_var));
//    auto test_m_val = test_m.get_vals(this->pb);
//    auto m_val = m.get_vals(this->pb);

//    for(int i = 0; i < 253; i++){
//        std::cout << m_val[i]<<" "<<test_m_val[i] << std::endl;
//    }
    commit -> generate_r1cs_witness(a, d, m, r);
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
    this->pb.val(this->right_x) = right_x;
    this->pb.val(this->right_y) = right_y;
    pedersen_hash<FieldT>::generate_r1cs_witness(this->left_x, this->left_y, this-> right_x, this->right_y);
}