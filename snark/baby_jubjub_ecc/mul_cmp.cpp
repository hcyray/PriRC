//
// Created by hcy_ray on 10/11/19.
//




using namespace libsnark;


template<typename FieldT>
mul_cmp_gadget<FieldT>::mul_cmp_gadget(protoboard<FieldT> &pb, const pb_variable<FieldT> &x,
        const pb_variable<FieldT> &disj_result, const std::string &annotation_prefix):
        gadget<FieldT>(pb, "mul_cmp") , x(x), disj_result(disj_result) {
    n = 63;
    n_cmp = 2; // number of comparision
    T_low.allocate(pb, n_cmp, FMT(this->annotation_prefix, "lower bound"));
    T_high.allocate(pb,n_cmp, FMT(this->annotation_prefix, "upper bound"));
    relation.allocate(pb, n_cmp * 4, FMT(this->annotation_prefix, "less and less_or_eq"));
    conj_result.allocate(pb, n_cmp, FMT(this->annotation_prefix, "conjunction result"));
    //disj_result.allocate(pb, "final result");
    for (int i = 0; i < n_cmp; i++){
        cmp_stat.emplace_back(new comparison_gadget<FieldT>(pb, n, T_low[i], x, relation[i*4], relation[i*4+1],
                                                            FMT(this->annotation_prefix, "cmp"+std::to_string(i*2))));
        cmp_stat.emplace_back(new comparison_gadget<FieldT>(pb, n, x, T_high[i], relation[i*4+2], relation[i*4+3],
                                                            FMT(this->annotation_prefix, "cmp_2"+std::to_string(i*2+1))));
    }



    for (int i = 0; i < n_cmp; i++) {
        conj_vec.emplace_back(new conjunction_gadget<FieldT>(pb,
                                                             pb_variable_array<FieldT>(relation.begin()+i*4+1,relation.begin()+i*4+3),
                                                             conj_result[i],
                                                             FMT(this->annotation_prefix, " conjunction_cmp")));
    }
    disj.reset(new disjunction_gadget<FieldT>(pb,pb_variable_array<FieldT>(conj_result.begin(),conj_result.begin()+n_cmp),
                                              disj_result,FMT(this->annotation_prefix, " disjunction_all")));

}



template<typename FieldT>
void  mul_cmp_gadget<FieldT>::generate_r1cs_constraints()
{
    for (int i = 0; i < n_cmp * 2; i++)
        cmp_stat[i] -> generate_r1cs_constraints();
    for (int i = 0; i < n_cmp; i++) {
        conj_vec[i] -> generate_r1cs_constraints();
    }
    disj -> generate_r1cs_constraints();
    //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(disj_result , FieldT::one(), final_true), FMT(this->annotation_prefix, "final result"));
}


template<typename FieldT>
void  mul_cmp_gadget<FieldT>::generate_r1cs_witness()
{
    this -> pb.val(T_low[0]) = FieldT(10);
    this -> pb.val(T_high[0]) = FieldT(20);
    this -> pb.val(T_low[1]) = FieldT(20);
    this -> pb.val(T_high[1]) = FieldT(30);
    for (int i = 0; i < n_cmp * 2; i++)
        cmp_stat[i] -> generate_r1cs_witness();
    for (int i = 0; i < n_cmp; i++) {
        conj_vec[i] -> generate_r1cs_witness();
    }
    disj -> generate_r1cs_witness();
}