/*    
    copyright 2018 to the baby_jubjub_ecc Authors

    This file is part of baby_jubjub_ecc.

    baby_jubjub_ecc is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    baby_jubjub_ecc is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with baby_jubjub_ecc.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "libff/algebra/curves/bn128/bn128_pp.hpp" //hold key
using namespace libff;

using namespace libsnark;


template<typename FieldT>


 pedersen_commitment<FieldT>:: pedersen_commitment(protoboard<FieldT> &pb, const std::string &annotation_prefix, const bool &outlayer):
        gadget<FieldT>(pb, annotation_prefix)
{

    commitment_x.allocate(pb, FMT(annotation_prefix, "commitment x"));
    commitment_y.allocate(pb, FMT(annotation_prefix, "commitment y"));

    if (outlayer){
        pb.set_input_sizes(verifying_field_element_size());
    }

    m.allocate(pb, 253, FMT(annotation_prefix, " m"));
    r.allocate(pb, 253, FMT(annotation_prefix, " r"));
    base_x.allocate(pb, "base x");
    base_y.allocate(pb, "base y");
    H_x.allocate(pb, "h_x");
    H_y.allocate(pb, "h_y");
    a.allocate(pb, "a");
    d.allocate(pb, "d");
    lhs_x.allocate(pb, 253,  FMT("lhs x", " pedersen_commitment"));
    lhs_y.allocate(pb, 253, FMT("lhs y", " pedersen_commitment"));
    rhs_mul_x.allocate(pb,253, FMT( "rhs mul x" , " pedersen_commitment" ));
    rhs_mul_y.allocate(pb,253, FMT( "rhs mul y ", " pedersen_commitment"));
    rhs_x.allocate(pb,253, FMT( "rhs mul x" , " pedersen_commitment" ));
    rhs_y.allocate(pb,253, FMT( "rhs mul y ", " pedersen_commitment"));

    res_x.allocate(pb, "x_zero");
    res_y.allocate(pb, "y_zero");

    // make sure both points are on the twisted edwards cruve
    jubjub_isOnCurve1.reset( new isOnCurve <FieldT> (pb, base_x,base_y, a, d, "Confirm x, y is on the twiseted edwards curve"));
    jubjub_isOnCurve2.reset( new isOnCurve <FieldT> (pb, H_x, H_y, a, d, "Confirm x, y is on the twiseted edwards curve"));

    // base * m
    jubjub_pointMultiplication_lhs.reset( new pointMultiplication <FieldT> (pb, a, d, base_x, base_y, m, lhs_x, lhs_y, " lhs check ", 253));
    // h*r
    jubjub_pointMultiplication_rhs.reset( new pointMultiplication <FieldT> (pb, a, d, H_x, H_y, r, rhs_x, rhs_y, "rhs mul ", 253));

    jubjub_pointAddition.reset( new pointAddition <FieldT> (pb, a, d, rhs_x[252], rhs_y[252] , lhs_x[252] , lhs_y[252], res_x, res_y , "rhs addition"));



}



template<typename FieldT>
void  pedersen_commitment<FieldT>::generate_r1cs_constraints(const bool commitment_check)
{
    // not sure if we need to check pub key and r 
    // are on the curve. But doing it here for defense
    // in depth
    jubjub_isOnCurve1->generate_r1cs_constraints();
    jubjub_isOnCurve2->generate_r1cs_constraints();

    jubjub_pointMultiplication_lhs->generate_r1cs_constraints();
    jubjub_pointMultiplication_rhs->generate_r1cs_constraints();
    jubjub_pointAddition->generate_r1cs_constraints();
    if (commitment_check){
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>({res_x} , {1}, {commitment_x}),
                                     FMT("find y1*x2 == y1x2", " pedersen_commitment"));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>({res_y} , {1}, {commitment_y}),
                                     FMT("find y1*x2 == y1x2", " pedersen_commitment"));
    }

}


template<typename FieldT>
void  pedersen_commitment<FieldT>::generate_r1cs_witness(
        const pb_variable<FieldT> &commitment_x, const pb_variable<FieldT> &commitment_y,
        const pb_variable_array<FieldT> &in_m, const pb_variable_array<FieldT> &in_r)
{
    m.fill_with_field_elements(this->pb, in_m.get_vals(this->pb));
    r.fill_with_field_elements(this->pb, in_r.get_vals(this->pb));
    this->pb.val(this->commitment_x) = this-> pb.val(commitment_x);
    this->pb.val(this->commitment_y) = this-> pb.val(commitment_y);
    this->pb.val(base_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    this->pb.val(base_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    this->pb.val(a) = FieldT("168700");
    this->pb.val(d) = FieldT("168696");

    this->pb.val(H_x) = FieldT("16540640123574156134436876038791482806971768689494387082833631921987005038935");
    this->pb.val(H_y) = FieldT("20819045374670962167435360035096875258406992893633759881276124905556507972311");

    jubjub_isOnCurve1->generate_r1cs_witness();
    jubjub_isOnCurve2->generate_r1cs_witness();
    jubjub_pointMultiplication_lhs->generate_r1cs_witness();
    jubjub_pointMultiplication_rhs->generate_r1cs_witness();
    jubjub_pointAddition->generate_r1cs_witness();
}


template<typename FieldT>
pb_variable<FieldT>  pedersen_commitment<FieldT>::get_res_x(){
    return this->res_x;

}
template<typename FieldT>
pb_variable<FieldT>  pedersen_commitment<FieldT>::get_res_y(){
    return this->res_y;

}

template<typename FieldT>
out_pedersen_commitment<FieldT>::out_pedersen_commitment(
        protoboard<FieldT> &in_pb,
        const std::string &in_annotation_prefix
): pedersen_commitment<FieldT>::pedersen_commitment(in_pb, in_annotation_prefix, true){
}

template<typename FieldT>
void out_pedersen_commitment<FieldT>::generate_r1cs_witness(const FieldT &comm_x, const FieldT &comm_y, const FieldT &in_m,
                                                      const FieldT &in_r)
{
    this->pb.val(this->commitment_x) = comm_x;
    this->pb.val(this->commitment_y) = comm_y;

    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this->pb, this->m, in_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this->pb, this->r, in_r);

    pedersen_commitment<FieldT>::generate_r1cs_witness(this->commitment_x, this->commitment_y, this-> m, this-> r);
}