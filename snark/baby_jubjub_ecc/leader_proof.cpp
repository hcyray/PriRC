//
// Created by hcy_ray on 10/29/19.
//


#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key


using namespace libff;

using namespace libsnark;
using namespace std;

template<typename FieldT>
leader_proof<FieldT>::leader_proof(protoboard<FieldT> &pb, const size_t &in_difficulty, const size_t &in_n,
        const std::string &annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix), difficulty(in_difficulty), n(in_n)
{

    block_hash.allocate(pb,FMT(annotation_prefix, "block hash"));
    sl.allocate(pb,FMT(annotation_prefix, "slot"));
    sn_x.allocate(pb, FMT(annotation_prefix, "sn x"));
    sn_y.allocate(pb, FMT(annotation_prefix, "sn y"));
    rep_x.allocate(pb, FMT(annotation_prefix, "rep x"));
    rep_y.allocate(pb, FMT(annotation_prefix, "rep y"));
    total_rep.allocate(pb, FMT(annotation_prefix, " total rep"));
    rn_x.allocate(pb, FMT(annotation_prefix, " rn x"));
    rn_y.allocate(pb, FMT(annotation_prefix, " rn y"));
    pb.set_input_sizes(verifying_field_element_size());

    sn_m.allocate(pb, 253, FMT(annotation_prefix, "sn m"));
    sn_r.allocate(pb, 253, FMT(annotation_prefix, "sn r"));
    rep_m.allocate(pb, 253, FMT(annotation_prefix, "rep m"));
    rep_r.allocate(pb, 253, FMT(annotation_prefix, "rep r"));
    rep.allocate(pb,FMT(annotation_prefix, "rep score"));
    rnc_x.allocate(pb, FMT(annotation_prefix, "rnc x"));
    rnc_y.allocate(pb, FMT(annotation_prefix, "rnc y"));
    rn_commitment_x.allocate(pb, FMT(annotation_prefix, "rn commitment x"));
    rn_commitment_y.allocate(pb, FMT(annotation_prefix, "rn commitment y"));
    full_rn_pack.allocate(pb,FMT(annotation_prefix, " packed random number"));
    full_rn.allocate(pb,255, FMT(annotation_prefix, " random number"));
    rn.allocate(pb, FMT(annotation_prefix, " rn with len of n"));
    repRN.allocate(pb, FMT(annotation_prefix, " total_rep times rn"));
    repDiff.allocate(pb, FMT(annotation_prefix, " rep times diff"));
    less.allocate(pb, FMT(annotation_prefix, "less"));
    less_or_eq.allocate(pb, FMT(annotation_prefix, "less_or_eq"));

    snCommit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, "SN Pedersen Commitment")));
    repCommit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, "Rep Pedersen Commitment")));
    randomCommit.reset(new pedersen_hash<FieldT>(pb, FMT(annotation_prefix, "random number"), false));
    outRNCommit.reset(new pedersen_hash<FieldT>(pb, FMT(annotation_prefix, "random number commitment"), false));
    pack_full_rn.reset(new packing_gadget<FieldT>(pb, full_rn, full_rn_pack, FMT(annotation_prefix, " unpack full rn")));
    pack_rn.reset(new packing_gadget<FieldT>(pb, pb_variable_array<FieldT>(full_rn.begin(), full_rn.begin()+n), rn, FMT(annotation_prefix, " pack rn")));

    rangeProof.reset(new comparison_gadget<FieldT>(pb, 253, repRN, repDiff, less, less_or_eq, FMT(this->annotation_prefix, "cmp")));

}

template<typename FieldT>
void leader_proof<FieldT>::generate_r1cs_constraints(){
    snCommit->generate_r1cs_constraints(true);
    repCommit->generate_r1cs_constraints(true);
    randomCommit->generate_r1cs_constraints();
    outRNCommit->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>( rnc_x, 1,  full_rn_pack),
                                FMT(this-> annotation_prefix, " rn_x + rn_y = full_rn_pack"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>({rn_commitment_x} , {1}, {rn_x}),
                                 FMT(this-> annotation_prefix, " rn PC"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>({rn_commitment_y} , {1}, {rn_y}),
                                 FMT(this-> annotation_prefix, " rn PC"));
    pack_full_rn -> generate_r1cs_constraints(true);
    pack_rn -> generate_r1cs_constraints(true);
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>( total_rep, rn,  repRN),
                               FMT(this-> annotation_prefix, " total_rep times rn"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>( rep, (FieldT(2)^(n+difficulty)),  repDiff),
                                 FMT(this-> annotation_prefix, " rep times diff"));
    rangeProof->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(less, FieldT::one(), FieldT::one()),
                                 FMT(this-> annotation_prefix, " check comparison"));
}

template<typename FieldT>
void leader_proof<FieldT>::generate_r1cs_witness(const FieldT &in_sn_m, const FieldT &in_sn_r,
                                                 const FieldT &sn_commit_x, const FieldT &sn_commit_y,
                                                 const FieldT &in_total_rep, const FieldT &in_rep_m, const FieldT &in_rep_r,
                                                 const FieldT &rep_commit_x, const FieldT &rep_commit_y,
                                                 const FieldT &in_block_hash, const FieldT &in_sl,
                                                 const FieldT &in_rn_x, const FieldT &in_rn_y)
{
    this -> pb.val(total_rep) = in_total_rep;
    this -> pb.val(block_hash) = in_block_hash;
    this -> pb.val(sl) = in_sl;
    this -> pb.val(sn_x) = sn_commit_x;
    this -> pb.val(sn_y) = sn_commit_y;
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this -> pb, sn_m, in_sn_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this -> pb, sn_r, in_sn_r);

    this -> pb.val(rep_x) = rep_commit_x;
    this -> pb.val(rep_y) = rep_commit_y;
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this -> pb, rep_m, in_rep_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this -> pb, rep_r, in_rep_r);
    this -> pb.val(rep) = in_rep_m;
    //commitment of sn and rep
    snCommit->generate_r1cs_witness(sn_x, sn_y, this->sn_m, this->sn_r);
    repCommit->generate_r1cs_witness(rep_x, rep_y, this->rep_m, this->rep_r);
    randomCommit->generate_r1cs_witness(sn_x, sn_y, block_hash, sl);

    this->pb.val(rnc_x) = this-> pb.val(randomCommit -> get_res_x());
    this->pb.val(rnc_y) = this-> pb.val(randomCommit -> get_res_y());
    //commitment for random number
    outRNCommit->generate_r1cs_witness(rnc_x, rnc_y, rep_x, rep_y);
    this->pb.val(rn_x) = in_rn_x;
    this->pb.val(rn_y) = in_rn_y;
    this->pb.val(rn_commitment_x) = this->pb.val(outRNCommit->get_res_x());
    this->pb.val(rn_commitment_y) = this->pb.val(outRNCommit->get_res_y());
    //unpack the rn
    this->pb.val(full_rn_pack) = this-> pb.val(rnc_x);
    pack_full_rn -> generate_r1cs_witness_from_packed();
    pack_rn -> generate_r1cs_witness_from_bits();
    this -> pb.val(repRN) = this -> pb.val(total_rep) * this-> pb.val(rn);
    this -> pb.val(repDiff) = this->pb.val(rep) * (FieldT(2)^(n+difficulty));
//    cout << this -> pb.val(rn_commitment_x) << endl;
//    cout << this -> pb.val(rn_commitment_y) << endl;
//    cout << this -> pb.val(full_rn_pack) << endl;
//    cout << this -> pb.val(rn) << endl;
//    cout << this -> pb.val(repRN) << endl;
//    cout << this -> pb.val(repDiff) << endl;
    rangeProof->generate_r1cs_witness();
}

