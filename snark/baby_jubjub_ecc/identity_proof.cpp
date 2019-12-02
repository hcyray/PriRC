// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

merkle_path_selector::merkle_path_selector(
    ProtoboardT &in_pb,
    const VariableT& in_input_x,
    const VariableT& in_input_y,
    const VariableT& in_pathvar_x,
    const VariableT& in_pathvar_y,
    const VariableT& in_is_right,
    const std::string &in_annotation_prefix
) :
    GadgetT(in_pb, in_annotation_prefix),
    m_input_x(in_input_x),
    m_input_y(in_input_y),
    m_pathvar_x(in_pathvar_x),
    m_pathvar_y(in_pathvar_y),
    m_is_right(in_is_right)
{
    m_left_a_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_a_x"));
    m_left_b_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_b_x"));
    m_left_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_x"));

    m_left_a_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_a_y"));
    m_left_b_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_b_y"));
    m_left_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_y"));

    m_right_a_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_a_x"));
    m_right_b_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_b_x"));
    m_right_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_x"));

    m_right_a_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_a_y"));
    m_right_b_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_b_y"));
    m_right_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_y"));
}

void merkle_path_selector::generate_r1cs_constraints()
{
    // left x commitment
    this->pb.add_r1cs_constraint(
        ConstraintT(1 - m_is_right, m_input_x, m_left_a_x),
        FMT(this->annotation_prefix, "1-is_right_x * input_x = left_a_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar_x, m_left_b_x),
        FMT(this->annotation_prefix, "is_right * pathvar_x = left_b_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_left_a_x + m_left_b_x, 1, m_left_x),
        FMT(this->annotation_prefix, "1 * left_a_x + left_b_x = left_x"));

    // left y commitment
    this->pb.add_r1cs_constraint(
            ConstraintT(1 - m_is_right, m_input_y, m_left_a_y),
            FMT(this->annotation_prefix, "1-is_right_y * input_y = left_a_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar_y, m_left_b_y),
                                 FMT(this->annotation_prefix, "is_right * pathvar_y = left_b_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_left_a_y + m_left_b_y, 1, m_left_y),
                                 FMT(this->annotation_prefix, "1 * left_a_y + left_b_y = left_y"));

    // right x commitment
    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input_x, m_right_a_x),
        FMT(this->annotation_prefix, "is_right * input_x = right_a_x"));

    this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar_x, m_right_b_x),
        FMT(this->annotation_prefix, "1-is_right * pathvar_x = right_b_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_right_a_x + m_right_b_x, 1, m_right_x),
        FMT(this->annotation_prefix, "1 * right_a_x + right_b_x = right_x"));

    // right y commitment
    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input_y, m_right_a_y),
                                 FMT(this->annotation_prefix, "is_right * input_y = right_a_y"));

    this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar_y, m_right_b_y),
                                 FMT(this->annotation_prefix, "1-is_right * pathvar_y = right_b_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_right_a_y + m_right_b_y, 1, m_right_y),
                                 FMT(this->annotation_prefix, "1 * right_a_y + right_b_y = right_y"));


}

void merkle_path_selector::generate_r1cs_witness() const
{
    this->pb.val(m_left_a_x) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input_x);
    this->pb.val(m_left_b_x) = this->pb.val(m_is_right) * this->pb.val(m_pathvar_x);
    this->pb.val(m_left_x) = this->pb.val(m_left_a_x) + this->pb.val(m_left_b_x);

    this->pb.val(m_left_a_y) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input_y);
    this->pb.val(m_left_b_y) = this->pb.val(m_is_right) * this->pb.val(m_pathvar_y);
    this->pb.val(m_left_y) = this->pb.val(m_left_a_y) + this->pb.val(m_left_b_y);

    this->pb.val(m_right_a_x) = this->pb.val(m_is_right) * this->pb.val(m_input_x);
    this->pb.val(m_right_b_x) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar_x);
    this->pb.val(m_right_x) = this->pb.val(m_right_a_x) + this->pb.val(m_right_b_x);

    this->pb.val(m_right_a_y) = this->pb.val(m_is_right) * this->pb.val(m_input_y);
    this->pb.val(m_right_b_y) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar_y);
    this->pb.val(m_right_y) = this->pb.val(m_right_a_y) + this->pb.val(m_right_b_y);
}

const VariableT& merkle_path_selector::left_x() const {
    return m_left_x;
}
const VariableT& merkle_path_selector::left_y() const {
    return m_left_y;
}
const VariableT& merkle_path_selector::right_x() const {
    return m_right_x;
}
const VariableT& merkle_path_selector::right_y() const {
    return m_right_y;
}


merkle_path_compute:: merkle_path_compute(
            ProtoboardT &in_pb,
            const size_t& in_depth,
            const std::string &in_annotation_prefix
    ) :
            GadgetT(in_pb, in_annotation_prefix),
            m_depth(in_depth)
    {
        assert( in_depth > 0 );
        assert( in_address_bits.size() == in_depth );
        m_expected_root_x.allocate(pb,FMT(in_annotation_prefix, "expected root x"));
        m_expected_root_y.allocate(pb,FMT(in_annotation_prefix, "expected root y"));
        //pb.set_input_sizes(verifying_field_element_size());
        //assert( in_IVs.size() >= in_depth * 2 );
        m_address_bits.allocate(pb, m_depth, FMT(annotation_prefix, "address_bit"));
        m_leaf_x.allocate(pb, FMT(annotation_prefix, "leaf_x"));
        m_leaf_y.allocate(pb, FMT(annotation_prefix, "leaf_x"));
        m_path.allocate(pb, m_depth*2, FMT(annotation_prefix, "path"));
        for( size_t i = 0; i < m_depth; i++ )
        {
            if( i == 0 )
            {
                m_selectors.emplace_back(
                                in_pb, m_leaf_x, m_leaf_y, m_path[0], m_path[1], m_address_bits[i],
                                FMT(this->annotation_prefix, ".selector[%zu]", i));
            }
            else {
                m_selectors.emplace_back(
                                in_pb, m_hashers[i-1]->get_res_x(), m_hashers[i-1]->get_res_y(), m_path[i*2], m_path[i*2+1], m_address_bits[i],
                                FMT(this->annotation_prefix, ".selector[%zu]", i));
            }

            m_hashers.emplace_back(new pedersen_hash<FieldT>(in_pb,  FMT(this->annotation_prefix, ".hasher[%zu]", i),false));
        }
    }


VariableT merkle_path_compute::result_x(){
        assert( m_hashers.size() > 0 );

        return m_hashers.back()->get_res_x();
    }


VariableT merkle_path_compute::result_y() {
    assert( m_hashers.size() > 0 );
    return m_hashers.back()->get_res_y();
}


void merkle_path_compute::generate_r1cs_constraints()
{
    size_t i;
    for( i = 0; i < m_hashers.size(); i++ )
    {
        m_selectors[i].generate_r1cs_constraints();
        m_hashers[i]->generate_r1cs_constraints();
    }
    pb.add_r1cs_constraint(
            ConstraintT(m_hashers.back()->get_res_x(), 1, m_expected_root_x),
            FMT(this->annotation_prefix, ".expected_root_x authenticator"));
    pb.add_r1cs_constraint(
            ConstraintT(m_hashers.back()->get_res_y(), 1, m_expected_root_y),
            FMT(this->annotation_prefix, ".expected_root_y authenticator"));
}

void merkle_path_compute::generate_r1cs_witness(
        const vector<FieldT>& in_address_bits,
        const FieldT& in_leaf_x,
        const FieldT& in_leaf_y,
        const vector<FieldT>& in_path,
        const VariableT& in_expected_root_x,
        const VariableT& in_expected_root_y
        )
{
    pb.val(m_expected_root_x) = pb.val(in_expected_root_x);
    pb.val(m_expected_root_y) = pb.val(in_expected_root_y);
    m_address_bits.fill_with_field_elements(pb, in_address_bits);
    pb.val(m_leaf_x) = in_leaf_x;
    pb.val(m_leaf_y) = in_leaf_y;
    m_path.fill_with_field_elements(pb, in_path);
    size_t i;
    for( i = 0; i < m_hashers.size(); i++ )
    {
        m_selectors[i].generate_r1cs_witness();
        m_hashers[i]->generate_r1cs_witness(m_selectors[i].left_x(),m_selectors[i].left_y(),
                                            m_selectors[i].right_x(),m_selectors[i].right_y());
    }

//    cout << "merkle tree result:" << endl;
//    cout << pb.val(m_expected_root_x) << endl;
//    cout << pb.val(m_expected_root_y) << endl;
//    cout << pb.val(m_hashers.back()->get_res_x()) << endl;
//    cout << pb.val(m_hashers.back()->get_res_y()) << endl;

}



/**
* Merkle path authenticator, verifies computed root matches expected result
*/

identity_update_proof::identity_update_proof(
            ProtoboardT &pb,
            const size_t& in_depth,
            const size_t& in_w,
            const std::string &annotation_prefix
    ) : GadgetT(pb, annotation_prefix)
{
    d = in_depth;
    w = in_w;
    old_id_expected_root_x.allocate(pb, FMT(annotation_prefix, " old id expected root x"));
    old_id_expected_root_y.allocate(pb, FMT(annotation_prefix, " old id expected root y"));
    old_rep_expected_root_x.allocate(pb, FMT(annotation_prefix, " old rep expected root x"));
    old_rep_expected_root_y.allocate(pb, FMT(annotation_prefix, " old rep expected root y"));
    new_id_comm_x.allocate(pb, FMT(annotation_prefix, " new id comm x"));
    new_id_comm_y.allocate(pb, FMT(annotation_prefix, " new id comm y"));
    new_rep_comm_x.allocate(pb, FMT(annotation_prefix, " new rep comm x"));
    new_rep_comm_y.allocate(pb, FMT(annotation_prefix, " new rep comm y"));
    new_epoch_rep_comm_x.allocate(pb, FMT(annotation_prefix, " new epoch rep comm x"));
    new_epoch_rep_comm_y.allocate(pb, FMT(annotation_prefix, " new epoch rep comm y"));
    new_rep_matrix_comm_x.allocate(pb, in_w, FMT(annotation_prefix, "new rep matrix x"));
    new_rep_matrix_comm_y.allocate(pb, in_w, FMT(annotation_prefix, "new rep matrix y"));
    old_rep_matrix_expected_root_x.allocate(pb, in_w, FMT(annotation_prefix, "old rep matrix root x"));
    old_rep_matrix_expected_root_y.allocate(pb, in_w, FMT(annotation_prefix, "old rep matrix root y"));

    pb.set_input_sizes(verifying_field_element_size(in_w));

    new_id_m.allocate(pb, 253, FMT(annotation_prefix, " new id m"));
    new_id_r.allocate(pb, 253, FMT(annotation_prefix, " new id r"));
    new_rep_m.allocate(pb, 253, FMT(annotation_prefix, " new rep m"));
    new_rep_r.allocate(pb, 253, FMT(annotation_prefix, " new rep r"));
    new_epoch_rep_m.allocate(pb, 253, FMT(annotation_prefix, " new epoch rep m"));
    new_epoch_rep_r.allocate(pb, 253, FMT(annotation_prefix, " new epoch rep r"));

    new_id_pedersen_comm.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, " new id pedersen commitment")));
    new_rep_pedersen_comm.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, " new rep pedersen commitment")));
    new_epoch_rep_pedersen_comm.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, " new epoch rep pedersen commitment")));
    old_id_merkle_tree.reset(new merkle_path_compute(pb, in_depth, FMT(annotation_prefix," id merkle tree")));
    old_rep_merkle_tree.reset(new merkle_path_compute(pb, in_depth, FMT(annotation_prefix," rep merkle tree")));
   for(size_t i=0; i < in_w; i ++) {
        old_rep_matrix_merkle_tree.emplace_back(new merkle_path_compute(pb, in_depth, FMT(annotation_prefix," rep matrix merkle tree")));
        new_epoch_rep_matrix_comm.emplace_back(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, " new rep matirx commitment")));
    }

}


void identity_update_proof::generate_r1cs_constraints()
{
    new_id_pedersen_comm -> generate_r1cs_constraints();
    new_rep_pedersen_comm -> generate_r1cs_constraints();
    new_epoch_rep_pedersen_comm->generate_r1cs_constraints();
    old_id_merkle_tree -> generate_r1cs_constraints();
    old_rep_merkle_tree -> generate_r1cs_constraints();
    for(size_t i=0; i < w; i ++) {
        old_rep_matrix_merkle_tree[i]->generate_r1cs_constraints();
        new_epoch_rep_matrix_comm[i]->generate_r1cs_constraints();
    }
    // Ensure root matches calculated path hash

}

void identity_update_proof::generate_r1cs_witness(
        const vector<FieldT> &in_id_address_bits, const FieldT &in_id_leaf_x, const FieldT &in_id_leaf_y,
        const FieldT &in_id_expected_root_x, const FieldT &in_id_expected_root_y, const vector<FieldT> &in_id_path,
        const vector<FieldT> &in_rep_address_bits, const FieldT &in_rep_leaf_x, const FieldT &in_rep_leaf_y,
        const FieldT &in_rep_expected_root_x, const FieldT &in_rep_expected_root_y, const vector<FieldT> &in_rep_path,
        const FieldT &in_new_id_m, const FieldT &in_new_id_r, const FieldT &in_new_id_x, const FieldT &in_new_id_y,
        const FieldT &in_new_rep_m, const FieldT &in_new_rep_r, const FieldT &in_new_rep_x, const FieldT &in_new_rep_y
        )
{
    pb.val(old_id_expected_root_x) = in_id_expected_root_x;
    pb.val(old_id_expected_root_y) = in_id_expected_root_y;
    pb.val(old_rep_expected_root_x) = in_rep_expected_root_x;
    pb.val(old_rep_expected_root_y) = in_rep_expected_root_y;

    pb.val(new_id_comm_x) = in_new_id_x;
    pb.val(new_id_comm_y) = in_new_id_y;
    pb.val(new_rep_comm_x) = in_new_rep_x;
    pb.val(new_rep_comm_y) = in_new_rep_y;
    pb.val(new_epoch_rep_comm_x) = in_new_rep_x;
    pb.val(new_epoch_rep_comm_y) = in_new_rep_y;

    fill_with_bits_of_field_element_baby_jubjub<FieldT>(pb, new_id_m, in_new_id_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(pb, new_id_r, in_new_id_r);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(pb, new_rep_m, in_new_rep_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(pb, new_rep_r, in_new_rep_r);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(pb, new_epoch_rep_m, in_new_rep_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(pb, new_epoch_rep_r, in_new_rep_r);
    new_id_pedersen_comm -> generate_r1cs_witness(new_id_comm_x, new_id_comm_y, new_id_m, new_id_r);
    new_rep_pedersen_comm ->generate_r1cs_witness(new_rep_comm_x, new_rep_comm_y, new_rep_m, new_rep_r);
    new_epoch_rep_pedersen_comm->generate_r1cs_witness(new_epoch_rep_comm_x, new_epoch_rep_comm_y, new_rep_m, new_rep_r);
    old_id_merkle_tree->generate_r1cs_witness(in_id_address_bits, in_id_leaf_x, in_id_leaf_y, in_id_path, old_id_expected_root_x, old_id_expected_root_y);
    old_rep_merkle_tree->generate_r1cs_witness(in_rep_address_bits, in_rep_leaf_x, in_rep_leaf_y, in_rep_path, old_rep_expected_root_x, old_rep_expected_root_y);

    for(size_t i=0; i < w; i ++) {
        pb.val(old_rep_matrix_expected_root_x[i]) = in_rep_expected_root_x;
        pb.val(old_rep_matrix_expected_root_y[i]) = in_rep_expected_root_y;
        pb.val(new_rep_matrix_comm_x[i]) = in_new_rep_x;
        pb.val(new_rep_matrix_comm_y[i]) = in_new_rep_y;
        old_rep_matrix_merkle_tree[i]->generate_r1cs_witness(in_rep_address_bits, in_rep_leaf_x, in_rep_leaf_y, in_rep_path, old_rep_matrix_expected_root_x[i], old_rep_matrix_expected_root_y[i]);
        new_epoch_rep_matrix_comm[i]->generate_r1cs_witness(new_rep_matrix_comm_x[i], new_rep_matrix_comm_y[i], new_rep_m, new_rep_r);
    }
}

