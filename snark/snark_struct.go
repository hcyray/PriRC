package snark

import (
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/group/curve25519"
	"go.dedis.ch/kyber/group/mod"
	"math/big"
)

// A pedersen commitment
type PedersenCommitment struct {
	Comm_x [32]byte
	Comm_y [32]byte
}

func (p *PedersenCommitment) NewPedersenCommmitment(x string, y string) {
	copy(p.Comm_x[:], StringToByte(x)[:32])
	copy(p.Comm_y[:], StringToByte(y)[:32])
}

type BabyJubJub_Curve struct {
	c   curve25519.ProjectiveCurve
	h_p kyber.Point
	PC  PedersenCommitment
}

func (b *BabyJubJub_Curve) Init() {
	var H_x, H_y big.Int
	H_x.SetString("17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	H_y.SetString("2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	b.c.Init(ParamBabyJubJub(), false)
	b.h_p = b.c.NewPoint(&H_x, &H_y)
}

func (b *BabyJubJub_Curve) CalPedersenCommitment(m, r *big.Int) {
	var s_m, s_r mod.Int
	s_m.Init(m, &b.c.P)
	s_r.Init(r, &b.c.P)
	lhs := b.h_p.Clone()
	lhs.Mul(&s_m, lhs)
	rhs := b.c.BasePoint().Clone()
	rhs.Mul(&s_r, rhs)
	res := b.c.Point()
	res.Add(lhs, rhs)
	res.String()
}

func ParamBabyJubJub() *curve25519.Param {
	var p curve25519.Param
	p.Name = "BabyJubJub"
	p.P.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	p.Q.SetString("21888242871839275222246405745257275088614511777268538073601725287587578984328", 10)

	p.R = 8
	p.A.SetInt64(168700)
	p.D.SetInt64(168696)
	p.PBX.SetString("16540640123574156134436876038791482806971768689494387082833631921987005038935", 10)
	p.PBY.SetString("20819045374670962167435360035096875258406992893633759881276124905556507972311", 10)
	return &p
}
