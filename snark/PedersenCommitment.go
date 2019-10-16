package snark

import (
	"fmt"
	"go.dedis.ch/kyber"
	"go.dedis.ch/kyber/group/curve25519"
	"go.dedis.ch/kyber/group/mod"
	"math/big"
	"strings"
)

// A pedersen commitment
type PedersenCommitment struct {
	Comm_x *big.Int
	Comm_y *big.Int
}

func (p *PedersenCommitment) Init() {
	p.Comm_x = new(big.Int)
	p.Comm_y = new(big.Int)
}

// Set Pedersen Commitment Value
func (p *PedersenCommitment) SetPedersenCommmitment(x string, y string, base int) {
	p.Comm_x.SetString(x, base)
	p.Comm_y.SetString(y, base)
}

// Print Pedersen Commitment
func (p *PedersenCommitment) PrintPC() {
	fmt.Println("commit x:", p.Comm_x)
	fmt.Println("commit y:", p.Comm_y)
}

// BaybJubJub curve
type BabyJubJub_Curve struct {
	c   curve25519.ProjectiveCurve
	h_p kyber.Point
}

func (b *BabyJubJub_Curve) Init() {
	H_x := new(big.Int)
	H_y := new(big.Int)
	H_x.SetString("17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	H_y.SetString("2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	b.c.Init(ParamBabyJubJub(), false)
	b.h_p = b.c.NewPoint(H_x, H_y)
}

// Calculate Pedersen Commitment
func (b *BabyJubJub_Curve) CalPedersenCommitment(m, r *big.Int, pc PedersenCommitment) {
	var s_m, s_r mod.Int
	s_m.Init(m, &b.c.P)
	s_r.Init(r, &b.c.P)
	lhs := b.h_p.Clone()
	lhs.Mul(&s_m, lhs)
	rhs := b.c.BasePoint().Clone()
	rhs.Mul(&s_r, rhs)
	res := b.c.Point()
	res.Add(lhs, rhs)
	b.setPedersenCommit(res.String(), pc)
}

func (b *BabyJubJub_Curve) AddPedersenCommitment(m *big.Int, pc PedersenCommitment) {
	var s_m mod.Int
	s_m.Init(m, &b.c.P)
	lhs := b.h_p.Clone()
	lhs.Mul(&s_m, lhs)
	res := b.c.NewPoint(pc.Comm_x, pc.Comm_y)
	res.Add(res, lhs)
	b.setPedersenCommit(res.String(), pc)
}

//op is the operation, true for setting a new commit value, false for adding a commit value
func (b *BabyJubJub_Curve) setPedersenCommit(s string, pc PedersenCommitment) {
	sA := strings.Split(s, ",")
	s_x := sA[0][:]
	s_y := sA[1][:]
	pc.SetPedersenCommmitment(s_x[1:], s_y[:len(s_y)-1], 16)

}
func (b *BabyJubJub_Curve) printPoint(s string) {
	sA := strings.Split(s, ",")
	s_x := sA[0][:]
	s_y := sA[1][:]
	x := new(big.Int)
	y := new(big.Int)
	x.SetString(s_x[1:], 16)
	y.SetString(s_y[:len(s_y)-1], 16)
	fmt.Println("x:", x)
	fmt.Println("y:", y)
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
