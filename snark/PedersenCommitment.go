package snark

import (
	"fmt"
	"github.com/uchihatmtkinu/PriRC/gVar"
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
	fmt.Print("commit x:", p.Comm_x)
	fmt.Println(" commit y:", p.Comm_y)
}

// BaybJubJub curve
type BabyJubJub_Curve struct {
	c   curve25519.ProjectiveCurve
	h_p kyber.Point
}

func (b *BabyJubJub_Curve) Init() {
	CurveMax = new(big.Int)
	CurveMax.SetBit(big.NewInt(0), 253, 1)
	H_x := new(big.Int)
	H_y := new(big.Int)
	H_x.SetString("17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	H_y.SetString("2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	b.c.Init(ParamBabyJubJub(), false)
	b.h_p = b.c.NewPoint(H_x, H_y)
}

// Calculate Pedersen Commitment
func (b *BabyJubJub_Curve) CalPedersenCommitment(m, r *big.Int, pc *PedersenCommitment) {
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

// Calculate Pedersen Hash
func (b *BabyJubJub_Curve) CalPedersenHash(x, y *big.Int, pc *PedersenCommitment) {
	x.Mod(x, CurveMax)
	y.Mod(y, CurveMax)
	b.CalPedersenCommitment(x, y, pc)
}

// add m to pedersen commitment pc
func (b *BabyJubJub_Curve) AddMToPedersenCommitment(m *big.Int, pc *PedersenCommitment, flag bool) {
	var s_m mod.Int
	s_m.Init(m, &b.c.P)
	lhs := b.h_p.Clone()
	lhs.Mul(&s_m, lhs)
	res := b.c.NewPoint(pc.Comm_x, pc.Comm_y)
	if flag {
		res.Add(res, lhs)
	} else {
		res.Sub(res, lhs)
	}
	b.setPedersenCommit(res.String(), pc)
}

// pc1 = pc1 + pc2
func (b *BabyJubJub_Curve) AddTwoPedersenCommitment(pc1 *PedersenCommitment, pc2 *PedersenCommitment) {
	lhs := b.c.NewPoint(pc1.Comm_x, pc1.Comm_y)
	res := b.c.NewPoint(pc2.Comm_x, pc2.Comm_y)
	res.Add(lhs, res)
	b.setPedersenCommit(res.String(), pc1)
}

// pc1 = pc1 + pc2
func (b *BabyJubJub_Curve) SubTwoPedersenCommitment(pc1 *PedersenCommitment, pc2 *PedersenCommitment) {
	lhs := b.c.NewPoint(pc1.Comm_x, pc1.Comm_y)
	res := b.c.NewPoint(pc2.Comm_x, pc2.Comm_y)
	res.Sub(lhs, res)
	b.setPedersenCommit(res.String(), pc1)
}
func (b *BabyJubJub_Curve) MulPedersenCommitment(t *big.Int, pc *PedersenCommitment) {
	var s_t mod.Int
	s_t.Init(t, &b.c.P)
	res := b.c.NewPoint(pc.Comm_x, pc.Comm_y)
	res.Mul(&s_t, res)
	b.setPedersenCommit(res.String(), pc)
}

// verify commitment
func (b *BabyJubJub_Curve) VerifyPedersenCommit(x int32, y int32, pc *PedersenCommitment) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(int64(x) + gVar.RepUint64ToInt32)
	b_r.SetInt64(int64(y))
	pc1 := new(PedersenCommitment)
	pc1.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc1)
	if pc1.Comm_x.Cmp(pc.Comm_x) == 0 && pc1.Comm_y.Cmp(pc.Comm_y) == 0 {
	} else {
		fmt.Println("rep comm false, client:", y-1, "rep:", x)
		pc1.PrintPC()
		pc.PrintPC()
	}
}

//set pedersen commitment
func (b *BabyJubJub_Curve) setPedersenCommit(s string, pc *PedersenCommitment) {
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
