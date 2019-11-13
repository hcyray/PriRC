package snark

import (
	"fmt"
	"math/big"
	"testing"
)

func TestPC(t *testing.T) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(1)
	b_r.SetInt64(1)
	pc := new(PedersenCommitment)
	pc.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc)
	Init()
	ParamGenHPC()
	proof_buf := ProveHPC(1, 1, pc.Comm_x.String(), pc.Comm_y.String())
	fmt.Println("verification result:", VerifyHPC(proof_buf, pc.Comm_x.String(), pc.Comm_y.String()))
}

func TestLP(t *testing.T) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(2)
	b_r.SetInt64(2)
	pc := new(PedersenCommitment)
	pc.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc)
	Init()
	ParamGenLP()
	var T string
	var blockHash string
	T = "12845949072827470624709637419912138308739243446882777103948483823386985213512"
	blockHash = "1234"
	proof_buf := ProveLP(2, 2, pc.Comm_x.String(), pc.Comm_y.String(), T,
		2, 2, pc.Comm_x.String(), pc.Comm_y.String(), blockHash, 1)
	fmt.Println("verification result:", VerifyLP(proof_buf, pc.Comm_x.String(), pc.Comm_y.String(),
		T, pc.Comm_x.String(), pc.Comm_y.String(), blockHash, 1))
}

func TestPrc(t *testing.T) {
	var d int
	d = 3
	a := make([]bool, 3)
	b := make([]string, 3)
	a[0] = true
	a[1] = false
	a[2] = true
	b[0] = "123"
	b[1] = "123"
	b[2] = "1234"
	var proof1 [312]byte
	var proof2 [312]byte
	prc_test(proof1, proof2, a, b, d)
}
func TestPedersenCommitment(t *testing.T) {
	BabyJubJubCurve.Init()
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(1)
	b_r.SetInt64(0)
	pc1 := new(PedersenCommitment)
	pc1.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc1)
	pc1.PrintPC()
	pc2 := new(PedersenCommitment)
	pc2.Init()
	b_m.SetInt64(1)
	b_r.SetInt64(0)
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc2)
	BabyJubJubCurve.AddTwoPedersenCommitment(pc1, pc2)
	pc1.PrintPC()
	b_m.SetInt64(0)
	b_r.SetInt64(0)
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc2)
	pc2.PrintPC()
}
func TestPedersenHash(t *testing.T) {
	BabyJubJubCurve.Init()
	pc1 := new(PedersenCommitment)
	pc1.Init()
	pc1.Comm_x.SetString("17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	pc1.Comm_y.SetString("2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	pc2 := new(PedersenCommitment)
	pc2.Init()
	pc2.Comm_x.SetString("1", 10)
	pc2.Comm_y.SetString("1", 10)
	BabyJubJubCurve.AddTwoPedersenCommitment(pc1, pc2)
	BabyJubJubCurve.CalPedersenHash(pc1.Comm_x, pc1.Comm_y, pc1)
	pc1.PrintPC()
}
func TestMerkleTree(t *testing.T) {
	BabyJubJubCurve.Init()
	n := 100
	b_m := new(big.Int)
	b_r := new(big.Int)
	pc := make([]PedersenCommitment, n)
	for i := 0; i < n; i++ {
		pc[i].Init()
		b_m.SetInt64(int64(i))
		b_r.SetInt64(0)
		BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &pc[i])
	}
	var mt MerkleTree
	mt.Init(pc)
	//mt.Print()
	p := mt.Proof(1)
	p.PrintToTxT()
}
