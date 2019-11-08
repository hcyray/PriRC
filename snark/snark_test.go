package snark

import (
	"math/big"
	"testing"
)

func TestProveHPC(t *testing.T) {

	//Init()

	//proof_buf := ProveHPC(9912321, 412323, p.Comm_x.String(), p.Comm_y.String())
	//fmt.Print(proof_buf)

	//fmt.Println("verification result:", VerifyHPC(proof_buf,  p.Comm_x.String(), p.Comm_y.String()))

	//fmt.Println(string(x[0:lenX]))

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
	n := 3
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
	mt.Print()
	p := mt.Proof(1)
	p.Print()
}
