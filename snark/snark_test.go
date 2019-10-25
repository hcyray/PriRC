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
