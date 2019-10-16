package snark

import (
	"fmt"
	"math/big"
	"testing"
)

func TestProveHPC(t *testing.T) {
	var cur BabyJubJub_Curve
	var p PedersenCommitment
	cur.Init()
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(1)
	b_r.SetInt64(1)
	p.Init()
	cur.CalPedersenCommitment(b_m, b_r, p)
	fmt.Println("commitment is:")
	p.PrintPC()
	fmt.Println("-------------------------------")

	b_m.SetInt64(1)
	b_r.SetInt64(1)
	cur.AddPedersenCommitment(b_m, p)
	fmt.Println("commitment of 1+1 is:")
	p.PrintPC()
	fmt.Println("-------------------------------")

	b_m.SetInt64(2)
	b_r.SetInt64(1)
	cur.CalPedersenCommitment(b_m, b_r, p)
	fmt.Println("commitment of 2 is:")
	p.PrintPC()
	fmt.Println("-------------------------------")

	Init()

	//proof_buf := ProveHPC(9912321, 412323, p.Comm_x.String(), p.Comm_y.String())
	//fmt.Print(proof_buf)

	//fmt.Println("verification result:", VerifyHPC(proof_buf,  p.Comm_x.String(), p.Comm_y.String()))

	//fmt.Println(string(x[0:lenX]))

}
