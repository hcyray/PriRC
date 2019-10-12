package snark

import (
	"fmt"
	"math/big"
	"testing"
)

func TestProveHPC(t *testing.T) {
	var cur BabyJubJub_Curve
	cur.Init()
	var b_m, b_r big.Int
	b_m.SetInt64(1)
	b_r.SetInt64(1)
	cur.CalPedersenCommitment(&b_m, &b_r)

	Init()
	x := make([]byte, 100)
	y := make([]byte, 100)
	var lenX int
	var lenY int
	proof_buf := ProveHPC(1, 1, x, &lenX, y, &lenY)
	fmt.Println(lenX)
	fmt.Println(lenY)
	fmt.Println(string(x[0:lenX]))
	var temp [32]byte
	copy(temp[:], StringToByte(string(x[0:lenX]))[:32])
	fmt.Println(string(x[0:lenX]))

	fmt.Print(proof_buf)
	//res := VerifyHPC(proof_buf, string(x[0:lenX]), string(y[0:lenY]))
	//fmt.Print(res)
}
