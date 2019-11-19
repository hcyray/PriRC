package Reputation

import (
	"fmt"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"github.com/uchihatmtkinu/PriRC/shard"
	"github.com/uchihatmtkinu/PriRC/snark"
	"math/big"
	"testing"
)

func TestNewRepBock(t *testing.T) {
	n := 2
	ms := make([]shard.MemShard, 2)
	for i := 0; i < n; i++ {
		//ms[i].NewMemShard("123", 1)
		ms[i].SetRep(0)
		ms[i].SetPriRep(0, 0)
	}
}

func TestRepTransaction(t *testing.T) {
	var a RepTransaction
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(gVar.RepUint64ToInt32)
	b_r.SetInt64(9)
	var pc snark.PedersenCommitment
	pc.Init()
	snark.BabyJubJubCurve.Init()
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &pc)
	a.NewRepTransaction(pc, pc)
	fmt.Println(a.GlobalIDX)
}
