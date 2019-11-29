package snark

import (
	"github.com/uchihatmtkinu/PriRC/gVar"
	"math/big"
)

type LeaderCalInfo struct {
	Leader    bool
	RNComm    PedersenCommitment
	BlockHash string
}

func (lc *LeaderCalInfo) LeaderCal(SNID *PedersenCommitment, Rep *PedersenCommitment, BlockHash []byte, sl int, totalrep int64, rep int64) {
	lc.RNComm.Init()
	l := new(PedersenCommitment)
	r := new(PedersenCommitment)
	l.Init()
	r.Init()
	l.SetPedersenCommmitment(SNID.Comm_x.String(), SNID.Comm_y.String(), 10)
	r.Comm_x.SetBytes(BlockHash[:])
	lc.BlockHash = r.Comm_x.String()
	r.Comm_y.SetInt64(int64(sl))
	BabyJubJubCurve.AddTwoPedersenCommitment(l, r)
	BabyJubJubCurve.CalPedersenHash(l.Comm_x, l.Comm_y, l)
	rn := new(big.Int)
	rn.Exp(big.NewInt(2), big.NewInt(gVar.LeaderBitSize), nil)
	rn.Mod(l.Comm_x, rn)
	rn.Mul(rn, big.NewInt(int64(totalrep)))
	ln := new(big.Int)
	ln.Exp(big.NewInt(2), big.NewInt(gVar.LeaderBitSize+gVar.LeaderDifficulty), nil)
	ln.Mul(big.NewInt(int64(rep)), ln)
	//fmt.Println(ln.String())
	//fmt.Println(rn.String())
	lc.Leader = ln.Cmp(rn) > 0
	if rep < int64(totalrep/int64(gVar.ShardSize)) {
		lc.Leader = false
	}
	r.SetPedersenCommmitment(Rep.Comm_x.String(), Rep.Comm_y.String(), 10)
	BabyJubJubCurve.AddTwoPedersenCommitment(l, r)
	BabyJubJubCurve.CalPedersenHash(l.Comm_x, l.Comm_y, &lc.RNComm)
}
