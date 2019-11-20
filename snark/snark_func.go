package snark

import (
	"github.com/uchihatmtkinu/PriRC/gVar"
	"math/big"
)

func LeaderCandidate(SNID PedersenCommitment, BlockHash [32]byte, sl int, totalrep int32, rep int32) bool {
	l := new(PedersenCommitment)
	r := new(PedersenCommitment)
	l.SetPedersenCommmitment(SNID.Comm_x.String(), SNID.Comm_y.String(), 10)
	r.Comm_x.SetBytes(BlockHash[:])
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
	return ln.Cmp(rn) > 0
}
