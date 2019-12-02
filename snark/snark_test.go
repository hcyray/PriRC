package snark

import (
	"bufio"
	"fmt"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"math"
	"math/big"
	"os"
	"strconv"
	"testing"
)

func TestParamGen(t *testing.T) {
	n := int(gVar.ShardSize * gVar.ShardCnt)
	d := int(math.Log2(float64(n)))
	w := 1
	fmt.Println(d)
	Init()
	ParamGenHPC()
	ParamGenIUP(d, w)
	ParamGenLP(gVar.LeaderDifficulty, gVar.LeaderBitSize)
}

func TestPC(t *testing.T) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(1)
	b_r.SetInt64(0)
	pc := new(PedersenCommitment)
	pc.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc)
	Init()
	ParamGenHPC()
	proof_buf := ProveHPC(b_m.Uint64(), b_r.Uint64(), pc.Comm_x.String(), pc.Comm_y.String())
	fmt.Println("verification result:", VerifyHPC(proof_buf, pc.Comm_x.String(), pc.Comm_y.String()))
}

func TestLP(t *testing.T) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(2 + gVar.RepUint64ToInt32)
	b_r.SetInt64(2)
	pc := new(PedersenCommitment)
	pc.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc)
	Init()
	//ParamGenLP(gVar.LeaderDifficulty, gVar.LeaderBitSize)
	totalRep := uint64(10)
	block_hash := [32]byte{66}
	sl := 1
	var lc LeaderCalInfo
	lc.LeaderCal(pc, pc, block_hash[:], sl, 10, 2)
	for !lc.Leader {
		sl++
		lc.LeaderCal(pc, pc, block_hash[:], sl, 10, 2)
	}
	fmt.Println(sl)
	proof_buf := ProveLP(b_m.Uint64(), b_r.Uint64(), pc.Comm_x.String(), pc.Comm_y.String(), totalRep,
		b_m.Uint64(), 2, pc.Comm_x.String(), pc.Comm_y.String(), lc.BlockHash, sl,
		lc.RNComm.Comm_x.String(), lc.RNComm.Comm_y.String(), gVar.LeaderDifficulty, gVar.LeaderBitSize, 1)
	pc.PrintPC()
	lc.RNComm.PrintPC()
	fmt.Println("verification result:", VerifyLP(proof_buf, pc.Comm_x.String(), pc.Comm_y.String(),
		totalRep, pc.Comm_x.String(), pc.Comm_y.String(), lc.BlockHash, sl,
		lc.RNComm.Comm_x.String(), lc.RNComm.Comm_y.String(), 1))
}

func TestIUP(t *testing.T) {
	file, _ := os.Open("merkle.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	var d int
	var idAdd uint64
	var repAdd uint64
	scanner.Scan()
	d, _ = strconv.Atoi(scanner.Text())
	idAddBit := make([]bool, d)
	for i := 0; i < d; i++ {
		scanner.Scan()
		temp, _ := strconv.Atoi(scanner.Text())
		if temp == 1 {
			idAddBit[i] = true
		} else {
			idAddBit[i] = false
		}
	}
	BoolArrayToDec(&idAdd, idAddBit, d)
	repAdd = idAdd
	idPath := make([]string, d*2)
	repPath := make([]string, d*2)
	for i := 0; i < d*2; i++ {
		scanner.Scan()
		idPath[i] = scanner.Text()
		repPath[i] = idPath[i]
	}
	scanner.Scan()
	idLeafX := scanner.Text()
	repLeafX := idLeafX
	scanner.Scan()
	idLeafY := scanner.Text()
	repLeafY := idLeafY
	scanner.Scan()
	idRootX := scanner.Text()
	repRootX := idRootX
	scanner.Scan()
	idRootY := scanner.Text()
	repRootY := idRootY

	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(2)
	b_r.SetInt64(2)
	pc1 := new(PedersenCommitment)
	pc1.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc1)
	pc2 := new(PedersenCommitment)
	pc2.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc2)
	w := 2
	Init()
	ParamGenIUP(d, w)
	proof_buf := ProveIUP(d, idAdd, idLeafX, idLeafY, idRootX, idRootY, idPath,
		repAdd, repLeafX, repLeafY, repRootX, repRootY, repPath, 2, 2, pc1.Comm_x.String(), pc1.Comm_y.String(),
		2, 2, pc2.Comm_x.String(), pc2.Comm_y.String(), w)
	fmt.Println("Ok")
	fmt.Println("verification result:", VerifyIUP(proof_buf, idRootX, idRootY, repRootX, repRootY,
		pc1.Comm_x.String(), pc1.Comm_y.String(), pc2.Comm_x.String(), pc2.Comm_y.String(), w))
}

func TestPedersenCommitment(t *testing.T) {
	BabyJubJubCurve.Init()
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(2 + 30000000000)
	b_r.SetInt64(2)
	var pc1 PedersenCommitment
	pc1.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &pc1)
	pc1.PrintPC()
	var pc2 PedersenCommitment
	pc2.Init()
	b_m.SetInt64(1)
	b_r.SetInt64(0)
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &pc2)
	old := new(big.Int)
	pc2.Comm_x.Add(pc1.Comm_x, old)
	pc2.Comm_y.Add(pc1.Comm_y, old)
	pc2.PrintPC()
	BabyJubJubCurve.AddMToPedersenCommitment(big.NewInt(10), &pc1, true)
	//BabyJubJubCurve.SubTwoPedersenCommitment(pc1, pc2)
	pc2.PrintPC()

}
func TestPedersenHash(t *testing.T) {
	BabyJubJubCurve.Init()
	pc1 := new(PedersenCommitment)
	pc1.Init()

	pc1.Comm_x.SetString("1234", 10)
	pc1.Comm_y.SetString("1", 10)
	pc1.PrintPC()
	pc2 := new(PedersenCommitment)
	pc2.Init()
	pc2.Comm_x.SetString("18517123153863469553573384572371536953407444696640934598826194274645946323334", 10)
	pc2.Comm_y.SetString("16366639365004517936716040800897479058579589069997927276858356063876961184474", 10)
	BabyJubJubCurve.AddTwoPedersenCommitment(pc1, pc2)
	pc1.PrintPC()
	BabyJubJubCurve.CalPedersenHash(pc1.Comm_x, pc1.Comm_y, pc1)
	pc1.PrintPC()
}
func TestMerkleTree(t *testing.T) {
	BabyJubJubCurve.Init()
	n := 50
	b_m := new(big.Int)
	b_r := new(big.Int)
	pc := make([]PedersenCommitment, n)
	for i := 0; i < n; i++ {
		pc[i].Init()
		b_m.SetInt64(int64(i))
		b_r.SetInt64(48)
		BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &pc[i])
	}
	var mt MerkleTree
	mt.Init(pc)
	p := mt.Proof(8)
	p.PrintToTxT()
}

func TestLeaderCandidate(t *testing.T) {
	BabyJubJubCurve.Init()
	pc1 := new(PedersenCommitment)
	pc1.Init()
	pc1.SetPedersenCommmitment("18517123153863469553573384572371536953407444696640934598826194274645946323334", "16366639365004517936716040800897479058579589069997927276858356063876961184474", 10)
	pc2 := new(PedersenCommitment)
	pc2.Init()
	pc2.SetPedersenCommmitment("6468125633283523844081138403201428527072905892236409266890308262966770366270", "15599159073676304331609141418095610264573471298139509244854073578575099976066", 10)
	block_hash := new(big.Int)
	block_hash.SetString("1234", 10)
	var lc LeaderCalInfo
	lc.LeaderCal(pc1, pc2, block_hash.Bytes(), 1, 10, 2)
	fmt.Println(lc.Leader)
	lc.RNComm.PrintPC()
}
