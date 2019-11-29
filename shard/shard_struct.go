package shard

import (
	"fmt"
	"github.com/uchihatmtkinu/PriRC/account"
	"github.com/uchihatmtkinu/PriRC/ed25519"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"github.com/uchihatmtkinu/PriRC/snark"
	"math/big"
)

//MemShard is the struct of miners for sharding and leader selection
type MemShard struct {
	//TCPAddress  *net.TCPAddr
	Address        string //ip+port
	PrivateAddress string
	PublicAddress  string
	Rep            int64 //rep this epoch
	TotalRep       int64 //rep all the time
	// Pedersen Commitment for totalrep
	RepComm snark.PedersenCommitment
	//TotalRep       []int32 //rep over several epoch
	CosiPub     ed25519.PublicKey
	Shard       int
	InShardId   int
	AttackID    int // used for simulate attack 
	EpochSNID   snark.PedersenCommitment
	Role        byte //1 - member, 0 - leader
	Legal       byte //0 - legal,  1 - kickout
	RealAccount *account.RcAcc
	PreShard    int
	//used of root identity
	IDComm    snark.PedersenCommitment
	Bandwidth int
}

//NewMemShard new a mem shard, addr - ip + port
func (ms *MemShard) NewMemShard(acc *account.RcAcc, addr string, band int) {
	ms.Address = addr
	ms.PrivateAddress = addr
	//ms.TCPAddress,_ = net.ResolveTCPAddr("tcp", addr)
	ms.RealAccount = acc
	ms.CosiPub = acc.CosiPuk
	ms.Legal = 0
	ms.Role = 1
	ms.Rep = 1000
	ms.TotalRep = 1000
	ms.Bandwidth = band
	ms.InitialPedersenCommitment()
}

//NewIDCommitment new ID commitment at the initial
func (ms *MemShard) InitialPedersenCommitment() {
	ms.IDComm.Init()
	ms.RepComm.Init()
	ms.EpochSNID.Init()
}

//NewIDCommitment new ID commitment at the initial
func (ms *MemShard) NewIDCommitment(ID int) [312]byte {
	var buff [312]byte
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(int64(ID))
	b_r.SetInt64(1)
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.IDComm)
	buff = snark.ProveHPC(b_m.Uint64(), b_r.Uint64(), ms.IDComm.Comm_x.String(), ms.IDComm.Comm_y.String())
	return buff
}

//NewIDSN new Epoch SN ID
func (ms *MemShard) NewSNID(epoch int, ID int) [312]byte {
	var buff [312]byte
	b_m := new(big.Int)
	b_r := new(big.Int)
	//tmp := make([]byte, 32)
	//copy(tmp, ID)
	//basic.Encode(&tmp, epoch)
	b_m.SetInt64(int64(epoch))
	b_r.SetInt64(int64(ID))
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.EpochSNID)
	buff = snark.ProveHPC(b_m.Uint64(), b_r.Uint64(), ms.EpochSNID.Comm_x.String(), ms.EpochSNID.Comm_y.String())
	return buff
}

//SetIDPC set ID pedersen commitment
func (ms *MemShard) SetIDPC(IDPC snark.PedersenCommitment) {
	old := new(big.Int)
	ms.IDComm.Comm_x.Add(IDPC.Comm_x, old)
	ms.IDComm.Comm_y.Add(IDPC.Comm_y, old)
}

//SetSNID set SNID pedersen commitment
func (ms *MemShard) SetSNID(PC snark.PedersenCommitment) {
	old := new(big.Int)
	ms.EpochSNID.Comm_x.Add(PC.Comm_x, old)
	ms.EpochSNID.Comm_y.Add(PC.Comm_y, old)
}

//int32  : -2147483648 to 2147483647
//uint64 : 0 to 18446744073709551615
//NewPriRep new private rep
func (ms *MemShard) NewPriRep(rep int64, r int) [312]byte {
	var RepBuff [312]byte
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(rep + gVar.RepUint64ToInt32)
	b_r.SetInt64(int64(r))
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.RepComm)
	RepBuff = snark.ProveHPC(b_m.Uint64(), b_r.Uint64(), ms.RepComm.Comm_x.String(), ms.RepComm.Comm_y.String())
	return RepBuff
}
func (ms *MemShard) SetPriRep(rep int64, r int) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(rep + gVar.RepUint64ToInt32)
	b_r.SetInt64(int64(r))
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.RepComm)
}

//SetRepPC set private rep pedersen commitment
func (ms *MemShard) SetPriRepPC(repPC snark.PedersenCommitment) {
	old := new(big.Int)
	ms.RepComm.Comm_x.Add(repPC.Comm_x, old)
	ms.RepComm.Comm_y.Add(repPC.Comm_y, old)
}

//SetRepPC new private rep
func (ms *MemShard) SetRep(rep int64) {
	ms.Rep = rep
}

//AddRep add a value to the rep PC
func (ms *MemShard) AddPriRep(value int64) {
	//ms.Rep += value
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(value)
	b_r.SetInt64(0)
	if value >= 0 {
		snark.BabyJubJubCurve.AddMToPedersenCommitment(b_m, &ms.RepComm, true)
	} else {
		snark.BabyJubJubCurve.AddMToPedersenCommitment(b_m, &ms.RepComm, false)
	}

}

//NewTotalRep set a new total rep to 0
//func (ms *MemShard) NewTotalRep() {
//	ms.TotalRep = []int32{}
//}

//CopyTotalRepFromSB copy total rep from sync bock
//func (ms *MemShard) CopyTotalRepFromSB(value []int32) {
//	ms.TotalRep = make([]int32, len(value))
//	copy(ms.TotalRep, value)
//}

//ClearTotalRep is clear total rep
//func (ms *MemShard) ClearTotalRep() {
//	for i := 0; i < len(ms.TotalRep); i++ {
//		ms.TotalRep[i] = 0
//	}
//}

//SetTotalRep set totalrep
//func (ms *MemShard) SetTotalRep(value int32) {
//	if len(ms.TotalRep) == gVar.SlidingWindows {
//		ms.TotalRep = ms.TotalRep[1:]
//	}
//	ms.TotalRep = append(ms.TotalRep, value)
//}

//CalTotalRep cal total rep over epoches
//func (ms *MemShard) CalTotalRep() int32 {
//	sum := int32(0)
//	for i := range ms.TotalRep {
//		sum += ms.TotalRep[i]
//	}
//	return sum
//}

//ClearRep clear rep
func (ms *MemShard) ClearRep() {
	ms.Rep = 0
}

//ClearRep clear rep
func (ms *MemShard) ClearPriRep(r uint32) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(int64(0) + gVar.RepUint64ToInt32)
	b_r.SetInt64(int64(r + 1))
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.RepComm)
}

//Print prints the sharding information
func (ms *MemShard) Print() {
	fmt.Println()
	fmt.Println("Member data:")
	fmt.Println("Addres:", ms.Address)
	fmt.Println("Rep:", ms.Rep)
	fmt.Print("RepID:")
	ms.RepComm.PrintPC()
	//fmt.Println("TotalRep:", ms.TotalRep)
	fmt.Println("Shard:", ms.Shard)
	fmt.Println("InShardId:", ms.InShardId)
	fmt.Print("EpochSNID:")
	ms.EpochSNID.PrintPC()
	if ms.Role == 0 {
		fmt.Println("Role:Leader")
	} else {
		fmt.Println("Role:Member")
	}

}
