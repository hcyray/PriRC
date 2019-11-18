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
	Rep            int32 //rep this epoch
	// Pedersen Commitment for rep
	RepPC snark.PedersenCommitment
	// Proof for Rep
	RepProve [312]byte
	//TotalRep       []int32 //rep over several epoch
	CosiPub   ed25519.PublicKey
	Shard     int
	InShardId int
	EpochSNID snark.PedersenCommitment
	//EpochSNProve used in generating a new epoch sn
	EpochSNProve [312]byte
	//EpochSNIDProve used in using SNID
	EpochSNIDProve [312]byte
	Role           byte //1 - member, 0 - leader
	Legal          byte //0 - legal,  1 - kickout
	RealAccount    *account.RcAcc
	PreShard       int
	//used of root identity
	IDCommit  snark.PedersenCommitment
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
	ms.Bandwidth = band
}

//NewIDCommitment new ID commitment at the initial
func (ms *MemShard) InitialPedersenCommitment() {
	ms.IDCommit.Init()
	ms.RepPC.Init()
	ms.EpochSNID.Init()
}

//NewIDCommitment new ID commitment at the initial
func (ms *MemShard) NewIDCommitment(ID int) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(int64(ID))
	b_r.SetInt64(1)
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.IDCommit)
}

//NewIDCommitmentTree new ID commitment merkle tree at the initial
func (ms *MemShard) NewIDCommitmentTree(ID int) {

}

//NewIDSN new Epoch ID SN
func (ms *MemShard) NewIDSN(epoch int, ID int) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	//tmp := make([]byte, 32)
	//copy(tmp, ID)
	//basic.Encode(&tmp, epoch)
	b_m.SetInt64(int64(ID))
	b_r.SetInt64(int64(epoch))
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.EpochSNID)
	ms.EpochSNProve = snark.ProveHPC(b_m.Uint64(), b_r.Uint64(), ms.EpochSNID.Comm_x.String(), ms.EpochSNID.Comm_y.String())
}

//int32  : -2147483648 to 2147483647
//uint64 : 0 to 18446744073709551615
//NewPriRep new private rep
func (ms *MemShard) SetPriRep(rep int32) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(int64(rep) + gVar.RepUint64ToInt32)
	b_r.SetInt64(1)
	snark.BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &ms.RepPC)
	ms.RepProve = snark.ProveHPC(b_m.Uint64(), b_r.Uint64(), ms.RepPC.Comm_x.String(), ms.RepPC.Comm_y.String())
	ms.EpochSNIDProve = snark.ProveHPC(b_m.Uint64(), b_r.Uint64(), ms.RepPC.Comm_x.String(), ms.RepPC.Comm_y.String())
}

//SetRepPC new private rep
func (ms *MemShard) SetPriRepPC(repPC snark.PedersenCommitment) {
	ms.RepPC = repPC
}

//SetRepPC new private rep
func (ms *MemShard) SetRep(rep int32) {
	ms.Rep = rep
}

//AddRep add a value to the rep PC
func (ms *MemShard) AddPriRep(value int32) {
	ms.Rep += value
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(int64(value))
	b_r.SetInt64(0)
	snark.BabyJubJubCurve.AddMToPedersenCommitment(b_m, &ms.RepPC)
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

//Print prints the sharding information
func (ms *MemShard) Print() {
	fmt.Println()
	fmt.Println("Member data:")
	fmt.Println("Addres:", ms.Address)
	fmt.Println("Rep:", ms.Rep)
	fmt.Print("RepID:")
	ms.RepPC.PrintPC()
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
