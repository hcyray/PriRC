package Reputation

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"github.com/uchihatmtkinu/PriRC/snark"
	"log"
	"time"

	"github.com/uchihatmtkinu/PriRC/Reputation/cosi"
	"github.com/uchihatmtkinu/PriRC/ed25519"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"github.com/uchihatmtkinu/PriRC/shard"
)

//SyncBlock syncblock
type SyncBlock struct {
	Timestamp          int64
	PrevRepBlockHash   [32]byte
	PrevSyncBlockHash  [][32]byte
	PrevFinalBlockHash [32]byte
	IDlist             []int
	TotalRep           []int32
	RepComm            []snark.PedersenCommitment
	CoSignature        []byte
	Hash               [32]byte
}

// NewSynBlock new sync block
func NewSynBlock(ms *[]shard.MemShard, prevSyncBlockHash [][32]byte, prevRepBlockHash [32]byte, prevFBHash [32]byte, coSignature []byte) *SyncBlock {
	var item *shard.MemShard
	var repList []int32
	var idList []int
	var repCommList []snark.PedersenCommitment
	tmpprevSyncBlockHash := make([][32]byte, len(prevSyncBlockHash))
	copy(tmpprevSyncBlockHash, prevSyncBlockHash)
	tmpcoSignature := make([]byte, len(coSignature))
	copy(tmpcoSignature, coSignature)

	//mask := coSignature[64:]
	//repList = make([][gVar.SlidingWindows]int64, 0)
	rollingLeader := false
	if gVar.ExperimentBadLevel == 2 && shard.ShardToGlobal[shard.MyMenShard.Shard][0] < int(gVar.ShardSize*gVar.ShardCnt/3) {
		rollingLeader = true
	}
	for i := 0; i < int(gVar.ShardSize); i++ {
		item = &(*ms)[shard.ShardToGlobal[shard.MyMenShard.Shard][i]]
		//need to consider if a node fail to sign the syncBlock but it is a good node indeed
		if gVar.ExperimentBadLevel == 2 {
			if (shard.ShardToGlobal[shard.MyMenShard.Shard][i] >= int(gVar.ShardSize*gVar.ShardCnt/3) && rollingLeader) || !rollingLeader {
				item.Rep += 10000

			}
		}
		item.TotalRep += item.Rep
		item.AddPriRep(item.Rep)
		idList = append(idList, shard.ShardToGlobal[shard.MyMenShard.Shard][i])
		repList = append(repList, item.Rep)
		repCommList = append(repCommList, item.RepComm)
	}

	block := &SyncBlock{time.Now().Unix(), prevRepBlockHash, tmpprevSyncBlockHash, prevFBHash, idList, repList, repCommList, tmpcoSignature, [32]byte{}}
	block.Hash = sha256.Sum256(block.prepareData())
	return block
}

// prepareData prepare []byte data
func (b *SyncBlock) prepareData() []byte {
	data := bytes.Join(
		[][]byte{
			b.PrevRepBlockHash[:],
			b.HashPrevSyncBlock(),
			b.HashIDList(),
			b.HashTotalRep(),
			b.HashRepComm(),
			b.CoSignature,
			//IntToHex(b.Timestamp),
		},
		[]byte{},
	)

	return data
}

// HashRep returns a hash of the TotalRepTransactions in the block
func (b *SyncBlock) HashTotalRep() []byte {
	var txHashes []byte
	var txHash [32]byte
	for _, item := range b.TotalRep {
		//for _, item := range b.TotalRep[i] {
		txHashes = append(txHashes, IntToHex(item)[:]...)
		//}

	}
	txHash = sha256.Sum256(txHashes)
	return txHash[:]
}

// HashIDList returns a hash of the IDList in the block
func (b *SyncBlock) HashIDList() []byte {
	var txHashes []byte
	var txHash [32]byte
	for _, item := range b.IDlist {
		txHashes = append(txHashes, IntToHex(int64(item))[:]...)
	}
	txHash = sha256.Sum256(txHashes)
	return txHash[:]
}

// HashPrevSyncBlock returns a hash of the previous sync block hash
func (b *SyncBlock) HashPrevSyncBlock() []byte {
	var txHashes []byte
	var txHash [32]byte
	for _, item := range b.PrevSyncBlockHash {
		txHashes = append(txHashes, item[:]...)
	}
	txHash = sha256.Sum256(txHashes)
	return txHash[:]
}

// HashPrevSyncBlock returns a hash of the previous sync block hash
func (b *SyncBlock) HashRepComm() []byte {
	var txHashes []byte
	var txHash [32]byte
	for _, item := range b.RepComm {
		txHashes = append(txHashes, item.Comm_x.Bytes()[:]...)
		txHashes = append(txHashes, item.Comm_y.Bytes()[:]...)
	}
	txHash = sha256.Sum256(txHashes)
	return txHash[:]
}

// VerifyCosign verify CoSignature, k-th shard
func (b *SyncBlock) VerifyCoSignature(ms *[]shard.MemShard) bool {
	//verify signature
	var pubKeys []ed25519.PublicKey
	var it *shard.MemShard
	sbMessage := b.PrevRepBlockHash[:]
	pubKeys = make([]ed25519.PublicKey, int(gVar.ShardSize))
	for i := 0; i < int(gVar.ShardSize); i++ {
		it = &(*ms)[b.IDlist[i]]
		pubKeys[i] = it.CosiPub
	}
	valid := cosi.Verify(pubKeys, cosi.ThresholdPolicy(int(gVar.ShardSize)/2), sbMessage, b.CoSignature)
	return valid
}

// UpdateRepToTotalRepInMS update the rep to total rep in memshards
func (b *SyncBlock) UpdateTotalRepInMS(ms *[]shard.MemShard) {
	var item *shard.MemShard
	for i, id := range b.IDlist {
		item = &(*ms)[id]
		item.SetRep(b.TotalRep[i])
	}
}

//Print print sync block
func (b *SyncBlock) Print() {
	fmt.Println("SyncBlock:")
	fmt.Println("PrevSyncBlockHash:", b.PrevSyncBlockHash)
	fmt.Println("RepTransactions:")
	for i, item := range b.IDlist {
		fmt.Print("	GlobalID:", item)
		fmt.Println("		Rep", b.TotalRep[i])
		b.RepComm[i].PrintPC()
	}

	fmt.Println("CoSignature:", b.CoSignature)
	fmt.Println("PrevRepBlockHash:", b.PrevRepBlockHash)
	fmt.Println("Hash:", b.Hash)
}

// Serialize encode block
func (b *SyncBlock) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)
	err := encoder.Encode(b)
	if err != nil {
		log.Panic(err)
	}
	return result.Bytes()
}

// DeserializeSyncBlock decode Syncblock
func DeserializeSyncBlock(d []byte) *SyncBlock {
	var block SyncBlock
	decoder := gob.NewDecoder(bytes.NewReader(d))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panic(err)
	}
	return &block
}
