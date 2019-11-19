package network

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"github.com/uchihatmtkinu/PriRC/shard"
	"github.com/uchihatmtkinu/PriRC/snark"
	"log"
	"math/rand"
	"time"
)

// generate MerkleTree for ID
func IDUpdateProcess() {
	shard.MyMenShard.SetPriRep(shard.MyMenShard.Rep, CurrentEpoch+2+MyGlobalID)
	shard.MySNIDCommProof = shard.MyMenShard.NewIDSN(CurrentEpoch+2, MyGlobalID)
	shard.MyIDUpdateProof = GenIDUpateProof(shard.MyIDMTProof, shard.MyRepMTProof, shard.MyMenShard.Rep)
	rand.Seed(int64(shard.MyMenShard.Shard*3000+shard.MyMenShard.InShardId) + time.Now().UTC().UnixNano())
	sendi := rand.Perm(int(gVar.ShardSize * gVar.ShardCnt))
	receivei := make([]bool, int(gVar.ShardSize*gVar.ShardCnt))
	fmt.Println("start sending ID comm")
	for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
		receivei[sendi[i]] = false
		if sendi[i] != MyGlobalID {
			receivei[sendi[i]] = false
			SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "IDU",
				IDUpdateInfo{MyGlobalID, shard.MyMenShard.IDComm, shard.MyMenShard.RepComm, shard.MyIDUpdateProof})
		}
	}
	receiveCount := 1
	for receiveCount <= int(gVar.ShardSize*gVar.ShardCnt) {
		select {
		case IDUpdateMessage := <-IDUpdateCh:
			if !receivei[IDUpdateMessage.ID] &&
				VerifyIDUpdate(IDUpdateMessage.IDComm, IDUpdateMessage.RepComm, IDUpdateMessage.IDUpdateProof) {
				shard.GlobalGroupMems[IDUpdateMessage.ID].SetIDPC(IDUpdateMessage.IDComm)
				shard.GlobalGroupMems[IDUpdateMessage.ID].SetPriRepPC(IDUpdateMessage.RepComm)
				receivei[IDUpdateMessage.ID] = true
				receiveCount++
				//fmt.Println(time.Now(), "Received commit from Global ID: ", commitMessage.ID, ", commits count:", signCount, "/", int(gVar.ShardSize))
			}
		case <-time.After(timeoutCosi):
			//resend after 15 seconds
			for i := 0; i < int(gVar.ShardSize*gVar.ShardSize); i++ {
				if !receivei[sendi[i]] {
					fmt.Println(time.Now(), "Request ID Comm Message to global client:", sendi[i])
					SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "reqIDU", MyGlobalID)
				}
			}
		}
	}
	fmt.Println(time.Now(), "Received all Identity Update")

}

func HandleIDUpdate(request []byte) {
	var buff bytes.Buffer
	var payload IDUpdateInfo

	buff.Write(request)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	fmt.Print("ID:", payload.ID, " ")
	payload.IDComm.PrintPC()
	fmt.Print("Rep:", payload.ID, " ")
	payload.RepComm.PrintPC()
	if err != nil {
		log.Panic(err)
	}
	IDUpdateCh <- payload
}
func HandleRequestIDMerkleTree(request []byte) {
	var buff bytes.Buffer
	var payload int
	buff.Write(request)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	SendIDComm(shard.GlobalGroupMems[payload].Address, "IDMT",
		IDCommInfo{MyGlobalID, shard.MyMenShard.IDComm, shard.MyIDCommProof,
			shard.MyMenShard.RepComm, shard.MyRepCommProof})
}

func GenIDUpateProof(IDMTP snark.MerkleProof, RepMTP snark.MerkleProof, rep int32) [312]byte {
	return snark.ProveIUP(IDMTP.Depth, IDMTP.AddressBitToAdd(), IDMTP.Leaf_x, IDMTP.Leaf_y, IDMTP.Root_x, IDMTP.Root_y, IDMTP.PathVar,
		RepMTP.AddressBitToAdd(), RepMTP.Leaf_x, RepMTP.Leaf_y, RepMTP.Root_x, RepMTP.Root_y, RepMTP.PathVar,
		uint64(CurrentEpoch+2), uint64(MyGlobalID), shard.MyMenShard.EpochSNID.Comm_x.String(), shard.MyMenShard.EpochSNID.Comm_y.String(),
		uint64(int64(rep)+gVar.RepUint64ToInt32), uint64(CurrentEpoch+2+MyGlobalID),
		shard.MyMenShard.RepComm.Comm_x.String(), shard.MyMenShard.RepComm.Comm_y.String())

}

func VerifyIDUpdate(id snark.PedersenCommitment, rep snark.PedersenCommitment, proof [312]byte) bool {
	return snark.VerifyIUP(proof, shard.MyIDMTProof.Root_x, shard.MyIDMTProof.Root_y, shard.MyRepMTProof.Root_x, shard.MyRepMTProof.Root_y,
		id.Comm_x.String(), id.Comm_y.String(), rep.Comm_x.String(), rep.Comm_y.String())
}
