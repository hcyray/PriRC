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
func IDMerkleTreeProcess() {

	rand.Seed(int64(shard.MyMenShard.Shard*3000+shard.MyMenShard.InShardId) + time.Now().UTC().UnixNano())
	sendi := rand.Perm(int(gVar.ShardSize * gVar.ShardCnt))
	receivei := make([]bool, int(gVar.ShardSize*gVar.ShardCnt))
	fmt.Println("start sending ID comm")
	for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
		receivei[sendi[i]] = false
		if sendi[i] != MyGlobalID {
			receivei[sendi[i]] = false
			SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "IDMT",
				IDCommInfo{MyGlobalID, shard.MyMenShard.IDComm, shard.MyIDCommProof,
					shard.MyMenShard.RepComm, shard.MyRepCommProof})
		}
	}
	receiveCount := 1
	for receiveCount <= int(gVar.ShardSize*gVar.ShardCnt) {
		select {
		case IDCommitMessage := <-IDCommCh:
			if !receivei[IDCommitMessage.ID] &&
				snark.VerifyHPC(IDCommitMessage.IDProof, IDCommitMessage.IDComm.Comm_x.String(), IDCommitMessage.IDComm.Comm_y.String()) &&
				snark.VerifyHPC(IDCommitMessage.RepProof, IDCommitMessage.RepComm.Comm_x.String(), IDCommitMessage.RepComm.Comm_y.String()) {
				shard.GlobalGroupMems[IDCommitMessage.ID].SetIDPC(IDCommitMessage.IDComm)
				shard.GlobalGroupMems[IDCommitMessage.ID].SetPriRepPC(IDCommitMessage.RepComm)
				receivei[IDCommitMessage.ID] = true
				receiveCount++
				//fmt.Println(time.Now(), "Received commit from Global ID: ", commitMessage.ID, ", commits count:", signCount, "/", int(gVar.ShardSize))
			}
		case <-time.After(timeoutCosi):
			//resend after 15 seconds
			for i := 0; i < int(gVar.ShardSize*gVar.ShardSize); i++ {
				if !receivei[sendi[i]] {
					fmt.Println(time.Now(), "Request ID Comm Message to global client:", sendi[i])
					SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "reqIDMT", MyGlobalID)
				}
			}
		}
	}
	fmt.Println(time.Now(), "Received all the ID commit")
	idpcs := make([]snark.PedersenCommitment, int(gVar.ShardSize*gVar.ShardSize))
	reppcs := make([]snark.PedersenCommitment, int(gVar.ShardSize*gVar.ShardSize))
	for i := 0; i < int(gVar.ShardSize*gVar.ShardSize); i++ {
		idpcs[i] = shard.GlobalGroupMems[i].IDComm
		reppcs[i] = shard.GlobalGroupMems[i].RepComm
	}
	shard.IDMerkleTree.Init(idpcs)
	shard.MyIDMTProof = shard.IDMerkleTree.Proof(MyGlobalID)
	shard.RepMerkleTree.Init(reppcs)
	shard.MyRepMTProof = shard.RepMerkleTree.Proof(MyGlobalID)
	// Parameter generation for identity update
	snark.ParamGenIUP(shard.MyIDMTProof.Depth)
}

func HandleIDMerkleTree(request []byte) {
	var buff bytes.Buffer
	var payload IDCommInfo

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
	IDCommCh <- payload
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

func SendIDComm(addr string, command string, message interface{}) {
	payload := gobEncode(message)
	request := append(commandToBytes(command), payload...)
	sendData(addr, request)
}
