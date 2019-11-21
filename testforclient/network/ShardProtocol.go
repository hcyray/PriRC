package network

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/uchihatmtkinu/PriRC/snark"
	"log"
	"math/rand"
	"time"

	"github.com/uchihatmtkinu/PriRC/Reputation"
	"github.com/uchihatmtkinu/PriRC/Reputation/cosi"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"github.com/uchihatmtkinu/PriRC/shard"
)

var readymask []byte
var SentLeaderReadyFlag = true

//ShardProcess is the process of sharding
func ShardProcess() {
	//var beginShard shard.Instance

	Reputation.CurrentRepBlock.Mu.Lock()
	Reputation.CurrentRepBlock.Round = -1
	CurrentRepRound = -1
	Reputation.CurrentRepBlock.Mu.Unlock()

	shard.StartFlag = true
	shard.ShardToGlobal = make([][]int, gVar.ShardCnt)

	for i := uint32(0); i < gVar.ShardCnt; i++ {
		shard.ShardToGlobal[i] = make([]int, gVar.ShardSize)
		for j := uint32(0); j < gVar.ShardSize; j++ {
			shard.ShardToGlobal[i][j] = int(j)
			shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].Shard = int(i)
			shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].InShardId = int(j)
			shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].Role = 1
		}
	}

	//Generating Leader Proof
	var MyLeader snark.LeaderCalInfo
	leaderflag := false
	blockHash := shard.PreviousSyncBlockHash[0][:]
	rand.Seed(int64(shard.MyMenShard.Shard*3000+shard.MyMenShard.InShardId) + time.Now().UTC().UnixNano())
	sendi := rand.Perm(int(gVar.ShardSize * gVar.ShardCnt))
	receivei := make([]bool, int(gVar.ShardSize*gVar.ShardCnt))
	//TODO calculate totalrep
	for !leaderflag {
		CurrentSlot++
		MyLeader.LeaderCal(&shard.MyMenShard.EpochSNID, &shard.MyMenShard.RepComm,
			blockHash, CurrentSlot, shard.MyMenShard.Rep, shard.TotalRep)
		if MyLeader.Leader {
			shard.MyLeaderProof = GenerateLeaderProof(shard.MyMenShard.EpochSNID, shard.MyMenShard.RepComm,
				shard.MyMenShard.Rep, shard.TotalRep, CurrentSlot, MyLeader)
			for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
				if sendi[i] != MyGlobalID {
					receivei[sendi[i]] = false
					SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "LYes",
						LeaderInfo{true, MyGlobalID, CurrentSlot, shard.MyMenShard.EpochSNID,
							MyLeader.RNComm, shard.MyLeaderProof})
				}
			}
		} else {
			for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
				if sendi[i] != MyGlobalID {
					receivei[sendi[i]] = false
					SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "LNot",
						LeaderInfo{false, MyGlobalID, CurrentSlot, shard.MyMenShard.EpochSNID, nil, nil})

				}
			}
		}
		receivei[MyGlobalID] = true
		receiveCount := 1
		for receiveCount < int(gVar.ShardSize*gVar.ShardCnt) {
			select {
			case IDUpdateMessage := <-IDUpdateCh:
				if !receivei[IDUpdateMessage.ID] {
					if VerifyIDUpdate(IDUpdateMessage.ID, IDUpdateMessage.IDComm, IDUpdateMessage.RepComm, IDUpdateMessage.IDUpdateProof) {
						shard.GlobalGroupMems[IDUpdateMessage.ID].SetIDPC(IDUpdateMessage.IDComm)
						shard.GlobalGroupMems[IDUpdateMessage.ID].SetPriRepPC(IDUpdateMessage.RepComm)
						receivei[IDUpdateMessage.ID] = true
						receiveCount++
						//fmt.Println(time.Now(), "Received commit from Global ID: ", commitMessage.ID, ", commits count:", signCount, "/", int(gVar.ShardSize))
					}
				}
			case <-time.After(timeoutCosi):
				//resend after 15 seconds
				for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
					if !receivei[sendi[i]] {
						fmt.Println(time.Now(), "Request ID Update Message from global client:", sendi[i])
						SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "reqIDU", MyGlobalID)
					}
				}
			}
		}
	}

	//beginShard.GenerateSeed(&shard.PreviousSyncBlockHash)
	//beginShard.Sharding(&shard.GlobalGroupMems, &shard.ShardToGlobal)
	//shard.MyMenShard = &shard.GlobalGroupMems[MyGlobalID]
	fmt.Println(time.Now(), CacheDbRef.ID, "Shard Calculated")
	LeaderAddr = shard.GlobalGroupMems[shard.ShardToGlobal[shard.MyMenShard.Shard][0]].Address
	CacheDbRef.Mu.Lock()
	if CurrentEpoch != -1 {
		CacheDbRef.PrevHeight = CacheDbRef.PrevHeight + gVar.NumTxListPerEpoch + 3
	}
	CacheDbRef.DB.ClearTx()
	CacheDbRef.ShardNum = uint32(shard.MyMenShard.Shard)
	CacheDbRef.Leader = uint32(shard.ShardToGlobal[shard.MyMenShard.Shard][0])
	CacheDbRef.HistoryShard = append(CacheDbRef.HistoryShard, CacheDbRef.ShardNum)
	if CurrentEpoch != -1 {
		CacheDbRef.Clear()

	}
	for i := 0; i < gVar.NumTxListPerEpoch; i++ {
		for j := uint32(0); j < gVar.ShardSize; j++ {
			CacheDbRef.RepCache[i][j] = 0
		}
	}
	CacheDbRef.Mu.Unlock()
	for i := uint32(0); i < gVar.NumTxListPerEpoch; i++ {
		BatchCache[i] = nil
	}

	StopGetTx = make(chan bool, 1)
	close(Reputation.RepPowRxCh)
	Reputation.RepPowRxCh = make(chan Reputation.RepPowInfo, bufferSize)
	if shard.MyMenShard.Role == 1 {
		MinerReadyProcess()
	} else {
		LeaderReadyProcess(&shard.GlobalGroupMems)
		if CurrentEpoch != -1 {
			//warn  be careful when Epoch modified
			go SendStartBlock(&shard.GlobalGroupMems)
		}
	}
	fmt.Println("shard finished")
	if CacheDbRef.ID == 0 {
		tmpStr := fmt.Sprint("Epoch", CurrentEpoch, ":")
		for i := uint32(0); i < gVar.ShardCnt*gVar.ShardSize; i++ {
			tmpStr = tmpStr + fmt.Sprint(shard.GlobalGroupMems[i].Rep, " ")
		}
		sendTxMessage(gVar.MyAddress, "LogInfo", []byte(tmpStr))
	}
	if CurrentEpoch != -1 {
		FinalTxReadyCh <- true
	}

}

func GenerateLeaderProof(SNID snark.PedersenCommitment, RepComm snark.PedersenCommitment, rep int32, TotalRep int32,
	sl int, LC snark.LeaderCalInfo) [312]byte {
	return snark.ProveLP(uint64(CurrentEpoch+2), uint64(MyGlobalID), SNID.Comm_x.String(), SNID.Comm_y.String(), uint64(TotalRep),
		uint64(int64(rep)+gVar.RepUint64ToInt32), uint64(CurrentEpoch+2+MyGlobalID), RepComm.Comm_x.String(), RepComm.Comm_y.String(),
		LC.BlockHash, sl, LC.RNComm.Comm_x.String(), LC.RNComm.Comm_y.String(), gVar.LeaderBitSize, gVar.LeaderDifficulty)
}

//LeaderReadyProcess leader use this
func LeaderReadyProcess(ms *[]shard.MemShard) {
	var readyMessage readyInfo
	var it *shard.MemShard
	var membermask []byte
	var leadermask []byte
	intilizeMaskBit(&membermask, (int(gVar.ShardSize)+7)>>3, cosi.Disabled)
	intilizeMaskBit(&leadermask, (int(gVar.ShardCnt)+7)>>3, cosi.Disabled)
	readyMember := 1
	readyLeader := 1
	//sent announcement
	for i := 1; i < int(gVar.ShardSize); i++ {
		it = &(*ms)[shard.ShardToGlobal[shard.MyMenShard.Shard][i]]
		SendShardReadyMessage(it.Address, "readyAnnoun", readyInfo{MyGlobalID, CurrentEpoch})
	}
	//fmt.Println("wait for ready")

	cnt := 0
	timeoutflag := true
	SentLeaderReadyFlag = false
	for readyMember < int(gVar.ShardSize) && timeoutflag {
		select {
		case readyMessage = <-readyMemberCh:
			if readyMessage.Epoch == CurrentEpoch {
				readyMember++
				setMaskBit((*ms)[readyMessage.ID].InShardId, cosi.Enabled, &membermask)
				//fmt.Println("ReadyCount: ", readyCount)
			}
		case <-time.After(timeoutSync * 2):
			//fmt.Println("Wait shard signal time out")
			for i := 1; i < int(gVar.ShardSize); i++ {
				if maskBit(i, &membermask) == cosi.Disabled {
					it = &(*ms)[shard.ShardToGlobal[shard.MyMenShard.Shard][i]]
					fmt.Println("Resend shard ready to Member: ", shard.ShardToGlobal[shard.MyMenShard.Shard][i])
					SendShardReadyMessage(it.Address, "readyAnnoun", readyInfo{MyGlobalID, CurrentEpoch})
				}

			}
			cnt++
			if cnt > 5 && readyMember >= int(gVar.ShardSize*2/3) {
				timeoutflag = false
				fmt.Println("Timeout! Ready Member: ", readyMember, "/", gVar.ShardSize)
			}
		}
	}
	//warn only one shard now, thus the code follos is useless
	fmt.Println(time.Now(), "Shard is ready, sent to other shards")
	for i := 0; i < int(gVar.ShardCnt); i++ {
		if i != shard.MyMenShard.Shard {
			it = &(*ms)[shard.ShardToGlobal[i][0]]
			SendShardReadyMessage(it.Address, "leaderReady", readyInfo{shard.MyMenShard.Shard, CurrentEpoch})
		}
	}
	SentLeaderReadyFlag = true
	for readyLeader < int(gVar.ShardCnt) && timeoutflag {
		select {
		case readyMessage = <-readyLeaderCh:
			if readyMessage.Epoch == CurrentEpoch {
				if maskBit(readyMessage.ID, &leadermask) == cosi.Disabled {
					readyLeader++
					setMaskBit(readyMessage.ID, cosi.Enabled, &leadermask)
					fmt.Println(time.Now(), "ReadyLeaderCount: ", readyLeader)
				}
			}
		case <-time.After(timeoutSync * 5):
			for i := 0; i < int(gVar.ShardCnt); i++ {
				if maskBit(i, &leadermask) == cosi.Disabled && i != shard.MyMenShard.Shard {
					fmt.Println(time.Now(), "Send ReadyLeader to Shard", i, "ID", shard.ShardToGlobal[i][0])
					it = &(*ms)[shard.ShardToGlobal[i][0]]
					SendShardReadyMessage(it.Address, "reqLeaReady", readyInfo{shard.MyMenShard.Shard, CurrentEpoch})
				}
			}

		}

	}
	fmt.Println("All shards are ready.")
	StartSendTx = make(chan bool, 1)
	StartSendTx <- true
}

//HandleRequestShardLeaderReady handle the request from other leader
func HandleRequestShardLeaderReady(data []byte) {
	if !SentLeaderReadyFlag {
		return
	}
	data1 := make([]byte, len(data))
	copy(data1, data)
	var buff bytes.Buffer
	var payload readyInfo
	buff.Write(data1)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	if CurrentEpoch == payload.Epoch {
		it := shard.GlobalGroupMems[shard.ShardToGlobal[payload.ID][0]]
		SendShardReadyMessage(it.Address, "leaderReady", readyInfo{shard.MyMenShard.Shard, CurrentEpoch})
	}
}

//MinerReadyProcess member use this
func MinerReadyProcess() {
	var readyMessage readyInfo
	readyMessage = <-readyMemberCh
	fmt.Println("Miner waits for leader shard ready")
	for !(readyMessage.Epoch == CurrentEpoch && shard.ShardToGlobal[shard.MyMenShard.Shard][0] == readyMessage.ID) {
		readyMessage = <-readyMemberCh
	}
	SendShardReadyMessage(LeaderAddr, "shardReady", readyInfo{MyGlobalID, CurrentEpoch})
	fmt.Println(time.Now(), "Sent Ready")
}

//SendShardReadyMessage is to send shardready message
func SendShardReadyMessage(addr string, command string, message interface{}) {
	payload := gobEncode(message)
	request := append(commandToBytes(command), payload...)
	sendData(addr, request)
}

//HandleShardReady handle shard ready command
func HandleShardReady(request []byte) {
	var buff bytes.Buffer
	var payload readyInfo
	buff.Write(request)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	readyMemberCh <- payload

}

//HandleLeaderReady handle shard ready command from other leader
func HandleLeaderReady(request []byte) {
	var buff bytes.Buffer
	var payload readyInfo
	buff.Write(request)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	readyLeaderCh <- payload
}
