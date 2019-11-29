package network

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/uchihatmtkinu/PriRC/snark"
	"log"
	"math/rand"
	"sort"
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

	//Generating Leader Proof
	leaderflag := false
	blockHash := shard.PreviousSyncBlockHash[0][:]
	rand.Seed(int64(shard.MyMenShard.Shard*3000+shard.MyMenShard.InShardId) + time.Now().UTC().UnixNano())
	sendi := rand.Perm(int(gVar.ShardSize * gVar.ShardCnt))
	flagi := make([]bool, int(gVar.ShardSize*gVar.ShardCnt))
	var LeaderCandidate []shard.SortTypes

	if CurrentEpoch != -1 {
		for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
			shard.GlobalGroupMems[i].ClearRep()
		}
	} else {
		//TODO move to other place
		for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
			shard.GlobalGroupMems[i].AttackID = i
		}
	}

	for !leaderflag {
		var slotLeaderCandidate []shard.SortType
		var MyLeaderMessage LeaderInfo
		MyLeader.mux.Lock()
		if CurrentSlot == 0 {
			MyLeader.f = true
		}
		CurrentSlot++
		fmt.Println("Leader Election, slot: ", CurrentSlot)

		MyLeader.lc.LeaderCal(&shard.MyMenShard.EpochSNID, &shard.MyMenShard.RepComm,
			blockHash, CurrentSlot, shard.TotalRep, shard.MyMenShard.TotalRep)

		if MyLeader.lc.Leader {
			fmt.Println("I am a leader candidate")
			shard.MyLeaderProof = GenerateLeaderProof(shard.MyMenShard.EpochSNID, shard.MyMenShard.RepComm,
				shard.MyMenShard.TotalRep, shard.TotalRep, CurrentSlot, MyLeader.lc,shard.MyMenShard.AttackID)
			MyLeader.mux.Unlock()
			MyLeader.mux.RLock()
			MyLeaderMessage = LeaderInfo{true, MyGlobalID, CurrentSlot, shard.MyMenShard.EpochSNID,
				MyLeader.lc.RNComm, shard.MyLeaderProof}
			var tempSortType shard.SortType
			tempSortType.NewSortType(MyGlobalID, MyLeader.lc.RNComm.Comm_x, MyLeader.lc.RNComm.Comm_y)
			slotLeaderCandidate = append(slotLeaderCandidate, tempSortType)
			MyLeader.mux.RUnlock()
			if gVar.ExperimentBadLevel != 0 {
				if MyGlobalID >= int(gVar.ShardCnt*gVar.ShardSize/3) {
					leaderflag = true
				}
			} else {
				leaderflag = true
			}

		} else {
			MyLeader.mux.Unlock()
			MyLeader.mux.RLock()
			MyLeaderMessage = LeaderInfo{false, MyGlobalID, CurrentSlot, shard.MyMenShard.EpochSNID, MyLeader.lc.RNComm, [312]byte{0}}
			MyLeader.mux.RUnlock()
		}
		for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
			if sendi[i] != MyGlobalID {
				flagi[sendi[i]] = false
				MyLeader.mux.RLock()
				SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "LI", MyLeaderMessage)
				MyLeader.mux.RUnlock()
			}
		}
		flagi[MyGlobalID] = true
		receiveCount := 1
		for receiveCount < int(gVar.ShardSize*gVar.ShardCnt) {
			select {
			case LeaderMessage := <-LeaderInfoCh:
				if LeaderMessage.Slot == CurrentSlot && !flagi[LeaderMessage.ID] {
					if !LeaderMessage.Leader {
						flagi[LeaderMessage.ID] = true
						receiveCount++
					} else {
						MyLeader.mux.RLock()
						if VerifyLeaderProof(LeaderMessage.LeaderProof, LeaderMessage.IDComm, shard.GlobalGroupMems[LeaderMessage.ID].RepComm,
							shard.TotalRep, LeaderMessage.Slot, MyLeader.lc.BlockHash, LeaderMessage.RNComm) {
							fmt.Println("Leader Candidate:", LeaderMessage.ID)
							var tempSortType shard.SortType
							tempSortType.NewSortType(LeaderMessage.ID, LeaderMessage.RNComm.Comm_x, LeaderMessage.RNComm.Comm_y)
							slotLeaderCandidate = append(slotLeaderCandidate, tempSortType)
							flagi[LeaderMessage.ID] = true
							receiveCount++
						} else {
							tmpStr := fmt.Sprint("Shard Leader Failed:")
							sendTxMessage(gVar.MyAddress, "LogInfo", []byte(tmpStr))
						}
						MyLeader.mux.RUnlock()
						if gVar.ExperimentBadLevel != 0 {
							if LeaderMessage.ID >= int(gVar.ShardCnt*gVar.ShardSize/3) {
								leaderflag = true
							}
						} else {
							leaderflag = true
						}
					}
				}
			case <-time.After(timeoutSync):
				//resend after 20 seconds
				for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
					if !flagi[sendi[i]] {
						fmt.Println(time.Now(), "Request Leader Info from global client:", sendi[i])
						SendIDComm(shard.GlobalGroupMems[sendi[i]].Address, "reqLI", ReqLeaderInfo{MyGlobalID, shard.MyMenShard.EpochSNID, CurrentSlot})
					}
				}
			}
		}
		LeaderCandidate = append(LeaderCandidate, slotLeaderCandidate)
	}
	//Select leader from leader candidate
	for i := 0; i < int(gVar.ShardSize*gVar.ShardCnt); i++ {
		flagi[i] = false
	}
	lInd := 0
	var lList [gVar.ShardCnt * gVar.ShardSize]int
	for _, slc := range LeaderCandidate {
		if len(slc) > 0 {
			sort.Sort(slc)
			for i := 0; i < len(slc); i++ {
				if !flagi[slc[i].ID] {
					lList[lInd] = slc[i].ID
					lInd++
					flagi[slc[i].ID] = true
				}
			}
		}
	}
	fmt.Println("Final Leader list: ", lList)
	MyLeader.mux.Lock()
	MyLeader.f = false
	MyLeader.mux.Unlock()
	shard.ShardToGlobal = make([][]int, gVar.ShardCnt)
	tempi := 0
	for i := uint32(0); i < gVar.ShardCnt; i++ {
		shard.ShardToGlobal[i] = make([]int, gVar.ShardSize)
		for j := uint32(0); j < gVar.ShardSize; j++ {
			if int(j) < lInd {
				shard.ShardToGlobal[i][j] = lList[j]
			} else {
				for flagi[tempi] {
					tempi++
				}
				shard.ShardToGlobal[i][j] = tempi
				tempi++
			}
			if j == 0 {
				shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].Role = 0
			} else {
				shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].Role = 1
			}
			shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].PreShard = int(i)
			shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].Shard = int(i)
			shard.GlobalGroupMems[shard.ShardToGlobal[i][j]].InShardId = int(j)
		}
	}
	//beginShard.GenerateSeed(&shard.PreviousSyncBlockHash)
	//beginShard.Sharding(&shard.GlobalGroupMems, &shard.ShardToGlobal)
	//shard.MyMenShard = &shard.GlobalGroupMems[MyGlobalID]
	if MyGlobalID == shard.ShardToGlobal[0][0] {
		tmpStr := fmt.Sprintln("Leader List:", lList)
		sendTxMessage(gVar.MyAddress, "LogInfo", []byte(tmpStr))
	}
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
		StartSendTx = make(chan bool, 1)
		StartSendTx <- true
		if CurrentEpoch != -1 {
			//warn  be careful when Epoch modified
			go SendStartBlock(&shard.GlobalGroupMems)
		}
	}
	fmt.Println("shard finished")
	if CacheDbRef.ID == 0 {
		tmpStr := fmt.Sprint("Epoch", CurrentEpoch, ":")
		for i := uint32(0); i < gVar.ShardCnt*gVar.ShardSize; i++ {
			tmpStr = tmpStr + fmt.Sprint(shard.GlobalGroupMems[i].TotalRep, " ")
		}
		sendTxMessage(gVar.MyAddress, "LogInfo", []byte(tmpStr))
	}
	if CurrentEpoch != -1 {
		FinalTxReadyCh <- true
	}

}

func GenerateLeaderProof(SNID snark.PedersenCommitment, RepComm snark.PedersenCommitment, rep int64, totalRep int64,
	sl int, LC snark.LeaderCalInfo, ind int) [312]byte {
	return snark.ProveLP(1, uint64(MyGlobalID), SNID.Comm_x.String(), SNID.Comm_y.String(), uint64(totalRep),
		uint64(rep+gVar.RepUint64ToInt32), uint64(ind+1), RepComm.Comm_x.String(), RepComm.Comm_y.String(),
		LC.BlockHash, sl, LC.RNComm.Comm_x.String(), LC.RNComm.Comm_y.String(), gVar.LeaderDifficulty, gVar.LeaderBitSize)
}

func VerifyLeaderProof(proof [312]byte, SNID snark.PedersenCommitment, RepComm snark.PedersenCommitment, totalRep int64,
	sl int, blockHash string, RNComm snark.PedersenCommitment) bool {
	return snark.VerifyLP(proof, SNID.Comm_x.String(), SNID.Comm_y.String(), uint64(totalRep), RepComm.Comm_x.String(), RepComm.Comm_y.String(),
		blockHash, sl, RNComm.Comm_x.String(), RNComm.Comm_y.String())
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
			if cnt > 5 {
				tmpStr := fmt.Sprint("Shard Leader Ready failed Epoch", CurrentEpoch, ":")
				sendTxMessage(gVar.MyAddress, "LogInfo", []byte(tmpStr))
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
	//StartSendTx = make(chan bool, 1)
	//StartSendTx <- true
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

func HandleLeaderInfo(request []byte) {
	var buff bytes.Buffer
	var payload LeaderInfo
	buff.Write(request)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	LeaderInfoCh <- payload
}
func HandleRequestLeaderInfo(request []byte) {
	MyLeader.mux.RLock()
	defer MyLeader.mux.RUnlock()
	if !MyLeader.f {
		return
	}
	var buff bytes.Buffer
	var payload ReqLeaderInfo
	buff.Write(request)
	dec := gob.NewDecoder(&buff)
	err := dec.Decode(&payload)
	if err != nil {
		log.Panic(err)
	}
	if CurrentSlot >= payload.Slot {
		if MyLeader.lc.Leader {
			SendIDComm(shard.GlobalGroupMems[payload.ID].Address, "LI",
				LeaderInfo{true, MyGlobalID, CurrentSlot, shard.MyMenShard.EpochSNID, MyLeader.lc.RNComm, shard.MyLeaderProof})
		} else {
			SendIDComm(shard.GlobalGroupMems[payload.ID].Address, "LI",
				LeaderInfo{false, MyGlobalID, CurrentSlot, shard.MyMenShard.EpochSNID, MyLeader.lc.RNComm, [312]byte{0}})
		}
	}

}
