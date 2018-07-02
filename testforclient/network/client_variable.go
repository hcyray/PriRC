package network

import (
	"github.com/uchihatmtkinu/RC/Reputation/cosi"
	"github.com/uchihatmtkinu/RC/ed25519"
	"github.com/uchihatmtkinu/RC/rccache"
	"github.com/uchihatmtkinu/RC/gVar"
	"github.com/uchihatmtkinu/RC/Reputation"
	"time"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 16
const bufferSize = 1000
const timeoutCosi = 10 * time.Second //10seconds for timeout
const timeoutSync = 20 * time.Second
const timeSyncNotReadySleep = 5 * time.Second
const timeoutResponse = 120 * time.Second

//currentEpoch epoch now
var CurrentEpoch int
//LeaderAddr leader address
var LeaderAddr string
//MyGlobalID my global ID
var MyGlobalID int
//var AddrMapToInd map[string]int //ip+port
//var GroupMems []shard.MemShard
//GlobalAddrMapToInd
var GlobalAddrMapToInd map[string]int

var CacheDbRef rccache.DbRef


//------------------- shard process ----------------------
//readyInfo
type readyInfo struct{
	ID 		int
	Epoch	int
}
//readyCh channel used in shard process, indicates the ready for a new epoch
var readyCh	chan readyInfo

//------------------- rep pow process -------------------------
//powInfo used in pow
type powInfo struct{
	ID		int
	Epoch	int
	Block   []byte
}



//------------------- cosi process -------------------------
//commitInfo used in commitCh
type commitInfo struct {
	ID 		int
	Commit  cosi.Commitment
}

// challengeInfo challenge info
type challengeInfo struct {
	AggregatePublicKey  ed25519.PublicKey
	AggregateCommit     cosi.Commitment
}

//responseInfo response info
type responseInfo struct {
	ID			int
	Sig 		cosi.SignaturePart
}


//channel used in cosi
//cosiAnnounceCh cosi announcement channel
var cosiAnnounceCh 	chan []byte
//cosiCommitCh		cosi commitment channel
var cosiCommitCh 	chan commitInfo
var cosiChallengeCh chan challengeInfo
var cosiResponseCh 	chan responseInfo
var cosiSigCh  		chan cosi.SignaturePart


//---------------------- sync process -------------
//syncSBInfo sync block info
type syncSBInfo struct {
	ID				int
	Block			Reputation.SyncBlock
}

//syncTBInfo tx block info
type syncTBInfo struct {
	ID				int
	Block			[]byte
}

//syncRequestInfo request sync
type syncRequestInfo struct {
	ID 				int
	Epoch			int
}

type syncNotReadyInfo struct {
	ID 				int
	Epoch			int
}

//channel used in sync
//syncCh
var syncSBCh [gVar.ShardCnt] 		chan syncSBInfo
var syncTBCh [gVar.ShardCnt]	 	chan syncTBInfo
var syncNotReadyCh [gVar.ShardCnt]	chan bool


//CoSiFlag flag determine the process has began
var CoSiFlag	bool


//channel used to indicate the process start
var IntialReadyCh chan bool
var ShardReadyCh chan bool
var CoSiReadyCh chan bool
var SyncReadyCh chan bool