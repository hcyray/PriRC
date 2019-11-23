package network

import (
	"github.com/uchihatmtkinu/PriRC/snark"
	"sync"
	"time"

	"github.com/uchihatmtkinu/PriRC/Reputation"
	"github.com/uchihatmtkinu/PriRC/Reputation/cosi"
	"github.com/uchihatmtkinu/PriRC/basic"
	"github.com/uchihatmtkinu/PriRC/ed25519"
	"github.com/uchihatmtkinu/PriRC/gVar"
	"github.com/uchihatmtkinu/PriRC/rccache"
)

const protocol = "tcp"
const nodeVersion = 1
const commandLength = 16
const bufferSize = 1000
const timeoutCosi = 15 * time.Second //10seconds for timeout
const timeoutSync = 10 * time.Second
const timeSyncNotReadySleep = 5 * time.Second
const timeoutResponse = 120 * time.Second
const timeoutTL = 60 * time.Second
const timeoutTxDecRev = 5 * time.Second
const timeoutResentTxmm = 2 * time.Second
const timeoutGetTx = time.Microsecond * 100

//CurrentEpoch epoch now
var CurrentEpoch int
var CurrentRepRound int
var CurrentSlot int

//LeaderAddr leader address
var LeaderAddr string

//MyGlobalID my global ID
var MyGlobalID int

//var AddrMapToInd map[string]int //ip+port
//var GroupMems []shard.MemShard
//GlobalAddrMapToInd
//var GlobalAddrMapToInd map[string]int

//CacheDbRef local database
var CacheDbRef rccache.DbRef

//------------------- IDMerkleTree process ----------------
type IDCommInfo struct {
	ID       int
	IDComm   snark.PedersenCommitment
	IDProof  [312]byte
	RepComm  snark.PedersenCommitment
	RepProof [312]byte
}

//channel used in ID commitment
var IDCommCh chan IDCommInfo

//Leader Info
type LeaderInfo struct {
	Leader      bool
	ID          int
	Slot        int
	IDComm      snark.PedersenCommitment
	RNComm      snark.PedersenCommitment
	LeaderProof [312]byte
}

//Requst Leader Info
type ReqLeaderInfo struct {
	ID   int
	SNID snark.PedersenCommitment
	Slot int
}

//channel used in Leader proof
var LeaderInfoCh chan LeaderInfo

//------------------- IDUpdate process -------------------
type IDUpdateInfo struct {
	ID            int
	IDComm        snark.PedersenCommitment
	RepComm       snark.PedersenCommitment
	IDUpdateProof [312]byte
}

//channel used in IDUpdate
var IDUpdateCh chan IDUpdateInfo

//------------------- shard process ----------------------
//readyInfo
type readyInfo struct {
	ID    int
	Epoch int
}

//readyMemberCh channel used in shard process, indicates the ready of the member for a new epoch
var readyMemberCh chan readyInfo

//readyLeaderCh channel used in shard process, indicates the ready of other shards for a new epoch
var readyLeaderCh chan readyInfo

//------------------- rolling process -------------------------
type rollingInfo struct {
	ID     uint32
	Epoch  uint32
	Leader uint32
}

//------------------- rep pow process -------------------------
//powInfo used in pow
type powInfo struct {
	ID    int
	Round int
	Hash  [32]byte
	Nonce int
}

//requetRepInfo used in pow
type requetRepInfo struct {
	ID    int
	Round int
}

//RepBlockRxInfo receive rep block
type RepBlockRxInfo struct {
	Round int
	Block Reputation.RepBlock
}

//RxRepBlockCh,
var RxRepBlockCh chan *Reputation.RepBlock

//------------------- cosi process -------------------------
//announceInfo used in cosi announce
type announceInfo struct {
	ID      int
	Message []byte
	Round   int
	Epoch   int
}

//commitInfo used in commitCh
type commitInfo struct {
	ID     int
	Commit cosi.Commitment
	Round  int
	Epoch  int
}

// challengeInfo challenge info
type challengeInfo struct {
	AggregatePublicKey ed25519.PublicKey
	AggregateCommit    cosi.Commitment
	Round              int
	Epoch              int
}

//responseInfo response info
type responseInfo struct {
	ID    int
	Sig   cosi.SignaturePart
	Round int
	Epoch int
}

//channel used in cosi
//cosiAnnounceCh cosi announcement channel
var cosiAnnounceCh chan announceInfo

//cosiCommitCh		cosi commitment channel
var cosiCommitCh chan commitInfo
var cosiChallengeCh chan challengeInfo
var cosiResponseCh chan responseInfo
var cosiSigCh chan responseInfo

//finalSignal
var finalSignal chan []byte

var startRep chan repInfo
var startTx chan int
var startSync chan bool
var CosiData map[int]cosi.SignaturePart

//syncSBInfo sync block info
type repInfo struct {
	Last  bool
	Hash  [][32]byte
	Rep   *[]int32
	Round int
}

//---------------------- sync process -------------
//syncSBInfo sync block info
type syncSBInfo struct {
	ID    int
	Block Reputation.SyncBlock
}

//syncTBInfo tx block info
type syncTBInfo struct {
	ID    int
	Block basic.TxBlock
}

//syncRequestInfo request sync
type syncRequestInfo struct {
	ID    int
	Round int
	Epoch int
}

//txDecRev request sync
type txDecRev struct {
	ID    uint32
	Round uint32
}

//TxBRequestInfo request txB
type TxBRequestInfo struct {
	Address string
	Shard   int
	Height  int
}

type syncNotReadyInfo struct {
	ID    int
	Epoch int
}

type TxBatchInfo struct {
	ID      uint32
	ShardID uint32
	Epoch   uint32
	Round   uint32
	Data    []byte
}

//channel used in sync
//syncCh
var syncSBCh [gVar.ShardCnt]chan syncSBInfo
var syncTBCh [gVar.ShardCnt]chan syncTBInfo
var syncNotReadyCh [gVar.ShardCnt]chan bool

//ShardDone flag determine whether the shard process is done
//var ShardDone bool

//CoSiFlag flag determine the CoSi process has began
var CoSiFlag bool

//SyncFlag flag determine the Sync process has began
var SyncFlag bool

//ReadyCh channel used to indicate the process start
var IntialReadyCh chan bool

//safe update ready
type SafeIDUpdateReady struct {
	f   bool
	mux sync.Mutex
}

var IDUpdateReady SafeIDUpdateReady

type SafeILeaderInfo struct {
	f   bool
	lc  snark.LeaderCalInfo
	mux sync.RWMutex
}

var MyLeader SafeILeaderInfo

var waitForFB chan bool

//FinalTxReadyCh whether the FB is done
var FinalTxReadyCh chan bool

var StartLastTxBlock chan int
var StartNewTxlist chan bool
var StartSendingTx chan bool

var TxDecRevChan [gVar.NumTxListPerEpoch]chan txDecRev
var TLChan [gVar.NumTxListPerEpoch]chan uint32
var RepFinishChan [gVar.NumberRepPerEpoch]chan bool

var TxBatchCache chan TxBatchInfo

var StopGetTx chan bool

var txMCh [gVar.NumTxListPerEpoch]chan txDecRev

var bindAddress string

var BatchCache [gVar.NumTxListPerEpoch][]TxBatchInfo

var TDSChan [gVar.NumTxListPerEpoch]chan int
var TBChan [gVar.NumTxListPerEpoch]chan int
var TBBChan [gVar.NumTxListPerEpoch]chan int
var StartSendTx chan bool
var rollingChannel chan rollingInfo
var VTDChannel chan rollingInfo
var rollingTxB chan []byte
var FBSent chan bool
var startDone bool
