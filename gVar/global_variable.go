package gVar

import "time"

//MagicNumber magic
const MagicNumber byte = 66

//ShardSize is the number of miners in one shard
const ShardSize uint32 = 100

//ShardCnt is the number of shards
const ShardCnt uint32 = 1

//used in rep calculation, scaling factor
const RepTP = 1
const RepTN = 1
const RepFP = 0
const RepFN = 0

//channel

const SlidingWindows = 4

//NumTxListPerEpoch is the number of txblocks in one epoch
const NumTxListPerEpoch = 10 //60

//NumTxBlockForRep is the number of blocks for one rep block
const NumTxBlockForRep = 4 //10

const NumberRepPerEpoch = NumTxListPerEpoch/NumTxBlockForRep + 1

//const GensisAcc = []byte{0}

const GensisAccValue = 2147483647

const TxSendInterval = 10

// number of transactions - TPS
const NumOfTxForTest = 1000

const GeneralSleepTime = 50

var T1 time.Time = time.Now()

const BandDiverse = false

// client for listen the leader
const MyAddress = "172.31.83.178:9999"

const MaxBand = 38 * 1024
const MinBand = 2 * 1024

// 0 - no bad, 1 - always bad, 2 - bad when leader is bad
const ExperimentBadLevel = 0
const RandomAttack = false

//int32  : -2147483648 to 2147483647
//uint64 : 0 to 18446744073709551615
const RepUint64ToInt32 = int64(3e10)

//Leader Proof
// bit size for random number
const LeaderBitSize = 50
const LeaderDifficulty = 0
