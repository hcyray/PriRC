package shard

import "github.com/uchihatmtkinu/PriRC/snark"

//RoleLeader  role is leader
const RoleLeader = 0

//RoleMember  role is member
const RoleMember = 1

//ShardToGlobal shard ind+in shard ind -> global index
var ShardToGlobal [][]int

//GlobalGroupMems global memshard
var GlobalGroupMems []MemShard

//NumMems number of members within one shard
var NumMems int

//MyMenShard my
var MyMenShard *MemShard

//used in ID and Rep Merkle tree
var IDMerkleTree snark.MerkleTree
var RepMerkleTree snark.MerkleTree
var MyIDMTProof snark.MerkleProof
var MyRepMTProof snark.MerkleProof

// used for snark proof
var MyIDCommProof [312]byte
var MySNIDCommProof [312]byte
var MyRepCommProof [312]byte

//used for identity update
var MyIDUpdateProof [312]byte

//PreviousSyncBlockHash the hash array of previous sync block from all the shards
var PreviousSyncBlockHash [][32]byte

//PreviousSyncBlockHash the hash array of previous final block from all the shards
var PrevFinalBlockHash [][32]byte

//StartFlag indicate whether it is the first block generated in this epoch
var StartFlag bool
