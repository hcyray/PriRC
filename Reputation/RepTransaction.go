package Reputation

import "github.com/uchihatmtkinu/PriRC/snark"

//uint64: 0 to 18,446,744,073,709,551,615 (2^64-1)
//int64: -9,223,372,036,854,775,808 to +9,223,372,036,854,775,807 (-2^63 and 2^63-1).
type RepTransaction struct {
	GlobalID int
	//AddrReal 	[32]byte //public key -> id
	Rep   int32
	RepPC snark.PedersenCommitment
}

//new reputation transaction
func NewRepTransaction(globalID int, rep int32) *RepTransaction {

	tx := RepTransaction{globalID, rep / 10}
	return &tx
}

// SetID sets ID of a transaction
/*
func (tx *RepTransaction) SetID() {
	var encoded bytes.Buffer
	var hash [32]byte

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}
	hash = sha256.Sum256(encoded.Bytes())
	tx.ID = hash[:]
}
*/
