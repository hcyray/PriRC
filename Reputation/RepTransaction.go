package Reputation

import "github.com/uchihatmtkinu/PriRC/snark"

//uint64: 0 to 18,446,744,073,709,551,615 (2^64-1)
//int64: -9,223,372,036,854,775,808 to +9,223,372,036,854,775,807 (-2^63 and 2^63-1).
type RepTransaction struct {
	GlobalIDX [32]byte
	GlobalIDY [32]byte
	//AddrReal 	[32]byte //public key -> id
	//Rep   int32
	RepPCX [32]byte
	RepPCY [32]byte
}

//new reputation transaction
func (r *RepTransaction) NewRepTransaction(globalID snark.PedersenCommitment, pc snark.PedersenCommitment) {
	copy(r.GlobalIDX[:], globalID.Comm_x.Bytes()[:32])
	copy(r.GlobalIDY[:], globalID.Comm_y.Bytes()[:32])
	copy(r.RepPCX[:], pc.Comm_x.Bytes()[:32])
	copy(r.RepPCY[:], pc.Comm_y.Bytes()[:32])
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
