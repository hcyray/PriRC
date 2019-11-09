package snark

// #cgo LDFLAGS: -L${SRCDIR} -lbaby_jubjub_ecc -lm  -lstdc++ -lsnark -lff  -lprocps -lgmp -lgmpxx
// #include "baby_jubjub_ecc/prc.h"
import "C"
import (
	"sync"
	"unsafe"
)

// Init() is only ever called once
var onceInit sync.Once

// Initialization for zkp
func Init() {
	onceInit.Do(func() {
		C.prc_initialize()
	})
}

//HPC param gen
func ParamGenHPC() {
	C.prc_paramgen_hpc()
}

// proof of Homomorphic Pedersen Commitment
func ProveHPC(m uint64, r uint64, commX string, commY string) [312]byte {
	var proof_buf [312]byte
	C.prc_prove_hpc(unsafe.Pointer(&proof_buf[0]), C.ulong(m), C.ulong(r), C.CString(commX), C.CString(commY))

	return proof_buf
}

// verify proof of Homomorphic Pedersen Commitment
func VerifyHPC(proof [312]byte, commX string, commY string) bool {
	ret := C.prc_verify_hpc(unsafe.Pointer(&proof[0]), C.CString(commX), C.CString(commY))
	if ret {
		return true
	} else {
		return false
	}
}

//Leader Proof param gen
func ParamGenLP() {
	C.prc_paramgen_lp()
}

//TODO
// prove leader proof
func ProveLP(snM uint64, snR uint64, snX string, snY string, T string,
	repM uint64, repR uint64, repX string, repY string, blockHash string, sl int) [312]byte {
	var proof_buf [312]byte
	C.prc_prove_lp(unsafe.Pointer(&proof_buf[0]), C.ulong(snM), C.ulong(snR), C.CString(snX), C.CString(snY),
		C.CString(T), C.ulong(repM), C.ulong(repR), C.CString(repX), C.CString(repY), C.CString(blockHash), C.int(sl))
	return proof_buf
}

//TODO
// verify leader proof
func VerifyLP(proof [312]byte, snX string, snY string, T string, repX string, repY string, blockHash string, sl int) bool {
	ret := C.prc_verify_lp(unsafe.Pointer(&proof[0]), C.CString(snX), C.CString(snY), C.CString(T),
		C.CString(repX), C.CString(repY), C.CString(blockHash), C.int(sl))
	if ret {
		return true
	} else {
		return false
	}
}

//Identity update Proof param gen
func ParamGenIUP(d int) {
	C.prc_paramgen_iup(C.int(d))
}

//TODO
// prove identity update
func ProveIUP(m uint64, r uint64, commX string, commY string) [312]byte {
	var proof_buf [312]byte
	C.prc_prove_lp(unsafe.Pointer(&proof_buf[0]), C.ulong(snM), C.ulong(snR), C.CString(snX), C.CString(snY),
		C.CString(T), C.ulong(repM), C.ulong(repR), C.CString(repX), C.CString(repY), C.CString(blockHash), C.int(sl))
	return proof_buf
}

//TODO
// verify identity update
func VerifyIUP(proof [312]byte, commX string, commY string) bool {
	ret := C.prc_verify_lp(unsafe.Pointer(&proof[0]), C.CString(snX), C.CString(snY), C.CString(T),
		C.CString(repX), C.CString(repY), C.CString(blockHash), C.int(sl))
	if ret {
		return true
	} else {
		return false
	}
}

//TODO
// prove PoW
func ProvePOW(m uint64, r uint64, commX string, commY string) [312]byte {
	return [312]byte{}
}

//TODO
// verify proof of ID
func VerifyPOW(proof [312]byte, commX string, commY string) bool {
	return false
}
