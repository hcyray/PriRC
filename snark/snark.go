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
	cCommX := C.CString(commX)
	cCommY := C.CString(commY)
	defer C.free(unsafe.Pointer(cCommX))
	defer C.free(unsafe.Pointer(cCommY))

	C.prc_prove_hpc(unsafe.Pointer(&proof_buf[0]), C.ulong(m), C.ulong(r), cCommX, cCommY)
	return proof_buf
}

// verify proof of Homomorphic Pedersen Commitment
func VerifyHPC(proof [312]byte, commX string, commY string) bool {
	cCommX := C.CString(commX)
	cCommY := C.CString(commY)
	defer C.free(unsafe.Pointer(cCommX))
	defer C.free(unsafe.Pointer(cCommY))

	ret := C.prc_verify_hpc(unsafe.Pointer(&proof[0]), cCommX, cCommY)
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

// prove leader proof
func ProveLP(snM uint64, snR uint64, snX string, snY string, T string,
	repM uint64, repR uint64, repX string, repY string, blockHash string, sl int) [312]byte {
	var proof_buf [312]byte

	cSnX := C.CString(snX)
	cSnY := C.CString(snY)
	cRepX := C.CString(repX)
	cRepY := C.CString(repY)
	cT := C.CString(T)
	cBlockHash := C.CString(blockHash)
	defer C.free(unsafe.Pointer(cSnX))
	defer C.free(unsafe.Pointer(cSnY))
	defer C.free(unsafe.Pointer(cRepX))
	defer C.free(unsafe.Pointer(cRepY))
	defer C.free(unsafe.Pointer(cT))
	defer C.free(unsafe.Pointer(cBlockHash))

	C.prc_prove_lp(unsafe.Pointer(&proof_buf[0]), C.ulong(snM), C.ulong(snR), cSnX, cSnY,
		cT, C.ulong(repM), C.ulong(repR), cRepX, cRepY, cBlockHash, C.int(sl))
	return proof_buf
}

// verify leader proof
func VerifyLP(proof [312]byte, snX string, snY string, T string, repX string, repY string, blockHash string, sl int) bool {
	cSnX := C.CString(snX)
	cSnY := C.CString(snY)
	cRepX := C.CString(repX)
	cRepY := C.CString(repY)
	cT := C.CString(T)
	cBlockHash := C.CString(blockHash)
	defer C.free(unsafe.Pointer(cSnX))
	defer C.free(unsafe.Pointer(cSnY))
	defer C.free(unsafe.Pointer(cRepX))
	defer C.free(unsafe.Pointer(cRepY))
	defer C.free(unsafe.Pointer(cT))
	defer C.free(unsafe.Pointer(cBlockHash))

	ret := C.prc_verify_lp(unsafe.Pointer(&proof[0]), cSnX, cSnY, cT, cRepX, cRepY, cBlockHash, C.int(sl))
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

func prc_test(proof1 [312]byte, proof2 [312]byte, a []bool, b []string, d int) {

	ca := make([]C.bool, d)
	cb := C.CString(b[0])
	for i := 0; i < d; i++ {
		ca[i] = C.bool(a[i])
		cb = append(cb, C.CString(b[i]))
	}
	C.prc_test(unsafe.Pointer(&proof1[0]), unsafe.Pointer(&proof2[0]), ca, cb, C.int(d))

}

/*
//TODO
// prove identity update
func ProveIUP( d int,

	m uint64, r uint64, commX string, commY string) [312]byte {
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
*/
