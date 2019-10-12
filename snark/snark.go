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

// proof of Homomorphic Pedersen Commitment
func ProveHPC(m uint64, r uint64, commX []byte, lenX *int, commY []byte, lenY *int) [312]byte {
	var proof_buf [312]byte
	c_lenX := C.int(0)
	c_lenY := C.int(0)
	C.prc_prove_hpc(unsafe.Pointer(&proof_buf[0]), C.ulong(m), C.ulong(r), (*C.char)(unsafe.Pointer(&commX[0])), (*C.int)(&c_lenX), (*C.char)(unsafe.Pointer(&commY[0])), (*C.int)(&c_lenY))
	*lenX = int(c_lenX)
	*lenY = int(c_lenY)

	return proof_buf
}

// verify proof of Homomorphic Pedersen Commitment
func VerifyHPC(proof [312]byte, commX string, commY string) bool {
	ret := C.prc_verify_hpc_with_commit(unsafe.Pointer(&proof[0]), C.CString(commX), C.CString(commY))
	if ret {
		return true
	} else {
		return false
	}
}
