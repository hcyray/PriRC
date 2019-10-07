package snark

// #cgo LDFLAGS: -L${SRCDIR} -lbaby_jubjub_ecc -lm -lstdc++ -lgmp -lgomp -lff -lsnark
// #include "libsnark/baby_jubjub_ecc/prc.h"
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
func ProveHPC(m uint64, r uint64, commX string, lenX int, commY string, lenY int) [312]byte {
	var proof_buf [312]byte
	c_lenX := C.int(lenX)
	c_lenY := C.int(lenY)
	C.prc_prove_hpc(unsafe.Pointer(&proof_buf[0]), C.ulong(m), C.ulong(r), C.CString(commX), (*C.int)(&c_lenX), C.CString(commY), (*C.int)(&c_lenY))
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
