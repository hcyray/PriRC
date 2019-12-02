package snark

// #cgo LDFLAGS: -L${SRCDIR} -lbaby_jubjub_ecc -lm  -lstdc++ -lsnark -lff -lzm  -lprocps -lgmp -lgmpxx
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
func ParamGenLP(d int, n int) {
	C.prc_paramgen_lp(C.int(d), C.int(n))
}

// prove leader proof
func ProveLP(snM uint64, snR uint64, snX string, snY string, totalRep uint64, repM uint64, repR uint64,
	repX string, repY string, blockHash string, sl int, rnX string, rnY string, d int, n int, avgRep uint64) [312]byte {
	var proof_buf [312]byte

	cSnX := C.CString(snX)
	cSnY := C.CString(snY)
	cRepX := C.CString(repX)
	cRepY := C.CString(repY)
	cBlockHash := C.CString(blockHash)
	cRNX := C.CString(rnX)
	cRNY := C.CString(rnY)
	defer C.free(unsafe.Pointer(cSnX))
	defer C.free(unsafe.Pointer(cSnY))
	defer C.free(unsafe.Pointer(cRepX))
	defer C.free(unsafe.Pointer(cRepY))
	defer C.free(unsafe.Pointer(cBlockHash))
	defer C.free(unsafe.Pointer(cRNX))
	defer C.free(unsafe.Pointer(cRNY))

	C.prc_prove_lp(unsafe.Pointer(&proof_buf[0]), C.ulong(snM), C.ulong(snR), cSnX, cSnY, C.ulong(totalRep),
		C.ulong(repM), C.ulong(repR), cRepX, cRepY, cBlockHash, C.int(sl), cRNX, cRNY, C.int(d), C.int(n), C.ulong(avgRep))
	return proof_buf
}

// verify leader proof
func VerifyLP(proof [312]byte, snX string, snY string, totalRep uint64, repX string, repY string, blockHash string,
	sl int, rnX string, rnY string, avgRep uint64) bool {
	cSnX := C.CString(snX)
	cSnY := C.CString(snY)
	cRepX := C.CString(repX)
	cRepY := C.CString(repY)
	cBlockHash := C.CString(blockHash)
	cRNX := C.CString(rnX)
	cRNY := C.CString(rnY)
	defer C.free(unsafe.Pointer(cSnX))
	defer C.free(unsafe.Pointer(cSnY))
	defer C.free(unsafe.Pointer(cRepX))
	defer C.free(unsafe.Pointer(cRepY))
	defer C.free(unsafe.Pointer(cBlockHash))
	defer C.free(unsafe.Pointer(cRNX))
	defer C.free(unsafe.Pointer(cRNY))
	ret := C.prc_verify_lp(unsafe.Pointer(&proof[0]), cSnX, cSnY, C.ulong(totalRep), cRepX, cRepY, cBlockHash,
		C.int(sl), cRNX, cRNY, C.ulong(avgRep))
	if ret {
		return true
	} else {
		return false
	}
}

//Identity update Proof param gen
func ParamGenIUP(d int, w int) {
	C.prc_paramgen_iup(C.int(d), C.int(w))
}

// prove identity update
func ProveIUP(d int, idAddress uint64, idLeafX string, idLeafY string, idRootX string, idRootY string, idPath []string,
	repAddress uint64, repLeafX string, repLeafY string, repRootX string, repRootY string, repPath []string,
	idM uint64, idR uint64, idCommX string, idCommY string, repM uint64, repR uint64, repCommX string, repCommY string, w int) [312]byte {
	var proof_buf [312]byte
	cIdLeafX := C.CString(idLeafX)
	cIdLeafY := C.CString(idLeafY)
	cRepLeafX := C.CString(repLeafX)
	cRepLeafY := C.CString(repLeafY)
	cIdRootX := C.CString(idRootX)
	cIdRootY := C.CString(idRootY)
	cRepRootX := C.CString(repRootX)
	cRepRootY := C.CString(repRootY)
	cIdCommX := C.CString(idCommX)
	cIdCommY := C.CString(idCommY)
	cRepCommX := C.CString(repCommX)
	cRepCommY := C.CString(repCommY)
	defer C.free(unsafe.Pointer(cIdLeafX))
	defer C.free(unsafe.Pointer(cIdLeafY))
	defer C.free(unsafe.Pointer(cRepLeafX))
	defer C.free(unsafe.Pointer(cRepLeafY))
	defer C.free(unsafe.Pointer(cIdRootX))
	defer C.free(unsafe.Pointer(cIdRootY))
	defer C.free(unsafe.Pointer(cRepRootX))
	defer C.free(unsafe.Pointer(cRepRootY))
	defer C.free(unsafe.Pointer(cIdCommX))
	defer C.free(unsafe.Pointer(cIdCommY))
	defer C.free(unsafe.Pointer(cRepCommX))
	defer C.free(unsafe.Pointer(cRepCommY))

	cIdPath := make([]*C.char, d*2)
	cRepPath := make([]*C.char, d*2)
	for i := 0; i < d*2; i++ {
		cIdPath[i] = C.CString(idPath[i])
		defer C.free(unsafe.Pointer(cIdPath[i]))
		cRepPath[i] = C.CString(repPath[i])
		defer C.free(unsafe.Pointer(cRepPath[i]))
	}

	C.prc_prove_iup(unsafe.Pointer(&proof_buf[0]), C.int(d),
		C.ulong(idAddress), cIdLeafX, cIdLeafY, cIdRootX, cIdRootY, &cIdPath[0],
		C.ulong(repAddress), cRepLeafX, cRepLeafY, cRepRootX, cRepRootY, &cRepPath[0],
		C.ulong(idM), C.ulong(idR), cIdCommX, cIdCommY, C.ulong(repM), C.ulong(repR), cRepCommX, cRepCommY, C.int(w))
	return proof_buf
}

// verify identity update
func VerifyIUP(proof [312]byte, oldIdRootX string, oldIdRootY string, oldRepRootX string, oldRepRootY string,
	newIdX string, newIdY string, newRepX string, newRepY string, w int) bool {
	cOldIdRootX := C.CString(oldIdRootX)
	cOldIdRootY := C.CString(oldIdRootY)
	cOldRepRootX := C.CString(oldRepRootX)
	cOldRepRootY := C.CString(oldRepRootY)
	cNewIdX := C.CString(newIdX)
	cNewIdY := C.CString(newIdY)
	cNewRepX := C.CString(newRepX)
	cNewRepY := C.CString(newRepY)
	defer C.free(unsafe.Pointer(cOldIdRootX))
	defer C.free(unsafe.Pointer(cOldIdRootY))
	defer C.free(unsafe.Pointer(cOldRepRootX))
	defer C.free(unsafe.Pointer(cOldRepRootY))
	defer C.free(unsafe.Pointer(cNewIdX))
	defer C.free(unsafe.Pointer(cNewIdY))
	defer C.free(unsafe.Pointer(cNewRepX))
	defer C.free(unsafe.Pointer(cNewRepY))
	ret := C.prc_verify_iup(unsafe.Pointer(&proof[0]), cOldIdRootX, cOldIdRootY, cOldRepRootX, cOldRepRootY,
		cNewIdX, cNewIdY, cNewRepX, cNewRepY, C.int(w))
	if ret {
		return true
	} else {
		return false
	}
}

/*
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
