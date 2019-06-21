package HE

// #cgo CFLAGS: -g -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lgmp
// #include <stdio.h>
// #include <stdlib.h>
// #include "HEtest.h"
import "C"
import (
	"fmt"
	//"unsafe"
)

func HEMessage() {
	//message1 := C.CString("0")
	_, err := C.HEtest()
	//message2 := C.CString("1")
	//defer C.free(unsafe.Pointer(message1))
	//defer C.free(unsafe.Pointer(message2))
	//keys := C.malloc(C.sizeof(C.paillier_plaintext_t))
	//defer C.free(unsafe.Pointer(keys))
	//C.key_gen(keys)
	if err != nil {
		fmt.Println("error")
	}
	fmt.Println("done")
}
