package HE

// #cgo LDFLAGS:-lgmp
// #include <stdio.h>
// #include <stdlib.h>
// #include "paillier_mh.h"
import "C"
import (
	"fmt"
	"unsafe"
	//"unsafe"
)

func HEMessage() {
	message1_str := C.CString("0")
	//_, err := C.HEtest()
	message2_str := C.CString("1")
	defer C.free(unsafe.Pointer(message1_str))
	defer C.free(unsafe.Pointer(message2_str))
	keys := &C.paillier_keys{}

	//cipher := &C.paillier_ciphertext_t{}
	secret := &C.paillier_ciphertext_t{}
	//result := &C.paillier_ciphertext_t{}
	var temp C.mpz_t

	//temp := C.mpz_t
	C.mpz_init(&temp[0])
	fmt.Println("Initial mpz_t value:", temp[0])
	C.mpz_init(&secret.c[0])
	C.key_gen(keys)
	fmt.Println("Message1_str:", *message1_str)
	fmt.Println("Message2_str:", *message2_str)
	message1 := C.paillier_plaintext_from_str(message1_str)
	message2 := C.paillier_plaintext_from_str(message2_str)

	fmt.Println(message1.m[0])
	fmt.Println(message2.m[0])
	/* test additive homomorphic */
	fmt.Println("Proving Additive Homomorphic")
	C.mpz_add(&temp[0], &message1.m[0], &message2.m[0]) // m1+m2
	C.mpz_mod(&temp[0], &temp[0], &keys.pubkey.n[0])    // m1+m2 mod n
	C.gmp_printf("m1+m2 mod n \t\t= %Zd\n", &temp[0])
	fmt.Println("m1+m2 mod n ", temp)

	fmt.Println("done")
}
