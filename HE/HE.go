package HE

// #cgo LDFLAGS:-lgmp
// #include <stdio.h>
// #include <stdlib.h>
// #include "paillier_mh.h"
import "C"
import (
	"fmt"
	//"unsafe"
)

func HEMessage() {
	var message1_str C.ulong
	var message2_str C.ulong
	message1_str = C.ulong(2)
	message2_str = C.ulong(3)
	keys := &C.paillier_keys{}

	cipher := &C.paillier_ciphertext_t{}
	secret := &C.paillier_ciphertext_t{}
	result := &C.paillier_plaintext_t{}
	var temp C.mpz_t
	var temp1 C.mpz_t

	//temp := C.mpz_t
	C.mpz_init(&temp[0])
	C.mpz_init(&temp1[0])
	fmt.Println("Initial mpz_t value:", temp[0])
	C.mpz_init(&secret.c[0])
	C.key_gen(keys)
	fmt.Println("Message1_str:", message1_str)
	fmt.Println("Message2_str:", message2_str)

	message1 := C.paillier_plaintext_from_ui(message1_str)
	message2 := C.paillier_plaintext_from_ui(message2_str)
	fmt.Println(message1.m[0])
	fmt.Println(message2.m[:])
	/* test additive homomorphic */
	fmt.Println("Proving Additive Homomorphic")
	C.mpz_add(&temp[0], &message1.m[0], &message2.m[0]) // m1+m2
	C.mpz_mod(&temp[0], &temp[0], &keys.pubkey.n[0])    // m1+m2 mod n
	C.mpz_set_ui(&temp1[0], C.ulong(5))
	//C.gmp_printf("m1+m2 mod n = %Zd\n", &temp[0])
	r := int(C.mpz_cmp(&temp1[0], &temp[0]))
	fmt.Println(r)

	cipher = C.enc_add_circuit(keys.pubkey, message1, message2) // c = Enc(m1) + Enc(m2)
	result = C.dec_add_circuit(keys, cipher)                    // Dec(c)
	fmt.Println(result.m)

	/* test multiplicative homomorphic */
	fmt.Println("Proving Multiplicative Homomorphic:")
	C.mpz_mul(&temp[0], &message1.m[0], &message2.m[0]) // m1*m2
	C.mpz_mod(&temp[0], &temp[0], &keys.pubkey.n[0])    // m1*m2 mod n
	C.mpz_set_ui(&temp1[0], C.ulong(6))
	r = int(C.mpz_cmp(&temp1[0], &temp[0]))
	fmt.Println(r)

	cipher = C.enc_mul_circuit(keys.pubkey, message1, message2, secret) // c = Enc(m1) + Enc(m2)
	result = C.dec_mul_circuit(keys, cipher, secret)                    // Dec(c)
	fmt.Println(result.m)

	fmt.Println("done")
}
