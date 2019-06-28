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

type PaillierPrivateKey struct {
	Lambda C.mpz_t
	X      C.mpz_t
}

type PaillierPublicKek struct {
	Bits      int32   /* e.g., 1024 */
	N         C.mpz_t /* public modulus n = p q */
	N_squared C.mpz_t /* cached to avoid recomputing */
	N_plusone C.mpz_t /* cached to avoid recomputing */
}

type PaillierKeys struct {
	Pub_key    PaillierPublicKek
	Prv_key    PaillierPrivateKey
	Modulubits int32
}
type HEScore struct {
	Stat  byte // HE add or have been HE mul once
	Score uint32
}

func (p *PaillierPrivateKey) unpack(c_PaillierPriKey *C.paillier_prvkey_t) {
	p.Lambda = (*c_PaillierPriKey).lambda
	p.X = (*c_PaillierPriKey).x
}

func (p *PaillierPrivateKey) pack(c_PaillierPriKey *C.paillier_prvkey_t) {
	c_PaillierPriKey.lambda = p.Lambda
	c_PaillierPriKey.x = p.X
}

func (p *PaillierPublicKek) unpack(c_PaillierPubKey *C.paillier_pubkey_t) {
	p.Bits = int32((*c_PaillierPubKey).bits)
	p.N = (*c_PaillierPubKey).n
	p.N_squared = (*c_PaillierPubKey).n_squared
	p.N_plusone = (*c_PaillierPubKey).n_plusone
}

func (p *PaillierPublicKek) pack(c_PaillierPubKey *C.paillier_pubkey_t) {
	c_PaillierPubKey.bits = C.int(p.Bits)
	c_PaillierPubKey.n = p.N
	c_PaillierPubKey.n_squared = p.N_squared
	c_PaillierPubKey.n_plusone = p.N_plusone
}

func (pk *PaillierKeys) unpack(c_PaillierKeys *C.paillier_keys) {
	pk.Pub_key.unpack(c_PaillierKeys.pubkey)
	pk.Prv_key.unpack(c_PaillierKeys.prvkey)
	pk.Modulubits = int32((*c_PaillierKeys).modulubits)
}

func (pk *PaillierKeys) pack(c_PaillierKeys *C.paillier_keys) {
	pub_key := (*C.paillier_pubkey_t)(C.malloc(C.size_t(unsafe.Sizeof(C.paillier_pubkey_t{}))))
	pri_key := (*C.paillier_prvkey_t)(C.malloc(C.size_t(unsafe.Sizeof(C.paillier_prvkey_t{}))))
	pk.Pub_key.pack(pub_key)
	pk.Prv_key.pack(pri_key)
	c_PaillierKeys.pubkey = pub_key
	c_PaillierKeys.prvkey = pri_key
	c_PaillierKeys.modulubits = C.int(pk.Modulubits)
}

func (p *PaillierKeys) NewHEKey(role byte) {
	if role == 0 {
		keys := (*C.paillier_keys)(C.malloc(C.size_t(unsafe.Sizeof(C.paillier_keys{}))))
		defer C.free(unsafe.Pointer(keys))
		C.keygen(keys)
		p.unpack(keys)
	}
}

func (h *HEScore) NewHEScore(s [32]byte) {

}

func HEMessage() {
	var message1_ul C.ulong
	var message2_ul C.ulong
	message1_ul = C.ulong(22222)
	message2_ul = C.ulong(33333)
	var new_keys PaillierKeys

	cipher := &C.paillier_ciphertext_t{}
	secret := &C.paillier_ciphertext_t{}
	result := &C.paillier_plaintext_t{}
	var temp C.mpz_t
	keys := &C.paillier_keys{}
	//temp := C.mpz_t
	C.mpz_init(&temp[0])
	fmt.Println("Initial mpz_t value:", temp[0])
	C.mpz_init(&secret.c[0])
	C.key_gen(keys)

	new_keys.unpack(keys)

	old_keys := (*C.paillier_keys)(C.malloc(C.size_t(unsafe.Sizeof(C.paillier_keys{}))))

	new_keys.pack(old_keys)

	message1 := C.paillier_plaintext_from_ui(message1_ul)
	message2 := C.paillier_plaintext_from_ui(message2_ul)
	fmt.Println("message1:", uint64(C.mpz_get_ui(&message1.m[0])))
	fmt.Println("message2:", uint64(C.mpz_get_ui(&message2.m[0])))

	/* test additive homomorphic */
	fmt.Println("Proving Additive Homomorphic")
	C.mpz_add(&temp[0], &message1.m[0], &message2.m[0])  // m1+m2
	C.mpz_mod(&temp[0], &temp[0], &old_keys.pubkey.n[0]) // m1+m2 mod n
	//C.gmp_printf("m1+m2 mod n = %Zd\n", &temp[0])
	fmt.Println(uint64(C.mpz_get_ui(&temp[0])))

	cipher = C.enc_add_circuit(old_keys.pubkey, message1, message2) // c = Enc(m1) + Enc(m2)
	result = C.dec_add_circuit(old_keys, cipher)                    // Dec(c)
	fmt.Println(uint64(C.mpz_get_ui(&result.m[0])))

	/* test multiplicative homomorphic */
	fmt.Println("Proving Multiplicative Homomorphic:")
	C.mpz_mul(&temp[0], &message1.m[0], &message2.m[0])  // m1*m2
	C.mpz_mod(&temp[0], &temp[0], &old_keys.pubkey.n[0]) // m1*m2 mod n
	fmt.Println(uint64(C.mpz_get_ui(&temp[0])))

	cipher = C.enc_mul_circuit(old_keys.pubkey, message1, message2, secret) // c = Enc(m1) + Enc(m2)
	result = C.dec_mul_circuit(old_keys, cipher, secret)                    // Dec(c)
	fmt.Println(uint64(C.mpz_get_ui(&result.m[0])))

	fmt.Println("done")
}
