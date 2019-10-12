package snark

import (
	"fmt"
	"math/big"
)

func StringToByte(x string) []byte {
	temp := new(big.Int)
	temp.SetString(x, 10)
	fmt.Println(temp)
	return temp.Bytes()
}

func PrintComm(x [32]byte) {
	temp := new(big.Int)
	temp.SetBytes(x[:])
	fmt.Println(temp)
}
