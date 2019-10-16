package snark

import (
	"math/big"
)

func StringToByte(x string, base int) []byte {
	temp := new(big.Int)
	temp.SetString(x, base)
	return temp.Bytes()
}
