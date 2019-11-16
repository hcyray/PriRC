package snark

import (
	"math/big"
)

func StringToByte(x string, base int) []byte {
	temp := new(big.Int)
	temp.SetString(x, base)
	return temp.Bytes()
}

func BoolArrayToDec(x *uint64, y []bool, d int) {
	*x = 0
	for i := 0; i < d; i++ {
		*x = *x << 1
		if y[i] {
			*x = *x + 1
		}
	}
}
