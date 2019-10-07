package snark

import (
	"fmt"
	"testing"
)

func TestProveHPC(t *testing.T) {
	Init()
	x := make([]byte, 100)
	y := make([]byte, 100)
	var lenX int
	var lenY int
	proof_buf := ProveHPC(1, 1, x, &lenX, y, &lenY)
	fmt.Println(lenX)
	fmt.Println(lenY)
	fmt.Println(string(x[0:lenX]))
	fmt.Println(string(y[0:lenY]))
	fmt.Print(proof_buf)
}
