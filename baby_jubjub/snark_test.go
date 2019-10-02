package snark

import (
	"fmt"
	"testing"
)

func TestProveHPC(t *testing.T) {
	Init()
	var x string
	var y string
	var lenX int
	var lenY int
	proof_buf := ProveHPC(1, 1, x, lenX, y, lenY)
	fmt.Print(proof_buf)
}
