package shard

import (
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestSortTyep(t *testing.T) {
	x := new(big.Int)
	y := new(big.Int)
	var ss []SortTypes
	var b [3]int
	b[0] = 0
	b[1] = 3
	b[2] = 6
	for i := 0; i < 3; i++ {
		var s []SortType
		for j := 0; j < b[i]; j++ {
			x.Rand(rand.New(rand.NewSource(time.Now().UnixNano())), big.NewInt(100))
			y.Rand(rand.New(rand.NewSource(time.Now().UnixNano())), big.NewInt(100))
			var tmp SortType
			tmp.NewSortType(i*5+j, x, y)
			s = append(s, tmp)
		}
		ss = append(ss, s)
	}
	fmt.Println(ss)
	flagi := make([]bool, 20)
	for i := 0; i < int(20); i++ {
		flagi[i] = false
	}
	lInd := 0
	var lList [20]int
	for i, slc := range ss {
		if len(slc) > 0 {
			sort.Sort(slc)
			fmt.Println(i, ":")
			fmt.Println(slc)
			for i := 0; i < len(slc); i++ {
				if !flagi[slc[i].ID] {
					lList[lInd] = slc[i].ID
					lInd++
					flagi[slc[i].ID] = true
				}
			}
		}
	}
	fmt.Println("lList:", lList)
	tempi := 0
	sg := make([][]int, 1)
	for i := uint32(0); i < 1; i++ {
		sg[i] = make([]int, 20)
		for j := uint32(0); j < 20; j++ {
			if int(j) < lInd {
				sg[i][j] = lList[j]
			} else {
				for flagi[tempi] {
					tempi++
				}
				sg[i][j] = tempi
				tempi++
			}
		}
	}
	fmt.Println(sg)
}
