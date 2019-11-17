package snark

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"
)

func TestPC(t *testing.T) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(1)
	b_r.SetInt64(1)
	pc := new(PedersenCommitment)
	pc.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc)
	Init()
	ParamGenHPC()
	proof_buf := ProveHPC(1, 1, pc.Comm_x.String(), pc.Comm_y.String())
	fmt.Println("verification result:", VerifyHPC(proof_buf, pc.Comm_x.String(), pc.Comm_y.String()))
}

func TestLP(t *testing.T) {
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(2)
	b_r.SetInt64(2)
	pc := new(PedersenCommitment)
	pc.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc)
	Init()
	ParamGenLP(1, 4)
	var totalRep string
	var blockHash string
	totalRep = "10"
	blockHash = "1234"
	proof_buf := ProveLP(2, 2, pc.Comm_x.String(), pc.Comm_y.String(), totalRep,
		2, 2, pc.Comm_x.String(), pc.Comm_y.String(), blockHash, 1, 1, 4)
	fmt.Println("verification result:", VerifyLP(proof_buf, pc.Comm_x.String(), pc.Comm_y.String(),
		totalRep, pc.Comm_x.String(), pc.Comm_y.String(), blockHash, 1))
}

func TestIUP(t *testing.T) {
	file, _ := os.Open("merkle.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanWords)
	var d int
	var idAdd uint64
	var repAdd uint64
	scanner.Scan()
	d, _ = strconv.Atoi(scanner.Text())
	idAddBit := make([]bool, d)
	for i := 0; i < d; i++ {
		scanner.Scan()
		temp, _ := strconv.Atoi(scanner.Text())
		if temp == 1 {
			idAddBit[i] = true
		} else {
			idAddBit[i] = false
		}
	}
	BoolArrayToDec(&idAdd, idAddBit, d)
	repAdd = idAdd
	idPath := make([]string, d*2)
	repPath := make([]string, d*2)
	for i := 0; i < d*2; i++ {
		scanner.Scan()
		idPath[i] = scanner.Text()
		repPath[i] = idPath[i]
	}
	scanner.Scan()
	idLeafX := scanner.Text()
	repLeafX := idLeafX
	scanner.Scan()
	idLeafY := scanner.Text()
	repLeafY := idLeafY
	scanner.Scan()
	idRootX := scanner.Text()
	repRootX := idRootX
	scanner.Scan()
	idRootY := scanner.Text()
	repRootY := idRootY

	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(2)
	b_r.SetInt64(2)
	pc1 := new(PedersenCommitment)
	pc1.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc1)
	pc2 := new(PedersenCommitment)
	pc2.Init()
	BabyJubJubCurve.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc2)
	Init()
	ParamGenIUP(d)
	proof_buf := ProveIUP(d, idAdd, idLeafX, idLeafY, idRootX, idRootY, idPath,
		repAdd, repLeafX, repLeafY, repRootX, repRootY, repPath, 2, 2, pc1.Comm_x.String(), pc1.Comm_y.String(),
		2, 2, pc2.Comm_x.String(), pc2.Comm_y.String())
	fmt.Println("Ok")
	fmt.Println("verification result:", VerifyIUP(proof_buf, idRootX, idRootY, repRootX, repRootY,
		pc1.Comm_x.String(), pc1.Comm_y.String(), pc2.Comm_x.String(), pc2.Comm_y.String()))
}

func TestPedersenCommitment(t *testing.T) {
	BabyJubJubCurve.Init()
	b_m := new(big.Int)
	b_r := new(big.Int)
	b_m.SetInt64(1)
	b_r.SetInt64(0)
	pc1 := new(PedersenCommitment)
	pc1.Init()
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc1)
	pc1.PrintPC()
	pc2 := new(PedersenCommitment)
	pc2.Init()
	b_m.SetInt64(1)
	b_r.SetInt64(0)
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc2)
	BabyJubJubCurve.AddTwoPedersenCommitment(pc1, pc2)
	pc1.PrintPC()
	b_m.SetInt64(0)
	b_r.SetInt64(0)
	BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, pc2)
	pc2.PrintPC()
}
func TestPedersenHash(t *testing.T) {
	BabyJubJubCurve.Init()
	pc1 := new(PedersenCommitment)
	pc1.Init()
	pc1.Comm_x.SetString("0", 10)
	pc1.Comm_y.SetString("1", 10)
	pc2 := new(PedersenCommitment)
	pc2.Init()
	pc2.Comm_x.SetString("17777552123799933955779906779655732241715742912184938656739573121738514868268", 10)
	pc2.Comm_y.SetString("2626589144620713026669568689430873010625803728049924121243784502389097019475", 10)
	BabyJubJubCurve.AddTwoPedersenCommitment(pc1, pc2)
	pc1.PrintPC()
	BabyJubJubCurve.CalPedersenHash(pc1.Comm_x, pc1.Comm_y, pc1)
	pc1.PrintPC()
}
func TestMerkleTree(t *testing.T) {
	BabyJubJubCurve.Init()
	n := 3
	b_m := new(big.Int)
	b_r := new(big.Int)
	pc := make([]PedersenCommitment, n)
	for i := 0; i < n; i++ {
		pc[i].Init()
		b_m.SetInt64(int64(i))
		b_r.SetInt64(0)
		BabyJubJubCurve.CalPedersenCommitment(b_m, b_r, &pc[i])
	}
	var mt MerkleTree
	mt.Init(pc)
	//mt.Print()
	p := mt.Proof(1)
	p.PrintToTxT()
}
