package snark

import (
	"fmt"
)

//Merkle Tree
type MerkleTree struct {
	Depth int
	N     int
	Root  *MerkleNode
}

// Merkle Node
type MerkleNode struct {
	//Parent	*MerkleNode
	LChild *MerkleNode
	RChild *MerkleNode
	PC     *PedersenCommitment
	IsLeaf bool
}

//used for merkle proof
type MerkleProof struct {
	PathVar   []string
	AdressBit []bool
	Leaf_x    string
	Leaf_y    string
	Root_x    string
	Root_y    string
	Depth     int
}

// build a Merkle Tree from PedersenCommitments
func (m *MerkleTree) Init(pcs []PedersenCommitment) {
	n := len(pcs)
	ns := make([]MerkleNode, n)
	for i := 0; i < n; i++ {
		p := MerkleNode{nil, nil, &(pcs[i]), true}
		ns[i] = p
	}
	m.N = n
	m.build(&ns, 0)
}

// recursively build a tree
func (m *MerkleTree) build(ns *[]MerkleNode, d int) {
	n := len(*ns)

	if n == 1 {
		m.Depth = d + 1
		m.Root = &((*ns)[0])
		return
	} else {
		var new_ns []MerkleNode
		for i := 0; i < n; i = i + 2 {
			pc1 := new(PedersenCommitment)
			pc1.Init()
			pc1.Comm_x.SetString((*ns)[i].PC.Comm_x.String(), 10)
			pc1.Comm_y.SetString((*ns)[i].PC.Comm_y.String(), 10)

			if i+1 < n {
				pc2 := new(PedersenCommitment)
				pc2.Init()
				pc2.Comm_x.SetString((*ns)[i+1].PC.Comm_x.String(), 10)
				pc2.Comm_y.SetString((*ns)[i+1].PC.Comm_y.String(), 10)
				BabyJubJubCurve.AddTwoPedersenCommitment(pc1, pc2)
			}
			BabyJubJubCurve.CalPedersenHash(pc1.Comm_x, pc1.Comm_y, pc1)

			//pc1.PrintPC()
			p := MerkleNode{nil, nil, pc1, false}
			//(*ns)[i].Parent = &p
			p.LChild = &((*ns)[i])
			if i+1 < n {
				//(*ns)[i+1].Parent = &p
				p.RChild = &((*ns)[i+1])
			}
			new_ns = append(new_ns, p)
		}
		m.build(&new_ns, d+1)
	}
}

//return merkle proof
func (m *MerkleTree) Proof(x int) MerkleProof {
	mp := MerkleProof{}
	mp.Depth = m.Depth - 1
	mp.Root_x = m.Root.PC.Comm_x.String()
	mp.Root_y = m.Root.PC.Comm_y.String()
	mp.AdressBit = make([]bool, m.Depth-1)
	for i := m.Depth - 2; i >= 0; i-- {
		mp.AdressBit[i] = x%2 == 1
		x = x / 2
	}
	fmt.Println(mp.AdressBit)
	root := m.Root
	mp.PathVar = make([]string, (m.Depth-1)*2)
	for i := m.Depth - 2; i >= 0; i-- {
		if !mp.AdressBit[i] {
			mp.PathVar[i*2] = root.RChild.PC.Comm_x.String()
			mp.PathVar[i*2+1] = root.RChild.PC.Comm_y.String()
			root = root.LChild
		} else {
			mp.PathVar[i*2] = root.LChild.PC.Comm_x.String()
			mp.PathVar[i*2+1] = root.LChild.PC.Comm_y.String()
			root = root.RChild
		}
	}
	mp.Leaf_x = root.PC.Comm_x.String()
	mp.Leaf_y = root.PC.Comm_y.String()
	return mp
}

// Print the Merkle Tree in
func (m *MerkleTree) Print() {
	a := make([][]*MerkleNode, m.Depth)
	for i := 0; i < m.Depth; i++ {
		a[i] = make([]*MerkleNode, 0)
	}
	//a[m.Depth-1][0] = m.Root
	m.printLayer(m.Root, &a, m.Depth-1)
	for i := 0; i < m.Depth; i++ {
		fmt.Println("Layer: ", i)
		for j := 0; j < len(a[i]); j++ {
			a[i][j].PC.PrintPC()
		}
	}
	fmt.Println("Merkle Tree finished")
}

// add node to different layer stack for printing
func (m *MerkleTree) printLayer(p *MerkleNode, a *[][]*MerkleNode, d int) {
	(*a)[d] = append((*a)[d], p)
	if p.LChild != nil {
		m.printLayer(p.LChild, a, d-1)
	}
	if p.RChild != nil {
		m.printLayer(p.RChild, a, d-1)
	}
}

// print proof
func (p *MerkleProof) AddressBitToAdd() uint64 {
	x := uint64(0)
	for _, b := range p.AdressBit {
		x = x << 1
		if b {
			x++
		}
	}
	return x
}

// print proof
func (p *MerkleProof) Print() {
	fmt.Println("address bit:", p.AdressBit)
	fmt.Println("path var:")
	for i := 0; i < p.Depth; i++ {
		fmt.Println("comm x:", p.PathVar[i*2])
		fmt.Println("comm y:", p.PathVar[i*2+1])
	}
	fmt.Println("Leaf:")
	fmt.Println(p.Leaf_x)
	fmt.Println(p.Leaf_y)

	fmt.Println("root:")
	fmt.Println(p.Root_x)
	fmt.Println(p.Root_y)
}

func (p *MerkleProof) PrintToTxT() {
	fmt.Println(p.Depth)
	for i := 0; i < p.Depth; i++ {
		if p.AdressBit[i] {
			fmt.Println(1)
		} else {
			fmt.Println(0)
		}
	}
	for i := 0; i < p.Depth; i++ {
		fmt.Println(p.PathVar[i*2])
		fmt.Println(p.PathVar[i*2+1])
	}
	fmt.Println(p.Leaf_x)
	fmt.Println(p.Leaf_y)
	fmt.Println(p.Root_x)
	fmt.Println(p.Root_y)
}

func (m *MerkleNode) InitLeaf(pc *PedersenCommitment) {
	m.PC = pc
	m.IsLeaf = true
	m.LChild = nil
	m.RChild = nil
}
