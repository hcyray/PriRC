package rccache

import (
	"fmt"
	"log"
	"strconv"

	"github.com/uchihatmtkinu/RC/gVar"

	"github.com/boltdb/bolt"
	"github.com/uchihatmtkinu/RC/basic"
)

//TxBlockChain is the blockchain database
type TxBlockChain struct {
	data    *bolt.DB
	LastTB  [32]byte
	Height  uint32
	LastFB  [gVar.ShardCnt][32]byte
	USet    map[[32]byte]UTXOSet
	TXCache map[[32]byte]int
	//AccData  *gtreap.Treap
	AccData  map[[32]byte]uint32
	FileName string
}

//NewBlockchain is to init the total chain
func (a *TxBlockChain) NewBlockchain(dbFile string) error {
	var err error
	a.FileName = dbFile
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		return err
	}
	defer a.data.Close()
	a.TXCache = make(map[[32]byte]int, 10000)
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TBBucket))
		if b == nil {
			genesis := basic.NewGensisTxBlock()
			b, err := tx.CreateBucket([]byte(TBBucket))
			var tmp []byte
			genesis.Encode(&tmp, 1)
			if err != nil {
				return nil
			}
			err = b.Put(append([]byte("B"), genesis.HashID[:]...), tmp)
			err = b.Put([]byte("XB"), genesis.HashID[:])
			a.LastTB = genesis.HashID
			a.Height = 0
		} else {
			copy(a.LastTB[:], b.Get([]byte("XB"))[:32])
			tmpByte := b.Get(append([]byte("B"), a.LastTB[:]...))
			var tmp basic.TxBlock
			tmp.Decode(&tmpByte, 1)
			a.Height = tmp.Height
		}
		b = tx.Bucket([]byte(FBBucket))
		if b == nil {
			b, err := tx.CreateBucket([]byte(FBBucket))
			if err != nil {
				return err
			}
			for i := uint32(0); i < gVar.ShardCnt; i++ {
				genesis := basic.NewGensisFinalTxBlock(i)
				var tmp []byte
				genesis.Encode(&tmp, 1)
				err = b.Put(append([]byte("B"+strconv.Itoa(int(i))), genesis.HashID[:]...), tmp)
				err = b.Put([]byte("XB"+strconv.Itoa(int(i))), genesis.HashID[:])
				a.LastFB[i] = genesis.HashID
			}

		} else {
			for i := uint32(0); i < gVar.ShardCnt; i++ {
				copy(a.LastFB[i][:], b.Get([]byte("XB" + strconv.Itoa(int(i))))[:32])
			}
		}
		b = tx.Bucket([]byte(ACCBucket))
		//a.AccData = gtreap.NewTreap(byteCompare)
		a.AccData = make(map[[32]byte]uint32, 1000)
		if b == nil {
			_, err := tx.CreateBucket([]byte(ACCBucket))
			if err != nil {
				log.Panic(err)
			}
		} else {
			c := b.Cursor()
			var tmp *basic.AccCache
			for k, v := c.First(); k != nil; k, v = c.Next() {
				tmp = new(basic.AccCache)
				copy(tmp.ID[:], k[:32])
				tmpStr := v
				basic.DecodeInt(&tmpStr, &tmp.Value)
				//a.AccData = a.AccData.Upsert(tmp, rand.Int())
				a.AccData[tmp.ID] = tmp.Value
			}
		}
		b = tx.Bucket([]byte(UTXOBucket))
		if b == nil {
			_, err := tx.CreateBucket([]byte(UTXOBucket))
			if err != nil {
				log.Panic(err)
			}
		}
		return nil
	})
	return err
}

//AddBlock is adding a new txblock
func (a *TxBlockChain) AddBlock(x *basic.TxBlock) error {
	var err error
	if x.Kind == 0 {
		return fmt.Errorf("Error type, should be 0")
	}
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TBBucket))
		err := b.Put(append([]byte("B"), x.HashID[:]...), x.Serial())
		if err != nil {
			return err
		}
		err = b.Put([]byte("XB"), x.HashID[:])
		if err != nil {
			return err
		}
		if x.Height > a.Height {
			a.LastTB = x.HashID
			a.Height = x.Height
		}

		return nil
	})
	return nil
}

//AddFinalBlock is adding a new txblock
func (a *TxBlockChain) AddFinalBlock(x *basic.TxBlock) error {
	if x.Kind != 1 {
		return fmt.Errorf("Error block type, should be 1")
	}
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(FBBucket))
		err := b.Put(append([]byte("B"+strconv.Itoa(int(x.ShardID))), x.HashID[:]...), x.Serial())
		if err != nil {
			return err
		}
		err = b.Put([]byte("XB"+strconv.Itoa(int(x.ShardID))), x.HashID[:])
		if err != nil {
			return err
		}
		a.LastFB[x.ShardID] = x.HashID
		b = tx.Bucket([]byte(ACCBucket))
		for i := uint32(0); i < x.TxCnt; i++ {
			var tmp []byte
			basic.EncodeInt(&tmp, x.TxArray[i].Out[0].Value)
			b.Put(x.TxArray[i].Out[0].Address[:], tmp)
		}
		return nil
	})
	return nil
}

//AddStartBlock is adding a new txblock
func (a *TxBlockChain) AddStartBlock(x *basic.TxBlock) error {
	if x.Kind != 2 {
		return fmt.Errorf("Error block type, should be 1")
	}
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TBBucket))
		err := b.Put(append([]byte("B"), x.HashID[:]...), x.Serial())
		if err != nil {
			return err
		}
		err = b.Put([]byte("XB"), x.HashID[:])
		if err != nil {
			return err
		}
		if x.Height > a.Height {
			a.LastTB = x.HashID
			a.Height = x.Height
		}

		return nil
	})
	return nil
}

//LatestTxBlock return the highest txblock
func (a *TxBlockChain) LatestTxBlock() *basic.TxBlock {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	var tmpStr []byte
	err = a.data.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TBBucket))
		tmpStr = b.Get(append([]byte("B"), a.LastTB[:]...))

		return nil
	})
	var tmp basic.TxBlock
	err = tmp.Decode(&tmpStr, 1)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return &tmp
}

//LatestFinalTxBlock return the highest txblock
func (a *TxBlockChain) LatestFinalTxBlock(x uint32) *basic.TxBlock {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	var tmpStr []byte
	err = a.data.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(FBBucket))
		tmpStr = b.Get(append([]byte("B"+strconv.Itoa(int(x))), a.LastFB[x][:]...))
		return nil
	})
	var tmp basic.TxBlock
	err = tmp.Decode(&tmpStr, 1)
	if err != nil {
		return nil
	}
	return &tmp
}

//AddAccount is adding a new account or update
func (a *TxBlockChain) AddAccount(x *basic.AccCache) error {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(ACCBucket))
		if x.Value == 0 {
			delete(a.AccData, x.ID)
			err := b.Delete(x.ID[:])
			return err
		}
		var tmp []byte
		basic.EncodeInt(&tmp, x.Value)
		a.AccData[x.ID] = x.Value
		err := b.Put(x.ID[:], tmp)
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

//CheckUTXO is to check whether the utxo is available
func (a *TxBlockChain) CheckUTXO(x *basic.InType, h [32]byte) bool {
	if x.Acc() {
		tmp := a.AccData[x.PrevTx]
		return tmp >= x.Index
	}
	tmp, ok := a.USet[x.PrevTx]
	res := false
	if !ok {
		var err error
		a.data, err = bolt.Open(a.FileName, 0600, nil)
		if err != nil {
			log.Panic(err)
		}
		defer a.data.Close()
		err = a.data.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(UTXOBucket))
			tmpStr := b.Get(x.PrevTx[:])
			if tmpStr == nil {
				return nil
			}
			res = true
			var xxx UTXOSet
			err = xxx.Decode(&tmpStr)
			if err != nil {
				return fmt.Errorf("Decoding error")
			}
			xxx.viewer = 0
			tmp = xxx
			return nil
		})
		if !res {
			return false
		}
		if x.Index >= tmp.Cnt {
			return false
		}
		a.USet[x.PrevTx] = tmp
	}
	if x.Index >= tmp.Cnt {
		return false
	}
	if tmp.Stat[x.Index] != 0 {
		return false
	}
	return x.VerifyIn(&tmp.Data[x.Index], h)
}

//LockUTXO is to lock the value
func (a *TxBlockChain) LockUTXO(x *basic.InType) error {
	if x.Acc() {
		//tmp := a.FindAcc(x.PrevTx)
		//tmp.Value -= x.Index
		a.AccData[x.PrevTx] -= x.Index
	} else {
		tmp, ok := a.USet[x.PrevTx]
		if !ok || x.Index >= tmp.Cnt || tmp.Stat[x.Index] != 0 {
			return fmt.Errorf("Locking utxo failed")
		}
		tmp.Stat[x.Index] = 2
		tmp.viewer++
		a.USet[x.PrevTx] = tmp
	}
	return nil
}

//UnlockUTXO is to lock the value
func (a *TxBlockChain) UnlockUTXO(x *basic.InType) error {
	if x.Acc() {
		//tmp := a.FindAcc(x.PrevTx)
		//tmp.Value += x.Index
		a.AccData[x.PrevTx] += x.Index
	} else {
		tmp, ok := a.USet[x.PrevTx]
		if !ok || x.Index >= tmp.Cnt || tmp.Stat[x.Index] != 2 {
			return fmt.Errorf("Unlocking utxo failed")
		}
		tmp.Stat[x.Index] = 0
		tmp.viewer--
		if tmp.viewer == 0 {
			err := a.data.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(UTXOBucket))
				b.Put(x.PrevTx[:], tmp.Encode())
				return nil
			})
			if err != nil {
				return err
			}
			delete(a.USet, x.PrevTx)
		} else {
			a.USet[x.PrevTx] = tmp
		}
	}
	return nil
}

//MakeFinalTx generates the final blocks transactions
func (a *TxBlockChain) MakeFinalTx() *[]basic.Transaction {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	res := make([]basic.Transaction, 0, 10000)
	tmpMap := make(map[[32]byte]uint32)
	for k, v := range a.AccData {
		var tmpTx basic.Transaction
		tmpIn := basic.InType{PrevTx: k, Index: v}
		var tmpOut basic.OutType
		tmpOut.Value = v
		tmpOut.Address = k
		tmpTx.New(1)
		tmpTx.AddIn(tmpIn)
		tmpTx.AddOut(tmpOut)
		res = append(res, tmpTx)
		tmpMap[tmpOut.Address] = uint32(len(res) - 1)
	}

	err = a.data.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(UTXOBucket))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			tmp := new(UTXOSet)
			tmpStr := v
			var tmpHash [32]byte
			copy(tmpHash[:], k[:32])
			err := tmp.Decode(&tmpStr)
			if err != nil {
				continue
			}
			for i := uint32(0); i < tmp.Cnt; i++ {
				if tmp.Stat[i] == 0 {
					tmpID, ok := tmpMap[tmp.Data[i].Address]
					if ok {
						tmpIn := basic.InType{PrevTx: tmpHash, Index: i}
						res[tmpID].AddIn(tmpIn)
						res[tmpID].Out[0].Value += tmp.Data[i].Value
					} else {
						var tmpTx basic.Transaction
						tmpIn := basic.InType{PrevTx: tmpHash, Index: i}
						var tmpOut basic.OutType
						tmpOut.Value = tmp.Data[i].Value
						tmpOut.Address = tmp.Data[i].Address
						tmpTx.New(1)
						tmpTx.AddIn(tmpIn)
						tmpTx.AddOut(tmpOut)
						res = append(res, tmpTx)
						tmpMap[tmp.Data[i].Address] = uint32(len(res) - 1)
					}
				}
			}
		}
		return nil
	})
	return &res
}

//UpdateFinal is to update the final block
func (a *TxBlockChain) UpdateFinal(x *basic.TxBlock) error {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	for i := uint32(0); i < x.TxCnt; i++ {
		a.AccData[x.TxArray[i].Out[0].Address] = x.TxArray[i].Out[0].Value
	}

	err = a.data.Update(func(tx *bolt.Tx) error {
		tx.DeleteBucket([]byte(UTXOBucket))
		tx.CreateBucket([]byte(UTXOBucket))
		b := tx.Bucket([]byte(ACCBucket))
		for k, v := range a.AccData {
			if v == 0 {
				b.Delete(k[:])
			} else {
				var tmp []byte
				basic.EncodeInt(&tmp, v)
				b.Put(k[:], tmp)
			}
		}
		return nil
	})
	return err
}

//UploadAcc is to upload the account data from database
func (a *TxBlockChain) UploadAcc(shardID uint32) error {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	a.AccData = make(map[[32]byte]uint32, 10000)
	err = a.data.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(ACCBucket))
		c := b.Cursor()
		var tmp *basic.AccCache
		for k, v := c.First(); k != nil; k, v = c.Next() {
			tmp = new(basic.AccCache)
			copy(tmp.ID[:], k[:32])
			tmpStr := v
			if basic.ShardIndex(tmp.ID) == shardID {
				basic.DecodeInt(&tmpStr, &tmp.Value)
				//a.AccData = a.AccData.Upsert(tmp, rand.Int())
				a.AccData[tmp.ID] = tmp.Value
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

//UpdateAccount save the current account data into database
func (a *TxBlockChain) UpdateAccount() error {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(ACCBucket))
		for k, v := range a.AccData {
			if v == 0 {
				b.Delete(k[:])
			} else {
				var tmp []byte
				basic.EncodeInt(&tmp, v)
				b.Put(k[:], tmp)
			}
		}
		return nil
	})
	return err
}

//ShowAccount prints all account information
func (a *TxBlockChain) ShowAccount() error {
	for k, v := range a.AccData {
		fmt.Println(k, ": ", v)
		fmt.Println(basic.ShardIndex(k))
	}
	return nil
}

//UpdateUTXO is to update utxo set
func (a *TxBlockChain) UpdateUTXO(x *basic.TxBlock, shardindex uint32) error {
	var err error
	a.data, err = bolt.Open(a.FileName, 0600, nil)
	if err != nil {
		log.Panic(err)
	}
	defer a.data.Close()
	err = a.data.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(UTXOBucket))
		for i := uint32(0); i < x.TxCnt; i++ {
			_, oktx := a.TXCache[x.TxArray[i].Hash]
			for j := uint32(0); j < x.TxArray[i].TxinCnt; j++ {
				if x.TxArray[i].In[j].ShardIndex() == shardindex {
					if x.TxArray[i].In[j].Acc() {
						_, ok := a.AccData[x.TxArray[i].In[j].PrevTx]
						if ok && !oktx {
							a.AccData[x.TxArray[i].In[j].PrevTx] -= x.TxArray[i].In[j].Index
						}
					} else {
						tmp, ok := a.USet[x.TxArray[i].In[j].PrevTx]
						if ok {
							if tmp.Stat[x.TxArray[i].In[j].Index] != 1 {
								tmp.Stat[x.TxArray[i].In[j].Index] = 1
								tmp.Remain--
								tmp.viewer--
								if tmp.Remain == 0 {
									delete(a.USet, x.TxArray[i].In[j].PrevTx)
									b.Delete(x.TxArray[i].In[j].PrevTx[:])
								} else {
									if tmp.viewer == 0 {
										delete(a.USet, x.TxArray[i].In[j].PrevTx)
										b.Put(x.TxArray[i].In[j].PrevTx[:], tmp.Encode())
									} else {
										b.Put(x.TxArray[i].In[j].PrevTx[:], tmp.Encode())
										a.USet[x.TxArray[i].In[j].PrevTx] = tmp
									}
								}
							}
						} else {
							tmpStr := b.Get(x.TxArray[i].In[j].PrevTx[:])
							err := tmp.Decode(&tmpStr)
							if err == nil && tmp.Stat[x.TxArray[i].In[j].Index] != 1 {
								tmp.Stat[x.TxArray[i].In[j].Index] = 1
								tmp.Remain--
								if tmp.Remain == 0 {
									b.Delete(x.TxArray[i].In[j].PrevTx[:])
								} else {
									tmpStr = tmp.Encode()
									b.Put(x.TxArray[i].In[j].PrevTx[:], tmpStr)
								}
							}
						}
					}
				}
			}
			tmp := UTXOSet{Cnt: x.TxArray[i].TxoutCnt}
			copy(tmp.Data, x.TxArray[i].Out)
			tmp.Remain = tmp.Cnt
			tmp.Stat = make([]uint32, tmp.Cnt)
			for i := uint32(0); i < tmp.Cnt; i++ {
				if tmp.Data[i].ShardIndex() != shardindex {
					tmp.Stat[i] = 1
					tmp.Remain--
				}
			}
			if tmp.Remain > 0 {
				b.Put(x.TxArray[i].Hash[:], tmp.Encode())
			}
			if oktx {
				delete(a.TXCache, x.TxArray[i].Hash)
			}
		}
		return nil
	})
	return err

}
