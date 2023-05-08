package tranx

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"math/big"
	"sync"
)

type Transaction struct {
	AccountNonce uint64          `json:"nonce"    `
	Price        *big.Int        `json:"gasPrice" `
	GasLimit     uint64          `json:"gas"      `
	Recipient    *common.Address `json:"to"       `
	Amount       *big.Int        `json:"value"    `
	Payload      []byte          `json:"input"    `

	// Signature values
	V *big.Int `json:"v" `
	R *big.Int `json:"r" `
	S *big.Int `json:"s" `
}

func (t Transaction) GetRLP() ([]byte, error) {
	return rlp.EncodeToBytes(t)
}

// EncodeBufferPool holds temporary encoder buffers for DeriveSha and TX encoding.
var EncodeBufferPool = sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

func EncodeForDerive(list types.Transactions, i int, buf *bytes.Buffer) []byte {
	buf.Reset()
	list.EncodeIndex(i, buf)
	// It's really unfortunate that we need to do perform this copy.
	// StackTrie holds onto the values until Hash is called, so the values
	// written to it must not alias.
	return common.CopyBytes(buf.Bytes())
}

func GetTransactionProof(bk *types.Block, index int) (Proof, []byte, bool) {
	trie := NewTrie()
	valueBuf := EncodeBufferPool.Get().(*bytes.Buffer)
	defer EncodeBufferPool.Put(valueBuf)
	var indexBuf []byte
	list := bk.Transactions()

	for i := 1; i < list.Len() && i <= 0x7f; i++ {
		indexBuf = rlp.AppendUint64(indexBuf[:0], uint64(i))
		value := EncodeForDerive(list, i, valueBuf)
		err := trie.PutWithError(indexBuf, value)
		if err != nil {
			return nil, nil, false
		}
	}

	if list.Len() > 0 {
		indexBuf = rlp.AppendUint64(indexBuf[:0], 0)
		value := EncodeForDerive(list, 0, valueBuf)
		err := trie.PutWithError(indexBuf, value)
		if err != nil {
			return nil, nil, false
		}
	}

	for i := 0x80; i < list.Len(); i++ {
		indexBuf = rlp.AppendUint64(indexBuf[:0], uint64(i))
		value := EncodeForDerive(list, i, valueBuf)
		err := trie.PutWithError(indexBuf, value)
		if err != nil {
			return nil, nil, false
		}
	}
	proof, found := trie.Prove(rlp.AppendUint64(indexBuf[:0], uint64(index)))

	return proof, rlp.AppendUint64(indexBuf[:0], uint64(index)), found
}
