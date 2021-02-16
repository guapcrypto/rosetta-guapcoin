package guap

import (
	"math/big"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func init() {
	if err := chaincfg.Register(&GuapMainnetParams); err != nil {
		panic(err)
	}
	if err := chaincfg.Register(&GuapTestnetParams); err != nil {
		panic(err)
	}
}

var (
	bigOne       = big.NewInt(1)
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)
)

const (
	// DeploymentTestDummy ...
	DeploymentTestDummy = iota

	// DeploymentCSV ...
	DeploymentCSV

	// DeploymentSegwit ...
	DeploymentSegwit

	// DefinedDeployments ...
	DefinedDeployments
)

// genesisCoinbaseTx is the coinbase transaction for the genesis blocks for
// the main network, regression test network, and test network (version 3).
var genesisCoinbaseTx = wire.MsgTx{
	Version: 1,
	TxIn: []*wire.TxIn{
		{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			SignatureScript: []byte{
				0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04, 0x17,
				0x69, 0x6e, 0x73, 0x65, 0x72, 0x74, 0x20, 0x74,
				0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
				0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
			},
			Sequence: 0xffffffff,
		},
	},
	TxOut: []*wire.TxOut{
		{
			Value: 0x00,
			PkScript: []byte{ // ToDo
				0x76, 0xa9, 0x14, 0x34, 0x59, 0x91, 0xdb, 0xf5,
				0x7b, 0xfb, 0x01, 0x4b, 0x87, 0x00, 0x6a, 0xcd,
				0xfa, 0xfb, 0xfc, 0x5f, 0xe8, 0x29, 0x2f, 0x88,
				0xac,
			},
		},
	},
	LockTime: 0,
}

// https://github.com/guapcrypto/guapcoin/blob/master/src/chainparams.cpp#L19
var genesisMerkleRoot = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x14, 0xa0, 0xda, 0x16, 0xdd, 0x29, 0x2c, 0x13,
	0xd0, 0x8a, 0x93, 0xc2, 0x39, 0xd8, 0xe6, 0xdc,
	0xf8, 0x5b, 0xc4, 0x02, 0x92, 0x49, 0x60, 0xab,
	0xfb, 0xb4, 0xd7, 0xfe, 0xb2, 0xcb, 0x93, 0xb6,
})

var genesisBlock = wire.MsgBlock{
	Header: wire.BlockHeader{
		Version:    1,
		PrevBlock:  chainhash.Hash{},         // 0000000000000000000000000000000000000000000000000000000000000000
		MerkleRoot: genesisMerkleRoot,        // b693cbb2fed7b4fbab60499202c45bf8dce6d839c2938ad0132c29dd16daa014
		Timestamp:  time.Unix(1563817096, 0), // Wednesday, October 28, 2015 6:51:31 PM GMT
		Bits:       0x1e0ffff0,
		Nonce:      21770810,
	},
	Transactions: []*wire.MsgTx{&genesisCoinbaseTx},
}

var genesisHash = chainhash.Hash([chainhash.HashSize]byte{ // Make go vet happy.
	0x64, 0x20, 0xfc, 0x5b, 0xe7, 0xe0, 0xbc, 0x23,
	0x66, 0x36, 0x21, 0x5f, 0x6c, 0x8f, 0x21, 0xfc,
	0x16, 0x30, 0x8e, 0x59, 0xff, 0x30, 0x66, 0xca,
	0x06, 0xb1, 0x24, 0x30, 0x56, 0x02, 0x00, 0x00,
})

func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		panic(err)
	}
	return hash
}

// MainNetParams returns the chain configuration for mainnet
var GuapMainnetParams = chaincfg.Params{
	Name:        "mainnet",
	Net:         0x32cb12ac,
	DefaultPort: "9633",

	// Chain parameters
	GenesisBlock: &genesisBlock,
	GenesisHash:  &genesisHash,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "guap",

	// Address encoding magics
	PubKeyHashAddrID:        38,
	ScriptHashAddrID:        6,
	PrivateKeyID:            46,
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh
	BIP0034Height:           1,
	BIP0065Height:           399100,
	BIP0066Height:           200000,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0x8c,
}

// TestnetParams returns the chain configuration for testnet
var GuapTestnetParams = chaincfg.Params{
	Name:        "testnet",
	Net:         0xfae4aae1,
	DefaultPort: "19246",

	// Chain parameters
	GenesisBlock: &genesisBlock,
	GenesisHash:  &genesisHash,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "guap", // always bc for main net

	// Address encoding magics
	PubKeyHashAddrID:        111,
	ScriptHashAddrID:        196,
	PrivateKeyID:            239,
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0A, // starts with 7Xh
	BIP0034Height:           1,
	BIP0065Height:           200000,
	BIP0066Height:           200000,

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0x8c,
}
