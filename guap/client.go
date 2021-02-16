// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package guap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"time"

	guapUtils "github.com/guapcrypto/rosetta-guapcoin/utils"

	"github.com/guapcrypto/rosetta-sdk-go/types"
	"github.com/guapcrypto/rosetta-sdk-go/utils"
	"github.com/btcsuite/btcutil"
)

const (
	// genesisBlockIndex is the height of the block we consider to be the
	// genesis block of the guap blockchain for polling
	genesisBlockIndex = 0

	// requestID is the JSON-RPC request ID we use for making requests.
	// We don't need unique request IDs because we're processing all of
	// our requests synchronously.
	requestID = 1

	// jSONRPCVersion is the JSON-RPC version we use for making requests
	jSONRPCVersion = "2.0"

	// blockVerbosity represents the verbose level used when fetching blocks
	// * 0 returns the hex representation
	// * 1 returns the JSON representation
	// * 2 returns the JSON representation with included Transaction data
	blockVerbosity = 2
)

type requestMethod string

const (
	// https://guap.org/en/developer-reference#getblock
	requestMethodGetBlock requestMethod = "getblock"

	// https://guap.org/en/developer-reference#getblockhash
	requestMethodGetBlockHash requestMethod = "getblockhash"

	// https://guap.org/en/developer-reference#getblockchaininfo
	requestMethodGetBlockchainInfo requestMethod = "getblockchaininfo"

	// https://developer.guap.org/reference/rpc/getpeerinfo.html
	requestMethodGetPeerInfo requestMethod = "getpeerinfo"

	// https://developer.guap.org/reference/rpc/pruneblockchain.html
	requestMethodPruneBlockchain requestMethod = "pruneblockchain"

	// https://developer.guap.org/reference/rpc/sendrawtransaction.html
	requestMethodSendRawTransaction requestMethod = "sendrawtransaction"

	// https://developer.guap.org/reference/rpc/estimatesmartfee.html
	requestMethodEstimateSmartFee requestMethod = "estimatesmartfee"

	// https://developer.guap.org/reference/rpc/getrawmempool.html
	requestMethodRawMempool requestMethod = "getrawmempool"

	// blockNotFoundErrCode is the RPC error code when a block cannot be found
	blockNotFoundErrCode = -5
)

const (
	defaultTimeout = 100 * time.Second
	dialTimeout    = 5 * time.Second

	// timeMultiplier is used to multiply the time
	// returned in guap blocks to be milliseconds.
	timeMultiplier = 1000

	// rpc credentials are fixed in rosetta-guap
	// because we never expose access to the raw guapcoind
	// endpoints (that could be used perform an attack, like
	// changing our peers).
	rpcUsername = "rosetta"
	rpcPassword = "rosetta"
)

var (
	// ErrBlockNotFound is returned by when the requested block
	// cannot be found by the node
	ErrBlockNotFound = errors.New("unable to find block")

	// ErrJSONRPCError is returned when receiving an error from a JSON-RPC response
	ErrJSONRPCError = errors.New("JSON-RPC error")
)

// Client is used to fetch blocks from guapcoind and
// to parse guap block data into Rosetta types.
//
// We opted not to use existing guap RPC libraries
// because they don't allow providing context
// in each request.
type Client struct {
	baseURL string

	genesisBlockIdentifier *types.BlockIdentifier
	currency               *types.Currency

	httpClient *http.Client
}

// LocalhostURL returns the URL to use
// for a client that is running at localhost.
func LocalhostURL(rpcPort int) string {
	return fmt.Sprintf("http://localhost:%d", rpcPort)
}

// NewClient creates a new guap client.
func NewClient(
	baseURL string,
	genesisBlockIdentifier *types.BlockIdentifier,
	currency *types.Currency,
) *Client {
	return &Client{
		baseURL:                baseURL,
		genesisBlockIdentifier: genesisBlockIdentifier,
		currency:               currency,
		httpClient:             newHTTPClient(defaultTimeout),
	}
}

// newHTTPClient returns a new HTTP client
func newHTTPClient(timeout time.Duration) *http.Client {
	var netTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: dialTimeout,
		}).Dial,
	}

	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: netTransport,
	}

	return httpClient
}

// NetworkStatus returns the *types.NetworkStatusResponse for
// guapcoind.
func (b *Client) NetworkStatus(ctx context.Context) (*types.NetworkStatusResponse, error) {
	rawBlock, err := b.getBlock(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to get current block", err)
	}

	currentBlock, err := b.parseBlockData(rawBlock)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to parse current block", err)
	}

	peers, err := b.GetPeers(ctx)
	if err != nil {
		return nil, err
	}

	return &types.NetworkStatusResponse{
		CurrentBlockIdentifier: currentBlock.BlockIdentifier,
		CurrentBlockTimestamp:  currentBlock.Timestamp,
		GenesisBlockIdentifier: b.genesisBlockIdentifier,
		Peers: peers,
	}, nil
}

// GetPeers fetches the list of peer nodes
func (b *Client) GetPeers(ctx context.Context) ([]*types.Peer, error) {
	info, err := b.getPeerInfo(ctx)
	if err != nil {
		return nil, err
	}

	peers := make([]*types.Peer, len(info))
	for i, peerInfo := range info {
		metadata, err := types.MarshalMap(peerInfo)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to marshal peer info", err)
		}

		peers[i] = &types.Peer{
			PeerID:   peerInfo.Addr,
			Metadata: metadata,
		}
	}

	return peers, nil
}

// GetRawBlock fetches a block (block) by *types.PartialBlockIdentifier.
func (b *Client) GetRawBlock(
	ctx context.Context,
	identifier *types.PartialBlockIdentifier,
) (*Block, []string, error) {
	block, err := b.getBlock(ctx, identifier)
	if err != nil {
		return nil, nil, err
	}

	coins := []string{}
	blockTxHashes := []string{}
	for txIndex, tx := range block.Txs {
		blockTxHashes = append(blockTxHashes, tx.Hash)
		for inputIndex, input := range tx.Inputs {
			txHash, vout, ok := b.getInputTxHash(input, txIndex, inputIndex)
			if !ok {
				continue
			}

			// If any transactions spent in the same block they are created, don't include them
			// in previousTxHashes to fetch.
			if !utils.ContainsString(blockTxHashes, txHash) {
				coins = append(coins, CoinIdentifier(txHash, vout))
			}
		}
	}

	return block, coins, nil
}

// ParseBlock returns a parsed guap block given a raw guap
// block and a map of transactions containing inputs.
func (b *Client) ParseBlock(
	ctx context.Context,
	block *Block,
	coins map[string]*types.AccountCoin,
) (*types.Block, error) {
	rblock, err := b.parseBlockData(block)
	if err != nil {
		return nil, err
	}

	txs, err := b.parseTransactions(ctx, block, coins)
	if err != nil {
		return nil, err
	}

	rblock.Transactions = txs

	return rblock, nil
}

// SendRawTransaction submits a serialized transaction
// to guapcoind.
func (b *Client) SendRawTransaction(
	ctx context.Context,
	serializedTx string,
) (string, error) {
	// Parameters:
	//   1. hextring
	//   2. maxfeerate (0 means accept any fee)
	params := []interface{}{serializedTx, 0}

	response := &sendRawTransactionResponse{}
	if err := b.post(ctx, requestMethodSendRawTransaction, params, response); err != nil {
		return "", fmt.Errorf("%w: error submitting raw transaction", err)
	}

	return response.Result, nil
}

// SuggestedFeeRate estimates the approximate fee per vKB needed
// to get a transaction in a block within conf_target.
func (b *Client) SuggestedFeeRate(
	ctx context.Context,
	confTarget int64,
) (float64, error) {
	// Parameters:
	//   1. conf_target (confirmation target in blocks)
	params := []interface{}{confTarget}

	response := &suggestedFeeRateResponse{}
	if err := b.post(ctx, requestMethodEstimateSmartFee, params, response); err != nil {
		return -1, fmt.Errorf("%w: error getting fee estimate", err)
	}

	return response.Result.FeeRate, nil
}

// PruneBlockchain prunes up to the provided height.
// https://guapcore.org/en/doc/0.20.0/rpc/blockchain/pruneblockchain
func (b *Client) PruneBlockchain(
	ctx context.Context,
	height int64,
) (int64, error) {
	// Parameters:
	//   1. Height
	// https://developer.guap.org/reference/rpc/pruneblockchain.html#argument-1-height
	params := []interface{}{height}

	response := &pruneBlockchainResponse{}
	if err := b.post(ctx, requestMethodPruneBlockchain, params, response); err != nil {
		return -1, fmt.Errorf("%w: error pruning blockchain", err)
	}

	return response.Result, nil
}

// RawMempool returns an array of all transaction
// hashes currently in the mempool.
func (b *Client) RawMempool(
	ctx context.Context,
) ([]string, error) {
	// Parameters:
	//   1. verbose
	params := []interface{}{false}

	response := &rawMempoolResponse{}
	if err := b.post(ctx, requestMethodRawMempool, params, response); err != nil {
		return nil, fmt.Errorf("%w: error getting raw mempool", err)
	}

	return response.Result, nil
}

// getPeerInfo performs the `getpeerinfo` JSON-RPC request
func (b *Client) getPeerInfo(
	ctx context.Context,
) ([]*PeerInfo, error) {
	params := []interface{}{}
	response := &peerInfoResponse{}
	if err := b.post(ctx, requestMethodGetPeerInfo, params, response); err != nil {
		return nil, fmt.Errorf("%w: error posting to JSON-RPC", err)
	}

	return response.Result, nil
}

// getBlock returns a Block for the specified identifier
func (b *Client) getBlock(
	ctx context.Context,
	identifier *types.PartialBlockIdentifier,
) (*Block, error) {
	hash, err := b.getBlockHash(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("%w: error getting block hash by identifier", err)
	}

	// Parameters:
	//   1. Block hash (string, required)
	//   2. Verbosity (integer, optional, default=1)
	// https://guap.org/en/developer-reference#getblock
	params := []interface{}{hash, blockVerbosity}

	response := &blockResponse{}
	if err := b.post(ctx, requestMethodGetBlock, params, response); err != nil {
		return nil, fmt.Errorf("%w: error fetching block by hash %s", err, hash)
	}

	return response.Result, nil
}

// getBlockchainInfo performs the `getblockchaininfo` JSON-RPC request
func (b *Client) getBlockchainInfo(
	ctx context.Context,
) (*BlockchainInfo, error) {
	params := []interface{}{}
	response := &blockchainInfoResponse{}
	if err := b.post(ctx, requestMethodGetBlockchainInfo, params, response); err != nil {
		return nil, fmt.Errorf("%w: unbale to get blockchain info", err)
	}

	return response.Result, nil
}

// getBlockHash returns the hash for a specified block identifier.
// If the identifier includes a hash it will return that hash.
// If the identifier only includes an index, if will fetch the hash that corresponds to
// that block height from the node.
func (b *Client) getBlockHash(
	ctx context.Context,
	identifier *types.PartialBlockIdentifier,
) (string, error) {
	// Lookup best block if no PartialBlockIdentifier provided.
	if identifier == nil || (identifier.Hash == nil && identifier.Index == nil) {
		info, err := b.getBlockchainInfo(ctx)
		if err != nil {
			return "", fmt.Errorf("%w: unable to get blockchain info", err)
		}

		return info.BestBlockHash, nil
	}

	if identifier.Hash != nil {
		return *identifier.Hash, nil
	}

	return b.getHashFromIndex(ctx, *identifier.Index)
}

// parseBlock returns a *types.Block from a Block
func (b *Client) parseBlockData(block *Block) (*types.Block, error) {
	if block == nil {
		return nil, errors.New("error parsing nil block")
	}

	blockIndex := block.Height
	previousBlockIndex := blockIndex - 1
	previousBlockHash := block.PreviousBlockHash

	// the genesis block's predecessor is itself
	if blockIndex == genesisBlockIndex {
		previousBlockIndex = genesisBlockIndex
		previousBlockHash = block.Hash
	}

	metadata, err := block.Metadata()
	if err != nil {
		return nil, fmt.Errorf("%w: unable to create block metadata", err)
	}

	return &types.Block{
		BlockIdentifier: &types.BlockIdentifier{
			Hash:  block.Hash,
			Index: blockIndex,
		},
		ParentBlockIdentifier: &types.BlockIdentifier{
			Hash:  previousBlockHash,
			Index: previousBlockIndex,
		},
		Timestamp: block.Time * timeMultiplier,
		Metadata:  metadata,
	}, nil
}

// getHashFromIndex performs the `getblockhash` JSON-RPC request for the specified
// block index, and returns the hash.
// https://guap.org/en/developer-reference#getblockhash
func (b *Client) getHashFromIndex(
	ctx context.Context,
	index int64,
) (string, error) {
	// Parameters:
	//   1. Block height (numeric, required)
	// https://guap.org/en/developer-reference#getblockhash
	params := []interface{}{index}

	response := &blockHashResponse{}
	if err := b.post(ctx, requestMethodGetBlockHash, params, response); err != nil {
		return "", fmt.Errorf(
			"%w: error fetching block hash by index: %d",
			err,
			index,
		)
	}

	return response.Result, nil
}

// skipTransactionOperations is used to skip operations on transactions that
// contain duplicate UTXOs (which are no longer possible after BIP-30). This
// function mirrors the behavior of a similar commit in guap-core.
//
// Source: https://github.com/guap/guap/commit/ab91bf39b7c11e9c86bb2043c24f0f377f1cf514
func skipTransactionOperations(blockNumber int64, blockHash string, transactionHash string) bool {
	if blockNumber == 267 && blockHash == "b64e480fdd859e9ffb55be37bf5be06bafac2b82898648269711d6792b9bee6c" &&
		transactionHash == "606441d523fc2ccf237fda9a9f1961e39b5732279ec429f11cf301d891301112" {
		return true
	}

	if blockNumber == 273 && blockHash == "9f5783dd5b148db745aeb1fd59bff4496ee5ce137b5de81f7a52fd735e09656b" &&
		transactionHash == "0a463fe691e2aa3907c30605e7da91c6adffafd2e1c4bd7c770b050661791b35" {
		return true
	}

	if blockNumber == 307 && blockHash == "3d6a458fb45fb1c0da27cc3117fff64a461a65e30bcbfe352697e991a88cb423" &&
		transactionHash == "d238d07a28bf3a86d394c0603be04d9716a7fb3ce98ebef3c9e54209c7d528e0" {
		return true
	}

	if blockNumber == 313 && blockHash == "c25a106260d27ab1a4dc765af9206eca5654049f7adb9d8031d0dcb0a27156cc" &&
		transactionHash == "e8aaa80c02ab4e0f378dad4eeda6b07353dce4d7ad188a612987234fc5f1d5bb" {
		return true
	}

	if blockNumber == 465 && blockHash == "229ae95343e8f66ab1100bc69d808522bc8a7588c1f94125d16e7953831bda3a" &&
		transactionHash == "cbb548a720dc48ef93b810ac91950dafd6cee76cb515edc23f3c749eee909311" {
		return true
	}

	if blockNumber == 505 && blockHash == "ddc9b654fcf6f8ee39e6a448afffb06f8c3313629477b398cc8422e1c15f20e2" &&
		transactionHash == "28e6f8bc2374057ce1599a1e54ff4fb94a262a95906913524675b5c79e001422" {
		return true
	}

	if blockNumber == 510 && blockHash == "a2b6cb547e56c4aa260cc487c5432314001d15357ec1c8fd272faba7b9c09091" &&
		transactionHash == "dacdc48d15df8e2251beb4daed8118fca6ba7d529ae36048ec5b1ef3291d4bc3" {
		return true
	}

	if blockNumber == 518 && blockHash == "f3e4c7c1a2b2d8256c839f65431ea02093e52fb517b336e424fd46f3e11114ae" &&
		transactionHash == "afd613d22813cd032fbce39848b8c55d3eeb254b4d261434c1ece62fa1c2a924" {
		return true
	}

	if blockNumber == 521 && blockHash == "5735c577920ced8ef8fb48787d7010f1bfd865b5eacb285d057c2f92d44afd11" &&
		transactionHash == "5fc5258e6ba2cab3d1d5d67a98e31e1da6608ca57e798b4b24e78e7445fb47cb" {
		return true
	}

	if blockNumber == 537 && blockHash == "cdddbb4bb0e1c8353462fc77b886e07e1ccd6d083f52d8c1e6547e9699978ffe" &&
		transactionHash == "866a7692d384383f5b6ef8ce3e5f534f2db9809fa3bfedcc4ed88fad8617d2f0" {
		return true
	}

	if blockNumber == 551 && blockHash == "621986fe0fafba73efd4c9959d127dc19a9b5ebbbf8fe5a9d36ee5e61bed2975" &&
		transactionHash == "a0ab6518408e6df06d98170425c6fd94b61c48c3c9db4a0edc2d93a408c7328b" {
		return true
	}

	if blockNumber == 603 && blockHash == "db8976fb952df7fde74776e211e196b7e281489fd1c2fa0df44a0459d8f01c16" &&
		transactionHash == "baad506994315607b7f3dad857546dc25586527901e5360cbeb4e20db6593056" {
		return true
	}

	if blockNumber == 729 && blockHash == "17a1e02596b720b08c5e5bad7ea30d07735c9315e4efdc9768fa8ee8c1118a67" &&
		transactionHash == "21cff60ab595af6b7865025b1e05f0154fb97fae40ff8bf190473ea9c19d12ac" {
		return true
	}

	return false
}

// parseTransactions returns the transactions for a specified `Block`
func (b *Client) parseTransactions(
	ctx context.Context,
	block *Block,
	coins map[string]*types.AccountCoin,
) ([]*types.Transaction, error) {
	logger := guapUtils.ExtractLogger(ctx, "client")

	if block == nil {
		return nil, errors.New("error parsing nil block")
	}

	txs := make([]*types.Transaction, len(block.Txs))

	for index, transaction := range block.Txs {
		txOps, err := b.parseTxOperations(transaction, index, coins)
		if err != nil {
			return nil, fmt.Errorf("%w: error parsing transaction operations", err)
		}

		if skipTransactionOperations(block.Height, block.Hash, transaction.Hash) {
			logger.Warnw(
				"skipping transaction",
				"block index", block.Height,
				"block hash", block.Hash,
				"transaction hash", transaction.Hash,
			)
			for _, op := range txOps {
				op.Status = types.String(SkippedStatus)
			}
		}

		metadata, err := transaction.Metadata()
		if err != nil {
			return nil, fmt.Errorf("%w: unable to get metadata for transaction", err)
		}

		tx := &types.Transaction{
			TransactionIdentifier: &types.TransactionIdentifier{
				Hash: transaction.Hash,
			},
			Operations: txOps,
			Metadata:   metadata,
		}

		txs[index] = tx

		// In some cases, a transaction will spent an output
		// from the same block.
		for _, op := range tx.Operations {
			if op.CoinChange == nil {
				continue
			}

			if op.CoinChange.CoinAction != types.CoinCreated {
				continue
			}

			coins[op.CoinChange.CoinIdentifier.Identifier] = &types.AccountCoin{
				Coin: &types.Coin{
					CoinIdentifier: op.CoinChange.CoinIdentifier,
					Amount:         op.Amount,
				},
				Account: op.Account,
			}
		}
	}

	return txs, nil
}

// parseTransactions returns the transaction operations for a specified transaction.
// It uses a map of previous transactions to properly hydrate the input operations.
func (b *Client) parseTxOperations(
	tx *Transaction,
	txIndex int,
	coins map[string]*types.AccountCoin,
) ([]*types.Operation, error) {
	txOps := []*types.Operation{}

	for networkIndex, input := range tx.Inputs {
		if guapIsCoinbaseInput(input, txIndex, networkIndex) {
			txOp, err := b.coinbaseTxOperation(input, int64(len(txOps)), int64(networkIndex))
			if err != nil {
				return nil, err
			}

			txOps = append(txOps, txOp)
			break
		}

		// Fetch the *types.AccountCoin the input is associated with
		accountCoin, ok := coins[CoinIdentifier(input.TxHash, input.Vout)]
		if !ok {
			return nil, fmt.Errorf(
				"error finding previous tx: %s, for tx: %s, input index: %d",
				input.TxHash,
				tx.Hash,
				networkIndex,
			)
		}

		// Parse the input transaction operation
		txOp, err := b.parseInputTransactionOperation(
			input,
			int64(len(txOps)),
			int64(networkIndex),
			accountCoin,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: error parsing tx input", err)
		}

		txOps = append(txOps, txOp)
	}

	for networkIndex, output := range tx.Outputs {
		txOp, err := b.parseOutputTransactionOperation(
			output,
			tx.Hash,
			int64(len(txOps)),
			int64(networkIndex),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: error parsing tx output, hash: %s, index: %d",
				err,
				tx.Hash,
				networkIndex,
			)
		}

		txOps = append(txOps, txOp)
	}

	return txOps, nil
}

// parseOutputTransactionOperation returns the types.Operation for the specified
// `guapOutput` transaction output.
func (b *Client) parseOutputTransactionOperation(
	output *Output,
	txHash string,
	index int64,
	networkIndex int64,
) (*types.Operation, error) {
	amount, err := b.parseAmount(output.Value)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: error parsing output value, hash: %s, index: %d",
			err,
			txHash,
			index,
		)
	}

	metadata, err := output.Metadata()
	if err != nil {
		return nil, fmt.Errorf("%w: unable to get output metadata", err)
	}

	coinChange := &types.CoinChange{
		CoinIdentifier: &types.CoinIdentifier{
			Identifier: fmt.Sprintf("%s:%d", txHash, networkIndex),
		},
		CoinAction: types.CoinCreated,
	}

	// If we are unable to parse the output account (i.e. guapcoind
	// returns a blank/nonstandard ScriptPubKey), we create an address as the
	// concatenation of the tx hash and index.
	//
	// Example: 4852fe372ff7534c16713b3146bbc1e86379c70bea4d5c02fb1fa0112980a081:1
	// on testnet
	account := b.parseOutputAccount(output.ScriptPubKey)
	if len(account.Address) == 0 {
		account.Address = fmt.Sprintf("%s:%d", txHash, networkIndex)
	}

	// If this is an OP_RETURN locking script,
	// we don't create a coin because it is provably unspendable.
	if output.ScriptPubKey.Type == NullData {
		coinChange = nil
	}

	return &types.Operation{
		OperationIdentifier: &types.OperationIdentifier{
			Index:        index,
			NetworkIndex: &networkIndex,
		},
		Type:    OutputOpType,
		Status:  types.String(SuccessStatus),
		Account: account,
		Amount: &types.Amount{
			Value:    strconv.FormatInt(int64(amount), 10),
			Currency: b.currency,
		},
		CoinChange: coinChange,
		Metadata:   metadata,
	}, nil
}

// getInputTxHash returns the transaction hash corresponding to an inputs previous
// output. If the input is a coinbase input, then no previous transaction is associated
// with the input.
func (b *Client) getInputTxHash(
	input *Input,
	txIndex int,
	inputIndex int,
) (string, int64, bool) {
	if guapIsCoinbaseInput(input, txIndex, inputIndex) {
		return "", -1, false
	}

	return input.TxHash, input.Vout, true
}

// guapIsCoinbaseInput returns whether the specified input is
// the coinbase input. The coinbase input is always the first input in the first
// transaction, and does not contain a previous transaction hash.
func guapIsCoinbaseInput(input *Input, txIndex int, inputIndex int) bool {
	return txIndex == 0 && inputIndex == 0 && input.TxHash == "" && input.Coinbase != ""
}

// parseInputTransactionOperation returns the types.Operation for the specified
// Input transaction input.
func (b *Client) parseInputTransactionOperation(
	input *Input,
	index int64,
	networkIndex int64,
	accountCoin *types.AccountCoin,
) (*types.Operation, error) {
	metadata, err := input.Metadata()
	if err != nil {
		return nil, fmt.Errorf("%w: unable to get input metadata", err)
	}

	newValue, err := types.NegateValue(accountCoin.Coin.Amount.Value)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to negate previous output", err)
	}

	return &types.Operation{
		OperationIdentifier: &types.OperationIdentifier{
			Index:        index,
			NetworkIndex: &networkIndex,
		},
		Type:    InputOpType,
		Status:  types.String(SuccessStatus),
		Account: accountCoin.Account,
		Amount: &types.Amount{
			Value:    newValue,
			Currency: b.currency,
		},
		CoinChange: &types.CoinChange{
			CoinIdentifier: &types.CoinIdentifier{
				Identifier: fmt.Sprintf("%s:%d", input.TxHash, input.Vout),
			},
			CoinAction: types.CoinSpent,
		},
		Metadata: metadata,
	}, nil
}

// parseAmount returns the atomic value of the specified amount.
// https://godoc.org/github.com/btcsuite/btcutil#NewAmount
func (b *Client) parseAmount(amount float64) (uint64, error) {
	atomicAmount, err := btcutil.NewAmount(amount)
	if err != nil {
		return uint64(0), fmt.Errorf("%w: error parsing amount", err)
	}

	if atomicAmount < 0 {
		return uint64(0), fmt.Errorf("error unexpected negative amount: %d", atomicAmount)
	}

	return uint64(atomicAmount), nil
}

// parseOutputAccount parses a guapScriptPubKey and returns an account
// identifier. The account identifier's address corresponds to the first
// address encoded in the script.
func (b *Client) parseOutputAccount(
	scriptPubKey *ScriptPubKey,
) *types.AccountIdentifier {
	if len(scriptPubKey.Addresses) != 1 {
		return &types.AccountIdentifier{Address: scriptPubKey.Hex}
	}

	return &types.AccountIdentifier{Address: scriptPubKey.Addresses[0]}
}

// coinbaseTxOperation constructs a transaction operation for the coinbase input.
// This reflects an input that does not correspond to a previous output.
func (b *Client) coinbaseTxOperation(
	input *Input,
	index int64,
	networkIndex int64,
) (*types.Operation, error) {
	metadata, err := input.Metadata()
	if err != nil {
		return nil, fmt.Errorf("%w: unable to get input metadata", err)
	}

	return &types.Operation{
		OperationIdentifier: &types.OperationIdentifier{
			Index:        index,
			NetworkIndex: &networkIndex,
		},
		Type:     CoinbaseOpType,
		Status:   types.String(SuccessStatus),
		Metadata: metadata,
	}, nil
}

// post makes a HTTP request to a guap node
func (b *Client) post(
	ctx context.Context,
	method requestMethod,
	params []interface{},
	response jSONRPCResponse,
) error {
	rpcRequest := &request{
		JSONRPC: jSONRPCVersion,
		ID:      requestID,
		Method:  string(method),
		Params:  params,
	}

	requestBody, err := json.Marshal(rpcRequest)
	if err != nil {
		return fmt.Errorf("%w: error marshalling RPC request", err)
	}

	req, err := http.NewRequest(http.MethodPost, b.baseURL, bytes.NewReader(requestBody))
	if err != nil {
		return fmt.Errorf("%w: error constructing request", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(rpcUsername, rpcPassword)

	// Perform the post request
	res, err := b.httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("%w: error posting to rpc-api", err)
	}
	defer res.Body.Close()

	// We expect JSON-RPC responses to return `200 OK` statuses
	if res.StatusCode != http.StatusOK {
		val, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("invalid response: %s %s", res.Status, string(val))
	}

	if err = json.NewDecoder(res.Body).Decode(response); err != nil {
		return fmt.Errorf("%w: error decoding response body", err)
	}

	// Handle errors that are returned in JSON-RPC responses with `200 OK` statuses
	return response.Err()
}
