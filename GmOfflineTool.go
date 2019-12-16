package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/33cn/chain33/common"
	"github.com/33cn/chain33/common/address"
	"github.com/33cn/chain33/common/crypto"

	ety "github.com/33cn/chain33/system/dapp/coins/types"
	types "github.com/33cn/chain33/types"

	//"github.com/33cn/chain33/wallet"

	// "io/ioutil"
	"log"

	"github.com/golang/protobuf/proto"
)

/*-----------------------------------------------------------------------------------------------------------------
调用说明：
	参数1： 方法名，目前支持
	        Chain33.CreateNoBalanceTransaction，
			Chain33.SignRawTx
			Chain33.CreateRawTransactionNoToken：此方法支持GM,BTY的转账，不支持token(WXB,JCB)的转账
	参数2： properFee 用户在真实网络中查询得到，查询命令：curl -sd '{"method":"Chain33.GetProperFee", "params":[{}]}' http://XXX:8901
	参数3： 方法参数
调用例子：
    签名交易：如果签名的是代扣交易，index：2，如果签名的是普通转账交易，index可以不赋值
	GmOfflineTool.exe "Chain33.SignRawTx" "100000" "{\"txHex\":\"0a13757365722e702e676d636861696e2e6e6f6e6512126e6f2d6665652d7472616e73616374696f6e1a6e0801122103021d3e3711419561a36b5e78a4148dcc187963beb7e7aa69fc2245b4a5c76e281a473045022100a2871090fd4ae6f15b5f0a4b351708ddb11e4d960a70253547bbbd7797b031ce02206aa94f72f1b64a13ffeaf1342bfd4bc696f5a7e4e24bca818684374086ec72d520c09a0c30d8e6bbb6e6c2c0d1793a22314a7068657667384b646863524c7053557633724351544a35333738415569754d4c40024ab4030a91020a13757365722e702e676d636861696e2e6e6f6e6512126e6f2d6665652d7472616e73616374696f6e1a6e0801122103021d3e3711419561a36b5e78a4148dcc187963beb7e7aa69fc2245b4a5c76e281a473045022100a2871090fd4ae6f15b5f0a4b351708ddb11e4d960a70253547bbbd7797b031ce02206aa94f72f1b64a13ffeaf1342bfd4bc696f5a7e4e24bca818684374086ec72d520c09a0c30d8e6bbb6e6c2c0d1793a22314a7068657667384b646863524c7053557633724351544a35333738415569754d4c40024a20b2baf372dc802f8432426685bf0f4b24eb05fc75a351e259b5cdea82d23571c752200350f5693226c8826b28774a28cf2e261f7857d17289a67d4cee077ef8f1543f0a9d010a14757365722e702e676d636861696e2e636f696e73123318010a2f100a1a0753656e6420474d2222314a6b624d7135794e4d5a48746f6b6a673558786b4333525a62716a6f504a6d383430febb9d9adcc1a6bc5e3a223137684a524e7257395767464a4a336d68686e6e657a57796477564c6b33534e387940024a20b2baf372dc802f8432426685bf0f4b24eb05fc75a351e259b5cdea82d23571c752200350f5693226c8826b28774a28cf2e261f7857d17289a67d4cee077ef8f1543f\",\"privkey\":\"0x2c0ac164452670785dc3a84ecfdbcdc3c98c2c29e140efa646ca0304fc30af2a\",\"expire\":\"1s\",\"index\":2}"
	代扣交易：
	GmOfflineTool.exe "Chain33.CreateNoBalanceTransaction" "100000" "{\"txHex\":\"0a14757365722e702e676d636861696e2e636f696e73123918010a351080e1eb171a0a73656e6420302e35676d222231504345705248764b45364438536834326f47514247687752374d6377456f645a4d20a08d0630a38fb6a5f3ffec8f393a223137684a524e7257395767464a4a336d68686e6e657a57796477564c6b33534e3879\",\"payAddr\":\"18bBoM1EnX99pEEByarD9HykUhiy3D94No\",\"privkey\":\"0x69c9d439c0ccdc5b6f1af2a5014330dbc7cdca17011936b6db5ff325fedb1b89\",\"expire\":\"30s\"}"
	构造交易：只支持GM,BTY的转账交易，不支持token(WXB,JCB)的转账
	GmOfflineTool.exe "Chain33.CreateRawTransactionNoToken" "100000" "{\"to\":\"1PCEpRHvKE6D8Sh42oGQBGhwR7McwEodZM\",\"amount\":50000000,\"fee\":0,\"note\":\"send 0.5gm\",\"isToken\":false,\"isWithdraw\":false,\"execName\":\"\",\"execer\":\"user.p.gmchain.coins\"}"
--------------------------------------------------------------------------------------------------------------------*/

var properFee int64 //最新properFee，由用户在真实网络中查询得到，通过命令行参数输入

//ParamsCreateRawTransactionNoToken 构造原始交易，支持GM,BTY的转账，不支持token(WXB,JCB)
type ParamsCreateRawTransactionNoToken struct {
	To         string
	Amount     int64
	Fee        int64
	Note       string
	IsToken    bool
	IsWithdraw bool
	ExecName   string
	Execer     string
}

//ParamsCreateNoBalanceTransaction  构造代扣交易
type ParamsCreateNoBalanceTransaction struct {
	TxHex   string
	PayAddr string
	Privkey string
	Expire  string
}

//ParamsSignRawTx 构造签名交易
type ParamsSignRawTx struct {
	PayAddr string
	Privkey string
	TxHex   string
	Expire  string
	Index   int32
}

//Response 程序应答
type Response struct {
	Method string
	ID     string
	Result string
	Error  string
}

// ProcSignRawTx 用钱包对交易进行签名
//input:
//type ReqSignRawTx struct {
//	Addr    string
//	Privkey string
//	TxHex   string
//	Expire  string
//}
//output:
//string
//签名交易
//func (wallet *Wallet) ProcSignRawTx(unsigned *types.ReqSignRawTx) (string, error) {
func ProcSignRawTx(unsigned *types.ReqSignRawTx) (string, error) {
	var SignType int
	var key crypto.PrivKey
	SignType = 1
	index := unsigned.Index
	/*
		wallet.mtx.Lock()
		defer wallet.mtx.Unlock()
		index := unsigned.Index

		if ok, err := wallet.IsRescanUtxosFlagScaning(); ok || err != nil {
			return "", err
		}

		var key crypto.PrivKey
		if unsigned.GetAddr() != "" {
			ok, err := wallet.CheckWalletStatus()
			if !ok {
				return "", err
			}
			key, err = wallet.getPrivKeyByAddr(unsigned.GetAddr())
			if err != nil {
				return "", err
			}
		} else if unsigned.GetPrivkey() != "" {
			keyByte, err := common.FromHex(unsigned.GetPrivkey())
			if err != nil || len(keyByte) == 0 {
				return "", err
			}
			cr, err := crypto.New(types.GetSignName("", SignType))
			if err != nil {
				return "", err
			}
			key, err = cr.PrivKeyFromBytes(keyByte)
			if err != nil {
				return "", err
			}
		} else {
			return "", types.ErrNoPrivKeyOrAddr
		}
	*/

	if unsigned.GetPrivkey() != "" {
		keyByte, err := common.FromHex(unsigned.GetPrivkey())
		if err != nil || len(keyByte) == 0 {
			return "", err
		}
		cr, err := crypto.New(types.GetSignName("", SignType))
		if err != nil {
			return "", err
		}
		key, err = cr.PrivKeyFromBytes(keyByte)
		if err != nil {
			return "", err
		}
	} else {
		return "", types.ErrNoPrivKeyOrAddr
	}

	txByteData, err := common.FromHex(unsigned.GetTxHex())
	if err != nil {
		return "", err
	}
	var tx types.Transaction
	err = types.Decode(txByteData, &tx)
	if err != nil {
		return "", err
	}

	if unsigned.NewToAddr != "" {
		tx.To = unsigned.NewToAddr
	}
	if unsigned.Fee != 0 {
		tx.Fee = unsigned.Fee
	} else {
		/*
			//get proper fee if not set
			proper, err := wallet.api.GetProperFee(nil)
			if err != nil {
				return "", err
			}
			fee, err := tx.GetRealFee(proper.ProperFee)
			if err != nil {
				return "", err
			}
			tx.Fee = fee
		*/
		tx.Fee = properFee //最新properFee，由用户在真实网络中查询得到，通过命令行参数输入
	}

	expire, err := types.ParseExpire(unsigned.GetExpire())
	if err != nil {
		return "", err
	}
	tx.SetExpire(time.Duration(expire))
	/*
		if policy, ok := wcom.PolicyContainer[string(types.GetParaExec(tx.Execer))]; ok {
			// 尝试让策略自己去完成签名
			needSysSign, signtx, err := policy.SignTransaction(key, unsigned)
			if !needSysSign {
				return signtx, err
			}
		}
	*/
	group, err := tx.GetTxGroup()
	if err != nil {
		return "", err
	}
	if group == nil {
		tx.Sign(int32(SignType), key)
		txHex := types.Encode(&tx)
		signedTx := hex.EncodeToString(txHex)
		return signedTx, nil
	}
	if int(index) > len(group.GetTxs()) {
		return "", types.ErrIndex
	}
	if index <= 0 {
		for i := range group.Txs {
			err := group.SignN(i, int32(SignType), key)
			if err != nil {
				return "", err
			}
		}
		grouptx := group.Tx()
		txHex := types.Encode(grouptx)
		signedTx := hex.EncodeToString(txHex)
		return signedTx, nil
	}
	index--
	err = group.SignN(int(index), int32(SignType), key)
	if err != nil {
		return "", err
	}
	grouptx := group.Tx()
	txHex := types.Encode(grouptx)
	signedTx := hex.EncodeToString(txHex)
	return signedTx, nil
}

// On_SignRawTx 处理交易签名
func txSignRawTx() (types.Message, error) {
	println("TestSignRawTx begin")
	/*
		单笔交易签名：
		1：将ReplySignRawTx.TxHex解码成Transaction,
		2：sign(marshal(Transaction))->Trascation.signature
		3: Marshal(Trascation)->ReplySignRawTx.TxHex

		req := &types.ReqSignRawTx{
			Addr:    "1D65zcQYGeQQATdjSBkMfTWQvhzJUeeaNc",
			Privkey: "b94ae286a508e4bb3fbbcb61997822fea6f0a534510597ef8eb60a19d6b219a0",
			TxHex:   "0a05636f696e73120c18010a081080c2d72f1a01312080897a30c0e2a4a789d684ad443a0131",
			Expire:  "0",
		}
	*/
	//代扣交易签名
	req := &types.ReqSignRawTx{
		//Addr:    "1D65zcQYGeQQATdjSBkMfTWQvhzJUeeaNc",
		Privkey: "0x2c0ac164452670785dc3a84ecfdbcdc3c98c2c29e140efa646ca0304fc30af2a",
		TxHex:   "0a13757365722e702e676d636861696e2e6e6f6e6512126e6f2d6665652d7472616e73616374696f6e1a6d0801122103021d3e3711419561a36b5e78a4148dcc187963beb7e7aa69fc2245b4a5c76e281a4630440220262aaa10b20f98c3d482ba7d1ced4034d3eedacaec8ca4f4d7a370f9cac78494022047c53ce4fc7f666cc30688b5388791fc996734a9b81b296d0cae3cd6313b688620c09a0c30dda887cca892f8ed2d3a22314a7068657667384b646863524c7053557633724351544a35333738415569754d4c40024ab9030a90020a13757365722e702e676d636861696e2e6e6f6e6512126e6f2d6665652d7472616e73616374696f6e1a6d0801122103021d3e3711419561a36b5e78a4148dcc187963beb7e7aa69fc2245b4a5c76e281a4630440220262aaa10b20f98c3d482ba7d1ced4034d3eedacaec8ca4f4d7a370f9cac78494022047c53ce4fc7f666cc30688b5388791fc996734a9b81b296d0cae3cd6313b688620c09a0c30dda887cca892f8ed2d3a22314a7068657667384b646863524c7053557633724351544a35333738415569754d4c40024a20ede5b86c03f7f9fa6fafb6d1d5a63c1f267519f49aa534628d0bc530908ed01e5220b01d5c3248b141de906ffe21571c7c2d9b09d29fc95fa215076d281df6611ec50aa3010a14757365722e702e676d636861696e2e746f6b656e1239380422350a03575842100a1a0853656e64205758422222314a6b624d7135794e4d5a48746f6b6a673558786b4333525a62716a6f504a6d38343098f8cf81bfb996c2543a2231506a4d69397947546a4139626271555a6131536a376441554b794c41384b71453140024a20ede5b86c03f7f9fa6fafb6d1d5a63c1f267519f49aa534628d0bc530908ed01e5220b01d5c3248b141de906ffe21571c7c2d9b09d29fc95fa215076d281df6611ec5",
		Expire:  "1s",
		Index:   2,
	}

	reply := &types.ReplySignRawTx{}
	txhex, err := ProcSignRawTx(req)
	if err != nil {
		fmt.Println("ProcSignRawTx err: ", err.Error())
	} else {
		reply.TxHex = txhex
	}
	return reply, err
}

// CreateNoBalanceTransaction create the transaction with no balance
// 实际使用的时候要注意，一般情况下，不要传递 private key 到服务器端，除非是本地localhost 的服务。
func CreateNoBalanceTransaction(in *types.NoBalanceTx) (*types.Transaction, error) {
	//1.创建none transaction txNone
	/*
		txNone := &types.Transaction{Execer: []byte(types.ExecName(types.NoneX)), Payload: []byte("no-fee-transaction")}
		txNone.To = address.ExecAddress(string(txNone.Execer))
		txNone, err := types.FormatTx(types.ExecName(types.NoneX), txNone)
	*/
	txNone := &types.Transaction{Execer: []byte("user.p.gmchain.none"), Payload: []byte("no-fee-transaction")}
	txNone.To = "1Jphevg8KdhcRLpSUv3rCQTJ5378AUiuML"
	txNone, err := types.FormatTx("user.p.gmchain.none", txNone)

	if err != nil {
		return nil, err
	}
	//2.Unmarshal NoBalanceTx.TxHex
	tx, err := decodeTx(in.TxHex)
	if err != nil {
		return nil, err
	}
	//3.生成交易组，包括txNone, tx
	transactions := []*types.Transaction{txNone, tx}
	feeRate := types.GInt("MinFee")
	/*
		//get proper fee rate
		proper, err := c.GetProperFee(nil)
		if err != nil {
			log.Error("CreateNoBalance", "GetProperFeeErr", err)
			return nil, err
		}
		if proper.GetProperFee() > feeRate {
			feeRate = proper.ProperFee
		}
	*/
	//4.创建组交易，计算总交易费率，组交易的header为第一个子交易的hash,各子交易之间通过next指针关联
	group, err := types.CreateTxGroup(transactions, feeRate)
	if err != nil {
		return nil, err
	}
	//检查费率是否合理，Check height == 0 的时候，不做检查

	//err = group.Check(0, feeRate, types.GInt("MaxFee"))
	err = group.CheckWithFork(false, false, 0, feeRate, types.GInt("MaxFee"))
	if err != nil {
		return nil, err
	}

	//5.marsha(Transactions) ,然后存放至交易组中第一个交易的Header域，返回第一个交易的指针
	newtx := group.Tx()
	//如果可能要做签名  //6.如果设置了代扣地址/私钥，需要签名组交易
	if in.PayAddr != "" || in.Privkey != "" {
		//6.1.marsha(Transaction)
		rawTx := hex.EncodeToString(types.Encode(newtx))
		//6.2.创建ReqSignRawTx
		req := &types.ReqSignRawTx{Addr: in.PayAddr, Privkey: in.Privkey, Expire: in.Expire, TxHex: rawTx, Index: 1}
		//6.3.签名：1）将ReplySignRawTx.TxHex解码成Transaction,
		//signedTx, err := c.SignRawTx(req)
		signedTx, err := ProcSignRawTx(req)
		if err != nil {
			return nil, err
		}
		//fmt.Println("CreateNoBalanceTransaction : ", signedTx)
		//return decodeTx(signedTx.TxHex)
		return decodeTx(signedTx)
	}
	return newtx, nil
}
func decodeTx(hexstr string) (*types.Transaction, error) {
	var tx types.Transaction
	data, err := hex.DecodeString(hexstr)
	if err != nil {
		return nil, err
	}
	err = types.Decode(data, &tx)
	if err != nil {
		return nil, err
	}
	return &tx, nil
}

// CreateRawTransactionNoToken create rawtransaction
func CreateRawTransactionNoToken(param *types.CreateTx) ([]byte, error) {
	if param == nil {
		//log.Error("CreateRawTransaction", "Error", types.ErrInvalidParam)
		return nil, types.ErrInvalidParam
	}
	//构建交易时to地址不为空时需要检测地址的合法性
	if param.GetTo() != "" {
		if err := address.CheckAddress(param.GetTo()); err != nil {
			return nil, types.ErrInvalidAddress
		}
	}
	//因为历史原因，这里还是有部分token 的字段，但是没有依赖token dapp
	//未来这个调用可能会被废弃
	execer := types.ExecName(ety.CoinsX)
	if param.IsToken {
		execer = types.ExecName("token")
	}
	if param.Execer != "" {
		execer = param.Execer
	}
	reply, err := types.CallCreateTx(execer, "", param)
	if err != nil {
		return nil, err
	}

	//add tx fee setting
	tx := &types.Transaction{}
	err = types.Decode(reply, tx)
	if err != nil {
		return nil, err
	}
	tx.Fee = param.Fee
	/*
		//set proper fee if zero fee
		if tx.Fee <= 0 {
			proper, err := c.GetProperFee(nil)
			if err != nil {
				return nil, err
			}
			fee, err := tx.GetRealFee(proper.GetProperFee())
			if err != nil {
				return nil, err
			}
			tx.Fee = fee
		}
	*/
	/*
		查询单元交易费率 Chain33.GetProperFee
		curl -sd '{"method":"Chain33.GetProperFee", "params":[{}]}' http://localhost:8901
		{"id":null,"result":{"properFee":100000},"error":null}
	*/
	if tx.Fee <= 0 {
		//tx.Fee = types.GInt("MinFee")
		tx.Fee = properFee // 需要动态查询单元交易费率 Chain33.GetProperFee
	}
	/*
				 curl -d '{"jsonrpc":"2.0", "method":"Chain33.ConvertExectoAddr",  "params":[{"execname":"user.p.gmchain.coins"}]  }' http://127.0.0.1:8901
				{"id":null,"result":"17hJRNrW9WgFJJ3mhhnnezWydwVLk3SN8y","error":null}
				 curl -d '{"jsonrpc":"2.0", "method":"Chain33.ConvertExectoAddr",  "params":[{"execname":"user.p.gmchain.none"}]  }' http://127.0.0.1:8901
				{"id":null,"result":"1Jphevg8KdhcRLpSUv3rCQTJ5378AUiuML","error":null}
				 curl -d '{"jsonrpc":"2.0", "method":"Chain33.ConvertExectoAddr",  "params":[{"execname":"coins"}]  }' http://127.0.0.1:8901
				{"id":null,"result":"1GaHYpWmqAJsqRwrpoNcB8VvgKtSwjcHqt","error":null}
				 curl -d '{"jsonrpc":"2.0", "method":"Chain33.ConvertExectoAddr",  "params":[{"execname":"none"}]  }' http://127.0.0.1:8901
				{"id":null,"result":"1DzTdTLa5JPpLdNNP2PrV1a6JCtULA7GsT","error":null}
				 curl -d '{"jsonrpc":"2.0", "method":"Chain33.ConvertExectoAddr",  "params":[{"execname":"user.p.gmchain.tokens"}]  }' http://127.0.0.1:8901
				{"id":null,"result":"1My7ojBesp9p7miYPKR5MV5RVZQ5iiZhsU","error":null}
				[root@new-node ~]# curl -d '{"jsonrpc":"2.0", "method":"Chain33.ConvertExectoAddr",  "params":[{"execname":"user.p.gmchain.token"}]  }' http://127.0.0.1:8901
		{"id":null,"result":"1PjMi9yGTjA9bbqUZa1Sj7dAUKyLA8KqE1","error":null}




	*/
	//转账目的地址的区分：user.p.gmchain.coins，user.p.gmchain.tokens , user.p.gmchain.none，coins，none
	if execer == "coins" {
		tx.To = "1GaHYpWmqAJsqRwrpoNcB8VvgKtSwjcHqt" //coins
	} else if execer == "none" {
		tx.To = "1DzTdTLa5JPpLdNNP2PrV1a6JCtULA7GsT" //"none"
	} else if execer == "user.p.gmchain.none" {
		tx.To = "1Jphevg8KdhcRLpSUv3rCQTJ5378AUiuML" //user.p.gmchain.none
	} else if execer == "user.p.gmchain.coins" {
		tx.To = "17hJRNrW9WgFJJ3mhhnnezWydwVLk3SN8y" //user.p.gmchain.coins
	} else if execer == "user.p.gmchain.token" {
		tx.To = "1PjMi9yGTjA9bbqUZa1Sj7dAUKyLA8KqE1" //user.p.gmchain.token
	}

	return types.Encode(tx), nil
}

//following are testing code
// added by liux 2019-08-11
func txCreateNoBalanceTransaction() {
	/*
		ctx := types.NoBalanceTx{
			TxHex:   "0a14757365722e702e676d636861696e2e636f696e73123918010a351080e1eb171a0a73656e6420302e35676d222231504345705248764b45364438536834326f47514247687752374d6377456f645a4d20a08d0630a38fb6a5f3ffec8f393a223137684a524e7257395767464a4a336d68686e6e657a57796477564c6b33534e3879",
			PayAddr: "18bBoM1EnX99pEEByarD9HykUhiy3D94No",                                 //代扣地址
			Privkey: "0x69c9d439c0ccdc5b6f1af2a5014330dbc7cdca17011936b6db5ff325fedb1b89", //代扣地址privkey
			Expire:  "30s",
		}
	*/

	ctx := types.NoBalanceTx{
		TxHex:   "0a14757365722e702e676d636861696e2e746f6b656e1239380422350a03575842100a1a0853656e64205758422222314a6b624d7135794e4d5a48746f6b6a673558786b4333525a62716a6f504a6d383420a08d063098f8cf81bfb996c2543a2231506a4d69397947546a4139626271555a6131536a376441554b794c41384b714531",
		PayAddr: "",                                                                   //代扣地址
		Privkey: "0x273256ea4bbc12d6dfc6d5a52a1ab5e03e3624b5c2948e7212498e629ed7c9d9", //代扣地址privkey
		Expire:  "1s",
	}
	//client := new(channelClient)
	//api := new(mocks.QueueProtocolAPI)
	//client.Init(&qmock.Client{}, api)
	fee := types.GInt("MinFee") * 2
	//api.On("GetProperFee", mock.Anything).Return(&types.ReplyProperFee{ProperFee: fee}, nil)
	//in := &types.NoBalanceTx{}

	//client := newTestChannelClient()

	tx, err := CreateNoBalanceTransaction(&ctx)
	//assert.NoError(t, err)
	gtx, _ := tx.GetTxGroup()

	gtx.Check(0, fee, types.GInt("MaxFee"))
	fmt.Println("txCreateNoBalanceTransaction err: ", err)
	fmt.Println("txCreateNoBalanceTransaction tx: ", tx)
	//assert.NoError(t, gtx.Check(0, fee, types.GInt("MaxFee")))
	//assert.NoError(t, err)
}

func txCreateRawTransactionCoin() ([]byte, error) {
	/*
		//transfer  coins
		ctx := types.CreateTx{
			ExecName:   "",
			Amount:     10,
			IsToken:    false,
			IsWithdraw: false,
			To:         "1JkbMq5yNMZHtokjg5XxkC3RZbqjoPJm84",
			//Note:       []byte("note"),
			Fee: 100000,
		}
		//txHex:  0a05636f696e73122a18010a26100a2222314a6b624d7135794e4d5a48746f6b6a673558786b4333525a62716a6f504a6d383420a08d0630eae4e5deed948593403a22314761485970576d71414a7371527772706f4e6342385676674b7453776a63487174
	*/

	//transfer  GM
	ctx := types.CreateTx{
		ExecName:   "",
		Execer:     "user.p.gmchain.coins",
		Amount:     50000000,
		IsToken:    false,
		IsWithdraw: false,
		To:         "1PCEpRHvKE6D8Sh42oGQBGhwR7McwEodZM",
		Note:       []byte("send 0.5gm"),
		//Fee:        100000,
	}
	//txHex:  0a14757365722e702e676d636861696e2e636f696e73123918010a351080e1eb171a0a73656e6420302e35676d222231504345705248764b45364438536834326f47514247687752374d6377456f645a4d20a08d0630faa1c1e788eb9ca1203a223137684a524e7257395767464a4a336d68686e6e657a57796477564c6b33534e3879

	/*
		//transfer  WXB
		ctx := types.CreateTx{
			ExecName:    "",
			Execer:      "user.p.gmchain.token",
			Amount:      10,
			IsToken:     true,
			TokenSymbol: "WXB",
			IsWithdraw:  false,
			To:          "1JkbMq5yNMZHtokjg5XxkC3RZbqjoPJm84",
			Note:        []byte("Send WXB"),
			//Fee:        100000,
		}
	*/
	//client := newTestChannelClient()
	txHex, err := CreateRawTransactionNoToken(&ctx)
	fmt.Println("txCreateRawTransactionCoinTransfer err: ", err)
	fmt.Println("txHex: ", hex.EncodeToString(txHex)) // added by liux
	//assert.Nil(t, err)
	var tx types.Transaction
	types.Decode(txHex, &tx)
	//assert.Equal(t, []byte(types.ExecName(cty.CoinsX)), tx.Execer)

	var transfer ety.CoinsAction
	types.Decode(tx.Payload, &transfer)
	fmt.Println("tx.Payload: ", transfer) // added by liux
	//assert.Equal(t, int32(cty.CoinsActionTransfer), transfer.Ty)

	return txHex, err
}

func decodeSignRawTx() {

	var inSignRawTx []byte

	// 定义一个空的结构体
	signRawTx := &types.Transaction{}
	// 将从文件中读取的二进制进行反序列化
	inSignRawTx = []byte{0x0A, 0x13, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x70, 0x2E, 0x67, 0x6D, 0x63, 0x68, 0x61, 0x69, 0x6E, 0x2E, 0x6E, 0x6F, 0x6E, 0x65, 0x12, 0x12, 0x6E, 0x6F, 0x2D, 0x66, 0x65, 0x65, 0x2D, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x1A, 0x6D, 0x08, 0x01, 0x12, 0x21, 0x02, 0x27, 0x12, 0x5E, 0x6B, 0xAC, 0xA0, 0xB6, 0xAD, 0x52, 0x4E, 0x83, 0x3F, 0xEC, 0xCF, 0x7C, 0x5A, 0x85, 0xD5, 0xC0, 0xE1, 0xF4, 0x35, 0x12, 0x85, 0xAB, 0x51, 0xDB, 0x9F, 0x4D, 0x84, 0xFB, 0xE2, 0x1A, 0x46, 0x30, 0x44, 0x02, 0x20, 0x12, 0xD5, 0x9E, 0xFE, 0xAA, 0x15, 0x3A, 0x74, 0x51, 0x08, 0x60, 0xCD, 0x47, 0x9D, 0x85, 0x9A, 0x1B, 0x0B, 0xE4, 0x17, 0x22, 0xBB, 0xA5, 0xF1, 0xD7, 0xA0, 0x77, 0x91, 0x0C, 0xFF, 0xE1, 0xBD, 0x02, 0x20, 0x78, 0x66, 0xBA, 0xFD, 0x0D, 0xD6, 0x2F, 0x9C, 0x57, 0x86, 0x0C, 0x32, 0x35, 0x99, 0x66, 0x21, 0x15, 0x54, 0x19, 0x83, 0x41, 0xCB, 0xAD, 0x4A, 0x6E, 0x0A, 0xE6, 0xC5, 0xF8, 0x69, 0xB5, 0x98, 0x20, 0xC0, 0x9A, 0x0C, 0x30, 0xD7, 0xB5, 0x9F, 0xC8, 0xC7, 0xA2, 0xF9, 0xC5, 0x75, 0x3A, 0x22, 0x31, 0x4A, 0x70, 0x68, 0x65, 0x76, 0x67, 0x38, 0x4B, 0x64, 0x68, 0x63, 0x52, 0x4C, 0x70, 0x53, 0x55, 0x76, 0x33, 0x72, 0x43, 0x51, 0x54, 0x4A, 0x35, 0x33, 0x37, 0x38, 0x41, 0x55, 0x69, 0x75, 0x4D, 0x4C, 0x40, 0x02, 0x4A, 0xA9, 0x04, 0x0A, 0x90, 0x02, 0x0A, 0x13, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x70, 0x2E, 0x67, 0x6D, 0x63, 0x68, 0x61, 0x69, 0x6E, 0x2E, 0x6E, 0x6F, 0x6E, 0x65, 0x12, 0x12, 0x6E, 0x6F, 0x2D, 0x66, 0x65, 0x65, 0x2D, 0x74, 0x72, 0x61, 0x6E, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x1A, 0x6D, 0x08, 0x01, 0x12, 0x21, 0x02, 0x27, 0x12, 0x5E, 0x6B, 0xAC, 0xA0, 0xB6, 0xAD, 0x52, 0x4E, 0x83, 0x3F, 0xEC, 0xCF, 0x7C, 0x5A, 0x85, 0xD5, 0xC0, 0xE1, 0xF4, 0x35, 0x12, 0x85, 0xAB, 0x51, 0xDB, 0x9F, 0x4D, 0x84, 0xFB, 0xE2, 0x1A, 0x46, 0x30, 0x44, 0x02, 0x20, 0x12, 0xD5, 0x9E, 0xFE, 0xAA, 0x15, 0x3A, 0x74, 0x51, 0x08, 0x60, 0xCD, 0x47, 0x9D, 0x85, 0x9A, 0x1B, 0x0B, 0xE4, 0x17, 0x22, 0xBB, 0xA5, 0xF1, 0xD7, 0xA0, 0x77, 0x91, 0x0C, 0xFF, 0xE1, 0xBD, 0x02, 0x20, 0x78, 0x66, 0xBA, 0xFD, 0x0D, 0xD6, 0x2F, 0x9C, 0x57, 0x86, 0x0C, 0x32, 0x35, 0x99, 0x66, 0x21, 0x15, 0x54, 0x19, 0x83, 0x41, 0xCB, 0xAD, 0x4A, 0x6E, 0x0A, 0xE6, 0xC5, 0xF8, 0x69, 0xB5, 0x98, 0x20, 0xC0, 0x9A, 0x0C, 0x30, 0xD7, 0xB5, 0x9F, 0xC8, 0xC7, 0xA2, 0xF9, 0xC5, 0x75, 0x3A, 0x22, 0x31, 0x4A, 0x70, 0x68, 0x65, 0x76, 0x67, 0x38, 0x4B, 0x64, 0x68, 0x63, 0x52, 0x4C, 0x70, 0x53, 0x55, 0x76, 0x33, 0x72, 0x43, 0x51, 0x54, 0x4A, 0x35, 0x33, 0x37, 0x38, 0x41, 0x55, 0x69, 0x75, 0x4D, 0x4C, 0x40, 0x02, 0x4A, 0x20, 0x31, 0x80, 0x96, 0xE1, 0x82, 0xC7, 0x5F, 0x73, 0x81, 0xDF, 0xA5, 0xF0, 0x1D, 0x81, 0x41, 0xCB, 0xDE, 0x44, 0xAB, 0x1D, 0x81, 0x1F, 0x63, 0x20, 0xB5, 0x80, 0x35, 0xF9, 0xB5, 0xD7, 0x7E, 0x51, 0x52, 0x20, 0xE8, 0x23, 0x1B, 0x6F, 0x1F, 0xA5, 0x8C, 0x51, 0x48, 0xA4, 0x27, 0x85, 0xE2, 0xDB, 0x26, 0x70, 0x83, 0x65, 0x9F, 0x0B, 0x3F, 0xCD, 0xE3, 0x24, 0xC9, 0x53, 0xA8, 0x0E, 0xC5, 0x24, 0x23, 0x62, 0x0A, 0x93, 0x02, 0x0A, 0x14, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x70, 0x2E, 0x67, 0x6D, 0x63, 0x68, 0x61, 0x69, 0x6E, 0x2E, 0x63, 0x6F, 0x69, 0x6E, 0x73, 0x12, 0x39, 0x18, 0x01, 0x0A, 0x35, 0x10, 0x80, 0xE1, 0xEB, 0x17, 0x1A, 0x0A, 0x73, 0x65, 0x6E, 0x64, 0x20, 0x30, 0x2E, 0x35, 0x67, 0x6D, 0x22, 0x22, 0x31, 0x50, 0x43, 0x45, 0x70, 0x52, 0x48, 0x76, 0x4B, 0x45, 0x36, 0x44, 0x38, 0x53, 0x68, 0x34, 0x32, 0x6F, 0x47, 0x51, 0x42, 0x47, 0x68, 0x77, 0x52, 0x37, 0x4D, 0x63, 0x77, 0x45, 0x6F, 0x64, 0x5A, 0x4D, 0x1A, 0x6E, 0x08, 0x01, 0x12, 0x21, 0x02, 0x27, 0x12, 0x5E, 0x6B, 0xAC, 0xA0, 0xB6, 0xAD, 0x52, 0x4E, 0x83, 0x3F, 0xEC, 0xCF, 0x7C, 0x5A, 0x85, 0xD5, 0xC0, 0xE1, 0xF4, 0x35, 0x12, 0x85, 0xAB, 0x51, 0xDB, 0x9F, 0x4D, 0x84, 0xFB, 0xE2, 0x1A, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xED, 0x68, 0xDD, 0x39, 0x17, 0x6E, 0x33, 0x3C, 0x45, 0xF2, 0x97, 0x12, 0x3B, 0xFA, 0x6A, 0xE3, 0x5A, 0x73, 0xFE, 0x4E, 0x18, 0x9D, 0x79, 0x51, 0x8A, 0x3E, 0x2C, 0x80, 0x5F, 0x6A, 0xE6, 0xE6, 0x02, 0x20, 0x61, 0xD0, 0xFC, 0xD2, 0xAB, 0xB7, 0x8B, 0xB4, 0x92, 0xC8, 0x69, 0x18, 0xDE, 0x1E, 0x24, 0xD5, 0x93, 0x0D, 0x2F, 0x2D, 0xDF, 0x66, 0x4A, 0x8A, 0x71, 0x63, 0xFD, 0x61, 0x37, 0x60, 0x47, 0x56, 0x30, 0xA3, 0x8F, 0xB6, 0xA5, 0xF3, 0xFF, 0xEC, 0x8F, 0x39, 0x3A, 0x22, 0x31, 0x37, 0x68, 0x4A, 0x52, 0x4E, 0x72, 0x57, 0x39, 0x57, 0x67, 0x46, 0x4A, 0x4A, 0x33, 0x6D, 0x68, 0x68, 0x6E, 0x6E, 0x65, 0x7A, 0x57, 0x79, 0x64, 0x77, 0x56, 0x4C, 0x6B, 0x33, 0x53, 0x4E, 0x38, 0x79, 0x40, 0x02, 0x4A, 0x20, 0x31, 0x80, 0x96, 0xE1, 0x82, 0xC7, 0x5F, 0x73, 0x81, 0xDF, 0xA5, 0xF0, 0x1D, 0x81, 0x41, 0xCB, 0xDE, 0x44, 0xAB, 0x1D, 0x81, 0x1F, 0x63, 0x20, 0xB5, 0x80, 0x35, 0xF9, 0xB5, 0xD7, 0x7E, 0x51, 0x52, 0x20, 0xE8, 0x23, 0x1B, 0x6F, 0x1F, 0xA5, 0x8C, 0x51, 0x48, 0xA4, 0x27, 0x85, 0xE2, 0xDB, 0x26, 0x70, 0x83, 0x65, 0x9F, 0x0B, 0x3F, 0xCD, 0xE3, 0x24, 0xC9, 0x53, 0xA8, 0x0E, 0xC5, 0x24, 0x23, 0x62}
	// fmt.Println("inSignRawTx: ",inSignRawTx)

	// fmt.Println(str)

	if err := proto.Unmarshal(inSignRawTx, signRawTx); err != nil {
		log.Fatalln("Failed to parse inSignRawTx:", err)
	}

	fmt.Println("signRawTx: ", signRawTx)

}

func encodeGMTransfer() {

	// 自定义AssetsTransfer内容
	assetsTransfer := types.AssetsTransfer{
		Cointoken: "",
		Amount:    50000000,                                                           // *proto.int64(50000000),
		Note:      []byte{0x73, 0x65, 0x6E, 0x64, 0x20, 0x30, 0x2E, 0x35, 0x67, 0x6D}, // *proto.[]byte{0x73,0x65,0x6E,0x64,0x20,0x30,0x2E,0x35,0x67,0x6D}, //send 0.5gm
		To:        "1PCEpRHvKE6D8Sh42oGQBGhwR7McwEodZM",                               // *proto.string("1PCEpRHvKE6D8Sh42oGQBGhwR7McwEodZM"),
	}
	fmt.Println("\n assetsTransfer : ", assetsTransfer)
	// 将assetsTransfer进行序列化
	out_assetsTransfer, err := proto.Marshal(&assetsTransfer)
	if err != nil {
		log.Fatalln("Failed to encode assetsTransfer:", err)
	}
	var len int
	fmt.Println("\n out_assetsTransfer: ")
	for i, x := range out_assetsTransfer {
		fmt.Printf("0x%02x,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

	// 自定义CoinsAction_Transfer内容
	coinsAction_Transfer := ety.CoinsAction_Transfer{
		Transfer: &assetsTransfer, //

	}
	fmt.Println("\n coinsAction_Transfer : ", coinsAction_Transfer)
	/*
	   	// 将coinsAction_Transfer进行序列化
	       out_coinsAction_Transfer, err := proto.Marshal(&coinsAction_Transfer)
	   	if err != nil {
	           log.Fatalln("Failed to encode coinsAction_Transfer:", err)
	       }
	   	var len int
	   	fmt.Println("\n out_coinsAction_Transfer: ")
	       for i,x:= range out_coinsAction_Transfer {
	         fmt.Printf("0x%02x,", x)
	   	  len = i
	       }
	       fmt.Println("\n")
	       fmt.Println("len=%d\n",len)
	*/

	// 自定义CoinsAction内容
	/*
			const (
			// CoinsActionTransfer defines const number
			CoinsActionTransfer = 1
			// CoinsActionGenesis  defines const coinsactiongenesis number
			CoinsActionGenesis = 2
			// CoinsActionWithdraw defines const number coinsactionwithdraw
			CoinsActionWithdraw = 3
			// CoinsActionTransferToExec defines const number coinsactiontransfertoExec
			CoinsActionTransferToExec = 10
		    )
	*/
	coinsAction := ety.CoinsAction{
		Value: &coinsAction_Transfer, //out_coinsAction_Transfer,  //
		Ty:    1,                     // CoinsActionTransfer = 1
	}
	fmt.Println("\n coinsAction : ", coinsAction)
	// 将coinsAction进行序列化
	out_coinsAction, err := proto.Marshal(&coinsAction)
	if err != nil {
		log.Fatalln("Failed to encode coinsAction:", err)
	}
	//var len int
	fmt.Println("\n out_coinsAction: ")
	for i, x := range out_coinsAction {
		fmt.Printf("0x%02x,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

	// 自定义Transaction内容
	new_transaction := types.Transaction{
		//Execer:    []byte{0x75,0x73,0x65,0x72,0x2E,0x70,0x2E,0x67,0x6D,0x63,0x68,0x61,0x69,0x6E,0x2E,0x63,0x6F,0x69,0x6E,0x73}, // user.p.gmchain.coins
		Execer:  []byte("user.p.gmchain.coins"),
		Payload: out_coinsAction, // payload_in,
		// Payload:   []byte{0x18,0x01,0x0A,0x35,0x10,0x80,0xE1,0xEB,0x17,0x1A,0x0A,0x73,0x65,0x6E,0x64,0x20,0x30,0x2E,0x35,0x67,0x6D,0x22,0x22,0x31,0x50,0x43,0x45,0x70,0x52,0x48,0x76,0x4B,0x45,0x36,0x44,0x38,0x53,0x68,0x34,0x32,0x6F,0x47,0x51,0x42,0x47,0x68,0x77,0x52,0x37,0x4D,0x63,0x77,0x45,0x6F,0x64,0x5A,0x4D},
		Fee: 100000,
		//随机ID，可以防止payload 相同的时候，交易重复
		Nonce: 4116206493121742755,
		//对方地址，如果没有对方地址，可以为空,此地址是执行器的地址
		To: "17hJRNrW9WgFJJ3mhhnnezWydwVLk3SN8y",
	}

	fmt.Println("\n new_transaction : ", new_transaction)

	// 将new_transaction进行序列化
	out_transaction, err := proto.Marshal(&new_transaction)
	if err != nil {
		log.Fatalln("Failed to encode new_transaction:", err)
	}
	// var len int
	fmt.Println("\n out_transaction: ")
	for i, x := range out_transaction {
		fmt.Printf("0x%02x,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

}

func txSendtoaddr() {

	// 自定义AssetsTransfer内容
	assetsTransfer := types.AssetsTransfer{
		Cointoken: "",
		Amount:    1000, // *proto.int64(50000000),
		Note:      []byte("test"),
		To:        "1L1zEgVcjqdM2KkQixENd7SZTaudKkcyDu", // *proto.string("1PCEpRHvKE6D8Sh42oGQBGhwR7McwEodZM"),
	}
	fmt.Println("\n assetsTransfer : ", assetsTransfer)
	// 将assetsTransfer进行序列化
	out_assetsTransfer, err := proto.Marshal(&assetsTransfer)
	if err != nil {
		log.Fatalln("Failed to encode assetsTransfer:", err)
	}
	var len int
	fmt.Println("\n out_assetsTransfer: ")
	for i, x := range out_assetsTransfer {
		fmt.Printf("0x%02x,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

	// 自定义CoinsAction_Transfer内容
	coinsAction_Transfer := ety.CoinsAction_Transfer{
		Transfer: &assetsTransfer, //

	}
	fmt.Println("\n coinsAction_Transfer : ", coinsAction_Transfer)
	/*
	   	// 将coinsAction_Transfer进行序列化
	       out_coinsAction_Transfer, err := proto.Marshal(&coinsAction_Transfer)
	   	if err != nil {
	           log.Fatalln("Failed to encode coinsAction_Transfer:", err)
	       }
	   	var len int
	   	fmt.Println("\n out_coinsAction_Transfer: ")
	       for i,x:= range out_coinsAction_Transfer {
	         fmt.Printf("0x%02x,", x)
	   	  len = i
	       }
	       fmt.Println("\n")
	       fmt.Println("len=%d\n",len)
	*/

	// 自定义CoinsAction内容
	/*
			const (
			// CoinsActionTransfer defines const number
			CoinsActionTransfer = 1
			// CoinsActionGenesis  defines const coinsactiongenesis number
			CoinsActionGenesis = 2
			// CoinsActionWithdraw defines const number coinsactionwithdraw
			CoinsActionWithdraw = 3
			// CoinsActionTransferToExec defines const number coinsactiontransfertoExec
			CoinsActionTransferToExec = 10
		    )
	*/
	coinsAction := ety.CoinsAction{
		Value: &coinsAction_Transfer, //out_coinsAction_Transfer,  //
		Ty:    1,                     // CoinsActionTransfer = 1
	}
	fmt.Println("\n coinsAction : ", coinsAction)
	// 将coinsAction进行序列化
	out_coinsAction, err := proto.Marshal(&coinsAction)
	if err != nil {
		log.Fatalln("Failed to encode coinsAction:", err)
	}
	//var len int
	fmt.Println("\n out_coinsAction: ")
	for i, x := range out_coinsAction {
		//fmt.Printf("0x%02x,", x)
		fmt.Printf("%d,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

	// var payload_in  []byte
	// payload_in =  out_assetsTransfer
	// 自定义Transaction内容
	tx := types.Transaction{
		//Execer:    []byte{0x75,0x73,0x65,0x72,0x2E,0x70,0x2E,0x67,0x6D,0x63,0x68,0x61,0x69,0x6E,0x2E,0x63,0x6F,0x69,0x6E,0x73}, // user.p.gmchain.coins
		Execer:  []byte("coins"),
		Payload: out_coinsAction, // payload_in,
		// Payload:   []byte{0x18,0x01,0x0A,0x35,0x10,0x80,0xE1,0xEB,0x17,0x1A,0x0A,0x73,0x65,0x6E,0x64,0x20,0x30,0x2E,0x35,0x67,0x6D,0x22,0x22,0x31,0x50,0x43,0x45,0x70,0x52,0x48,0x76,0x4B,0x45,0x36,0x44,0x38,0x53,0x68,0x34,0x32,0x6F,0x47,0x51,0x42,0x47,0x68,0x77,0x52,0x37,0x4D,0x63,0x77,0x45,0x6F,0x64,0x5A,0x4D},
		Signature: nil,
		Fee:       100000,
		Expire:    1565531653,
		//随机ID，可以防止payload 相同的时候，交易重复
		Nonce: 7336920907551247539,
		//对方地址，如果没有对方地址，可以为空,此地址是执行器的地址
		To: "1L1zEgVcjqdM2KkQixENd7SZTaudKkcyDu",
	}

	fmt.Println("\n tx : ", tx)

	// 将tx进行序列化
	out_transaction, err := proto.Marshal(&tx)
	if err != nil {
		log.Fatalln("Failed to encode tx:", err)
	}
	// var len int
	fmt.Println("\n out_transaction: ")
	for i, x := range out_transaction {
		fmt.Printf("0x%02x,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

	//var priv crypto.PrivKey
	var privkeyData []byte
	privkeyData = []byte{185, 74, 226, 134, 165, 8, 228, 187, 63, 187, 203, 97, 153, 120, 34, 254, 166, 240, 165, 52, 81, 5, 151, 239, 142, 182, 10, 25, 214, 178, 25, 160}

	//通过privkey生成一个pubkey然后换算成对应的addr
	var SignType int
	var ty int32
	SignType = 1
	ty = 1
	cr, err := crypto.New(types.GetSignName("", SignType))
	if err != nil {
		//walletlog.Error("getPrivKeyByAddr", "err", err)
		fmt.Println("crypto.New  err\n")
		return
	}
	priv, err := cr.PrivKeyFromBytes(privkeyData)
	if err != nil {
		//walletlog.Error("getPrivKeyByAddr", "PrivKeyFromBytes err", err)
		fmt.Println("cr.PrivKeyFromBytes err\n")
		return
	}

	tx.Signature = nil
	data := types.Encode(&tx)
	fmt.Println("data: ", data)
	pub := priv.PubKey()
	fmt.Println("pub: ", pub)
	fmt.Println("priv: ", priv)
	sign := priv.Sign(data)
	fmt.Println("sign: ", sign)
	tx.Signature = &types.Signature{
		Ty:        ty,
		Pubkey:    pub.Bytes(),
		Signature: sign.Bytes(),
	}
	fmt.Println("tx.Signature.Signature: ", tx.Signature.Signature)

	// 将tx进行序列化
	out_tx, err := proto.Marshal(&tx)
	if err != nil {
		log.Fatalln("Failed to encode tx:", err)
	}
	// var len int
	fmt.Println("\n out_tx: ")
	for i, x := range out_tx {
		fmt.Printf("0x%02x,", x)
		len = i
	}
	fmt.Println("\n")
	fmt.Println("len=%d\n", len)

}

func decodeTxTokenWXB() {

	var in []byte

	// 定义一个空的结构体
	Tx := &types.Transaction{}
	// 将从文件中读取的二进制进行反序列化
	//from online
	in = []byte{0x0A, 0x14, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x70, 0x2E, 0x67, 0x6D, 0x63, 0x68, 0x61, 0x69, 0x6E, 0x2E, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x12, 0x39, 0x38, 0x04, 0x22, 0x35, 0x0A, 0x03, 0x57, 0x58, 0x42, 0x10, 0x0A, 0x1A, 0x08, 0x53, 0x65, 0x6E, 0x64, 0x20, 0x57, 0x58, 0x42, 0x22, 0x22, 0x31, 0x4A, 0x6B, 0x62, 0x4D, 0x71, 0x35, 0x79, 0x4E, 0x4D, 0x5A, 0x48, 0x74, 0x6F, 0x6B, 0x6A, 0x67, 0x35, 0x58, 0x78, 0x6B, 0x43, 0x33, 0x52, 0x5A, 0x62, 0x71, 0x6A, 0x6F, 0x50, 0x4A, 0x6D, 0x38, 0x34, 0x20, 0xA0, 0x8D, 0x06, 0x30, 0xF4, 0xE1, 0x80, 0x85, 0xDE, 0xE2, 0xAF, 0xAF, 0x05, 0x3A, 0x22, 0x31, 0x50, 0x6A, 0x4D, 0x69, 0x39, 0x79, 0x47, 0x54, 0x6A, 0x41, 0x39, 0x62, 0x62, 0x71, 0x55, 0x5A, 0x61, 0x31, 0x53, 0x6A, 0x37, 0x64, 0x41, 0x55, 0x4B, 0x79, 0x4C, 0x41, 0x38, 0x4B, 0x71, 0x45, 0x31}
	//from offline
	//in = []byte{0x0A, 0x14, 0x75, 0x73, 0x65, 0x72, 0x2E, 0x70, 0x2E, 0x67, 0x6D, 0x63, 0x68, 0x61, 0x69, 0x6E, 0x2E, 0x74, 0x6F, 0x6B, 0x65, 0x6E, 0x12, 0x39, 0x18, 0x03, 0x22, 0x35, 0x0A, 0x03, 0x57, 0x58, 0x42, 0x10, 0x0A, 0x1A, 0x08, 0x53, 0x65, 0x6E, 0x64, 0x20, 0x57, 0x58, 0x42, 0x2A, 0x22, 0x31, 0x4A, 0x6B, 0x62, 0x4D, 0x71, 0x35, 0x79, 0x4E, 0x4D, 0x5A, 0x48, 0x74, 0x6F, 0x6B, 0x6A, 0x67, 0x35, 0x58, 0x78, 0x6B, 0x43, 0x33, 0x52, 0x5A, 0x62, 0x71, 0x6A, 0x6F, 0x50, 0x4A, 0x6D, 0x38, 0x34, 0x20, 0xA0, 0x8D, 0x06, 0x30, 0xF4, 0xE1, 0x80, 0x85, 0xDE, 0xE2, 0xAF, 0xAF, 0x05, 0x3A, 0x22, 0x31, 0x50, 0x6A, 0x4D, 0x69, 0x39, 0x79, 0x47, 0x54, 0x6A, 0x41, 0x39, 0x62, 0x62, 0x71, 0x55, 0x5A, 0x61, 0x31, 0x53, 0x6A, 0x37, 0x64, 0x41, 0x55, 0x4B, 0x79, 0x4C, 0x41, 0x38, 0x4B, 0x71, 0x45, 0x31}
	//decodeTransaction:  execer:"user.p.gmchain.token" payload:"8\004\"5\n\003WXB\020\n\032\010Send WXB\"\"1JkbMq5yNMZHtokjg5XxkC3RZbqjoPJm84" fee:100000 nonce:386956718684254452 to:"1PjMi9yGTjA9bbqUZa1Sj7dAUKyLA8KqE1"
	//decodeTransaction Tx.Payload:   withdraw:<cointoken:"WXB" amount:10 note:"Send WXB" execName:"1JkbMq5yNMZHtokjg5XxkC3RZbqjoPJm84" > 7:4
	// fmt.Println("inSignRawTx: ",inSignRawTx)

	// fmt.Println(str)

	if err := proto.Unmarshal(in, Tx); err != nil {
		log.Fatalln("Failed to parse Transaction:", err)
	}

	fmt.Println("decodeTransaction: ", Tx)

	coinsAction := &ety.CoinsAction{}

	if err := proto.Unmarshal(Tx.Payload, coinsAction); err != nil {
		log.Fatalln("Failed to parse Tx.Payload:", err)
	}

	fmt.Println("decodeTransaction Tx.Payload:  ", coinsAction)

	//coinsActionWithdraw := &ety.CoinsAction_Withdraw{}
	var coinsActionWithdraw *ety.CoinsAction_Withdraw

	//var coinsActionWithdraw ety.isCoinsAction_Value
	//coinsActionWithdraw := &ety.CoinsAction_Withdraw{}
	coinsActionWithdraw = (coinsAction.Value).(*ety.CoinsAction_Withdraw) //golang将interface{}转换为struct
	//coinsActionWithdraw := coinsAction.Value
	fmt.Println("decodeTransaction coinsAction.Value:  ", coinsActionWithdraw)

	//assetWithdraw := &types.AssetsWithdraw{}

	var assetWithdraw *types.AssetsWithdraw
	assetWithdraw = coinsActionWithdraw.Withdraw
	fmt.Println("decodeTransaction coinsActionWithdraw.Withdraw:  ", assetWithdraw)

	//assetWithdraw = coinsActionWithdraw.isCoinsAction_Value()
	//assetWithdraw = coinsAction.Value

	//fmt.Println("decodeTransaction coinsActionWithdraw.Withdraw:  ", assetWithdraw)

	/*
			if err := proto.Unmarshal(coinsAction.Value, coinsActionWithdraw); err != nil {
				log.Fatalln("Failed to parse coinsAction.Value:", err)
			}

			fmt.Println("decodeTransaction coinsAction.Value:  ", coinsActionWithdraw)

		//assetTransfer := &types.AssetsTransfer{}

		//coinsActionWithdraw := coinsAction.Value
		assetWithdraw := &types.AssetsWithdraw{}

		if err := proto.Unmarshal(coinsActionWithdraw.isCoinsAction_Value(), assetWithdraw); err != nil {
			//if err := proto.Unmarshal(coinsAction.Value, assetTransfer); err != nil {
			log.Fatalln("Failed to parse coinsAction.Value:", err)
		}

		fmt.Println("decodeTransaction coinsActionWithdraw.Withdraw:  ", assetWithdraw)
	*/
}

func encodeTxTokenWXB() {

	// 自定义AssetsWithdraw内容
	assetWithdraw := types.AssetsWithdraw{
		Cointoken: "WXB",
		Amount:    10, // *proto.int64(10),
		Note:      []byte("Send WXB"),
		ExecName:  "",
		To:        "1JkbMq5yNMZHtokjg5XxkC3RZbqjoPJm84", // *proto.string("1JkbMq5yNMZHtokjg5XxkC3RZbqjoPJm84"),

	}
	fmt.Println("\n assetWithdraw : ", assetWithdraw)
	/*
		// 将assetsTransfer进行序列化
		out_assetsTransfer, err := proto.Marshal(&assetsTransfer)
		if err != nil {
			log.Fatalln("Failed to encode assetsTransfer:", err)
		}
		var len int
		fmt.Println("\n out_assetsTransfer: ")
		for i, x := range out_assetsTransfer {
			fmt.Printf("0x%02x,", x)
			len = i
		}
		fmt.Println("\n")
		fmt.Println("len=%d\n", len)
	*/
	// 自定义CoinsAction_Transfer内容
	coinsAction_Withdraw := ety.CoinsAction_Withdraw{
		Withdraw: &assetWithdraw, //

	}

	fmt.Println("\n coinsAction_Withdraw : ", coinsAction_Withdraw)
	/*
	   	// 将coinsAction_Transfer进行序列化
	       out_coinsAction_Transfer, err := proto.Marshal(&coinsAction_Transfer)
	   	if err != nil {
	           log.Fatalln("Failed to encode coinsAction_Transfer:", err)
	       }
	   	var len int
	   	fmt.Println("\n out_coinsAction_Transfer: ")
	       for i,x:= range out_coinsAction_Transfer {
	         fmt.Printf("0x%02x,", x)
	   	  len = i
	       }
	       fmt.Println("\n")
	       fmt.Println("len=%d\n",len)
	*/

	// 自定义CoinsAction内容
	/*
			const (
			// CoinsActionTransfer defines const number
			CoinsActionTransfer = 1
			// CoinsActionGenesis  defines const coinsactiongenesis number
			CoinsActionGenesis = 2
			// CoinsActionWithdraw defines const number coinsactionwithdraw
			CoinsActionWithdraw = 3
			// CoinsActionTransferToExec defines const number coinsactiontransfertoExec
			CoinsActionTransferToExec = 10
		    )
	*/
	coinsAction := ety.CoinsAction{
		Value: &coinsAction_Withdraw, //out_coinsAction_Transfer,  //
		Ty:    3,                     // CoinsActionTransfer = 1
	}
	fmt.Println("\n coinsAction : ", coinsAction)
	// 将coinsAction进行序列化
	coinsActionHex, err := proto.Marshal(&coinsAction)
	if err != nil {
		log.Fatalln("Failed to encode coinsAction:", err)
	}

	fmt.Println("coinsActionHex: ", hex.EncodeToString(coinsActionHex))

	// 自定义Transaction内容
	tx := types.Transaction{
		Execer:  []byte("user.p.gmchain.token"),
		Payload: coinsActionHex,
		Fee:     100000,
		//随机ID，可以防止payload 相同的时候，交易重复
		Nonce: 386956718684254452,
		//对方地址，如果没有对方地址，可以为空,此地址是执行器的地址
		To: "1PjMi9yGTjA9bbqUZa1Sj7dAUKyLA8KqE1", //执行器user.p.gmchain.token的地址
	}

	fmt.Println("\n tx : ", tx)

	// 将new_transaction进行序列化
	txHex, err := proto.Marshal(&tx)
	if err != nil {
		log.Fatalln("Failed to encode tx:", err)
	}
	fmt.Println("txHex: ", hex.EncodeToString(txHex)) // added by liux

}

func cmdParse(method string, params string) *Response {

	var response Response
	//fmt.Println("cmdParse method: ", method)
	//fmt.Println("cmdParse params: ", params)

	if method == "Chain33.CreateNoBalanceTransaction" {
		var rpcCmd ParamsCreateNoBalanceTransaction
		err := json.Unmarshal([]byte(params), &rpcCmd)
		if err != nil {
			fmt.Println("error:", err)
			response.Error = err.Error()
		} else {
			//fmt.Printf("%+v", rpcCmd)

			ctx := types.NoBalanceTx{
				TxHex:   rpcCmd.TxHex,   //,
				PayAddr: "",             //代扣地址
				Privkey: rpcCmd.Privkey, //代扣地址privkey
				Expire:  rpcCmd.Expire,  //"1s",
			}

			tx, err := CreateNoBalanceTransaction(&ctx)
			txHex := hex.EncodeToString(types.Encode(tx))
			//fee := types.GInt("MinFee") * 2
			//gtx, _ := tx.GetTxGroup()
			//gtx.Check(0, fee, types.GInt("MaxFee"))

			//var response Response
			if err == nil {
				response.Result = txHex
			} else {
				response.Error = err.Error()
			}
		}

	} else if method == "Chain33.SignRawTx" {
		var rpcCmd ParamsSignRawTx
		err := json.Unmarshal([]byte(params), &rpcCmd)
		if err != nil {
			fmt.Println("error:", err)
			response.Error = err.Error()
		} else {
			//fmt.Printf("%+v", rpcCmd)

			ctx := &types.ReqSignRawTx{
				//Addr:    "1D65zcQYGeQQATdjSBkMfTWQvhzJUeeaNc",
				Privkey: rpcCmd.Privkey,
				TxHex:   rpcCmd.TxHex,
				Expire:  rpcCmd.Expire, //"1s",
				Index:   rpcCmd.Index,
			}

			txHex, err := ProcSignRawTx(ctx)
			//var response Response
			if err == nil {
				response.Result = txHex
			} else {
				response.Error = err.Error()
			}
		}

	} else if method == "Chain33.CreateRawTransactionNoToken" {
		var rpcCmd ParamsCreateRawTransactionNoToken
		err := json.Unmarshal([]byte(params), &rpcCmd)
		if err != nil {
			fmt.Println("error:", err)
			response.Error = err.Error()
		} else {
			//fmt.Printf("%+v", rpcCmd)

			//transfer  BTY GM ,can't transfer Token such as WXB,JCB
			ctx := types.CreateTx{
				ExecName:   "",
				Execer:     rpcCmd.Execer, //"user.p.gmchain.coins",
				Amount:     rpcCmd.Amount, //50000000,
				IsToken:    false,
				IsWithdraw: false,
				To:         rpcCmd.To,           //"1PCEpRHvKE6D8Sh42oGQBGhwR7McwEodZM",
				Note:       []byte(rpcCmd.Note), //[]byte("send 0.5gm"),
				//Fee:        100000,
			}

			txBytes, err := CreateRawTransactionNoToken(&ctx)
			txHex := hex.EncodeToString(txBytes)
			//fmt.Println("CreateRawTransactionNoToken err: ", err)
			//fmt.Println("cmdParse txHex: ", txHex)
			if err == nil {
				response.Result = txHex
			} else {
				response.Error = err.Error()
			}
		}
	} else {
		response.Error = "Invalid Method"
	}

	response.Method = method
	return &response

}

func main() {

	if len(os.Args) < 3 {
		fmt.Println("no args")
		return
	}
	/*
		argsWithProg := os.Args
		argsWithoutProg1 := os.Args[1]
		argsWithoutProg2 := os.Args[2]
		//argsWithoutProg3 := os.Args[3:]
		fmt.Println(argsWithProg)
		fmt.Println(argsWithoutProg1)
		fmt.Println(argsWithoutProg2)
	*/
	//获取最新properFee，用户在真实网络中查询得到
	valueArg2, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		fmt.Println(err)
		return
	}

	if valueArg2 > 0 {
		properFee = valueArg2
	} else {
		properFee = types.GInt("MinFee")
	}
	response := cmdParse(os.Args[1], os.Args[3])
	ret, _ := json.Marshal(response)
	fmt.Println(string(ret))

	//encodeTxTokenWXB()
	//decodeTxTokenWXB()

	//types.RegistorExecutor("token", ety.NewType())
	//types.RegisterDappFork("token", "Enable", 0)

	//decode1()
	//encode1()
	//decodeNoBalanceTx()
	//decodeSignRawTx()
	//txSendtoaddr()

	//txCreateRawTransactionCoin()

	//txCreateNoBalanceTransaction()

	//replay, err := txSignRawTx()
	//fmt.Println("txSignRawTx err: ", err)
	//fmt.Println("txSignRawTx replay: ", replay)

}
