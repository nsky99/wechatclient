package mmtls

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"

	"github.com/wsddn/go-ecdh"
)

/*
// key 5,6 server public key 不知道作用
"0000004d000000050000019f00410464d39efbe5b110f1b6c5bd4d838038ead94ad75e9f01a4ff6ce814d09b369bdff6915b84461813b3fc15464e4882165a69fc1400162d981f7fe0abb4bbb719e70000"
"0000004d000000060000019f004104e923ef1a14269440f50af4256d61b41a8d66c85159c2b1cb7fb4696d9026b7e6eaf81f55a64de08178058ee3facfec8ddf48be41ad638fe8a6f42a532da6a2410000"
*/
type ClientEcdhKeys struct {
	EcdhPriKey          crypto.PrivateKey // 加密key
	EcdhPubKeyBuf       []byte
	EcdhVerifyPriKey    crypto.PrivateKey // 验证key
	EcdhVerifyPubKeyBuf []byte
}

// 生成客户端ecdh 密钥对 加密和签名密钥对
func create_client_ecdh_keys() *ClientEcdhKeys {
	clientEcdhKeys := &ClientEcdhKeys{}
	e := ecdh.NewEllipticECDH(elliptic.P256())
	priKey1, pubKey1, _ := e.GenerateKey(rand.Reader)
	priKey2, pubKey2, _ := e.GenerateKey(rand.Reader)
	clientEcdhKeys.EcdhPriKey = priKey1
	clientEcdhKeys.EcdhPubKeyBuf = e.Marshal(pubKey1)
	clientEcdhKeys.EcdhVerifyPriKey = priKey2
	clientEcdhKeys.EcdhVerifyPubKeyBuf = e.Marshal(pubKey2)

	return clientEcdhKeys
}

func random_bytes(length uint32) []byte {
	retBytes := make([]byte, length)
	_, err := rand.Read(retBytes)
	if err != nil {
		panic(err)
	}
	return retBytes
}

func xor_nonce(data []byte, seq uint32) []byte {
	ret := make([]byte, len(data))
	copy(ret, data)

	seqBytes := make([]byte, 0)
	seqBytes = binary.BigEndian.AppendUint32(seqBytes, seq)

	baseOffset := 8
	for index := 0; index < 4; index++ {
		ret[baseOffset+index] = ret[baseOffset+index] ^ byte(seqBytes[index])
	}
	return ret
}

func get_cipher_suite_by_code(code uint16) *CipherSuite {
	switch code {
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		{
			cipherSuite := &CipherSuite{}

			// SuiteCode
			cipherSuite.SuiteCode = code

			// cipherSuiteInfo
			cipherSuiteInfo := &CipherSuiteInfo{}
			cipherSuiteInfo.SuiteCode = code
			cipherSuiteInfo.ClipherKeyChange = "ECDHE"
			cipherSuiteInfo.ClipherSign = "ECDSA"
			cipherSuiteInfo.ClipherDigst = "SHA256"
			cipherSuiteInfo.ClipherEncryption = "AES_128_GCM"
			cipherSuiteInfo.ClipherMode = "AEAD"
			cipherSuiteInfo.Length1 = 16
			cipherSuiteInfo.Length2 = 0
			cipherSuiteInfo.Length3 = 12
			cipherSuite.SuiteInfo = cipherSuiteInfo
			return cipherSuite
		}
	case TLS_PSK_WITH_AES_128_GCM_SHA256:
		{
			cipherSuite := &CipherSuite{}

			// SuiteCode
			cipherSuite.SuiteCode = code

			// cipherSuiteInfo
			cipherSuiteInfo := &CipherSuiteInfo{}
			cipherSuiteInfo.SuiteCode = code
			cipherSuiteInfo.ClipherKeyChange = "PSK"
			cipherSuiteInfo.ClipherSign = "ECDSA"
			cipherSuiteInfo.ClipherDigst = "SHA256"
			cipherSuiteInfo.ClipherEncryption = "AES_128_GCM"
			cipherSuiteInfo.ClipherMode = "AEAD"
			cipherSuiteInfo.Length1 = 16
			cipherSuiteInfo.Length2 = 0
			cipherSuiteInfo.Length3 = 12
			cipherSuite.SuiteInfo = cipherSuiteInfo
			return cipherSuite
		}
	default:
		return nil
	}
}
