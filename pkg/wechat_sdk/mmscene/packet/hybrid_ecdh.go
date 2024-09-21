package packet

import (
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"hash"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"

	"google.golang.org/protobuf/proto"
)

var (
	HybridEcdhInitServerPubKey = []byte{
		0x04, 0x18, 0x38, 0x8C, 0x99, 0x36, 0x65, 0xA9, 0xDB, 0xFA, 0xDA, 0xA5, 0xAE, 0x31, 0x72, 0xD0,
		0x94, 0xDC, 0x5B, 0xD4, 0x4A, 0x9F, 0x49, 0x5A, 0xB9, 0x1C, 0xC9, 0x3F, 0x86, 0xFF, 0xFA, 0xDC,
		0xDB, 0x9E, 0x2D, 0x06, 0x3B, 0x38, 0xE5, 0xC5, 0xE0, 0xBE, 0x47, 0x35, 0x91, 0x02, 0xD0, 0x6E,
		0x79, 0xCC, 0x36, 0x54, 0xBF, 0xEB, 0x0C, 0x5B, 0x7D, 0xB4, 0xAE, 0x97, 0xB3, 0x2A, 0x2B, 0x57,
		0x5E,
	}
	HybridEcdsaVerifyPubKey = []byte("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8pHNfJY1rtyK+0EMH20veU3IGoAQ\nlNedfTZ3wTzalUGKmxUKifi2iBF3J8seMNV3TivDpUmLscLb4jrWKurCkg==\n-----END PUBLIC KEY-----\n")
)

type HybridEcdhClient struct {
	// State                      uint32 // 登录所处的状态
	// SN                         uint32 // 应该是地域，cn10010, sg50001, ml10001
	// Nid                        uint32 // 椭圆曲线曲率415
	Src                        []byte // 要加密的数据
	Externkey                  []byte // 扩展密钥
	HybridEcdhPubKey           []byte // 公钥
	HybridEcdhPriKey           []byte // 私钥
	HybridEcdsaVerifyPubKey    []byte // ecdsa验签公钥
	HybridEcdhInitServerPubKey []byte // 服务端加密公钥

	HybridDecryptHash        hash.Hash
	HybridServerpubhashFinal hash.Hash
}

func (ecdhClient *HybridEcdhClient) Encrypt(data []byte) []byte {
	// 生成随机ecdh密钥对,并保存
	privateKey, publicKey := GenEcdhKeyPair(elliptic.P256())
	if len(privateKey) == 0 || len(publicKey) == 0 {
		return nil
	}
	ecdhClient.HybridEcdhPubKey = publicKey
	ecdhClient.HybridEcdhPriKey = privateKey

	// 计算共享秘钥
	EcdhKey := EcdhSharedSecret(elliptic.P256(), ecdhClient.HybridEcdhInitServerPubKey, privateKey, 0)
	if len(EcdhKey) == 0 {
		return nil
	}
	// 如果ecdh扩展密钥长度大于24只保留24字节
	if len(EcdhKey) > 0x18 {
		EcdhKey = EcdhKey[:0x18]
	}

	// 计算加密随机数用到的aad
	mClientpubhash := sha256.New()
	mClientpubhash.Write([]byte("1"))   // state
	mClientpubhash.Write([]byte("415")) // nid
	mClientpubhash.Write(publicKey)     // pubkey
	mClientpubhash_digest := mClientpubhash.Sum(nil)

	randomByte := Random(0x20)

	// 计算秘钥加密随机数数据
	Randomkeydata := AesGcmEncryptWithCompress(EcdhKey[:0x18], randomByte, mClientpubhash_digest)

	// 判断是否有扩展密钥，如果有扩展密钥则计算扩展密钥加密随机数数据
	var Randomkeyextenddata []byte
	if len(ecdhClient.Externkey) == 0x20 {
		Randomkeyextenddata = AesGcmEncryptWithCompress(ecdhClient.Externkey[:0x18], randomByte, mClientpubhash_digest)
		if len(Randomkeyextenddata) == 0 {
			Randomkeyextenddata = []byte("")
		}
	}

	// 计算扩展密钥，最终加密数据需要用到的
	hkdfexpand_security_key := HybridHkdfExpand([]byte("security hdkf expand"), randomByte, mClientpubhash_digest, 56)

	// 计算最终加密需要用到的aad
	mClientpubhashFinal := sha256.New()
	mClientpubhashFinal.Write([]byte("1"))
	mClientpubhashFinal.Write([]byte("415"))
	mClientpubhashFinal.Write(publicKey)
	mClientpubhashFinal.Write(Randomkeydata)
	mClientpubhashFinal.Write(Randomkeyextenddata)
	mClientpubhashFinal_digest := mClientpubhashFinal.Sum(nil)

	// 加密最终的数据
	Encyptdata := AesGcmEncryptWithCompress(hkdfexpand_security_key[:0x18], data, mClientpubhashFinal_digest)

	// 组装proto
	HybridEcdhRequest := &micromsg.HybridEcdhRequest{
		Type: proto.Int32(1),
		SecECDHKey: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(415),
			Buffer: publicKey,
		},
		Randomkeydata:       Randomkeydata,
		Randomkeyextenddata: Randomkeyextenddata,
		Encyptdata:          Encyptdata,
	}

	reqdata, _ := proto.Marshal(HybridEcdhRequest)

	ecdhClient.HybridDecryptHash = sha256.New()
	ecdhClient.HybridDecryptHash.Write(Encyptdata)

	ecdhClient.HybridServerpubhashFinal = sha256.New()
	ecdhClient.HybridServerpubhashFinal.Write(hkdfexpand_security_key[24:56])
	ecdhClient.HybridServerpubhashFinal.Write(data)

	return reqdata
}

func (ecdhClient *HybridEcdhClient) Decrypt(data []byte) ([]byte, error) {

	// 解析数据
	HybridEcdhResponse := &micromsg.HybridEcdhResponse{}
	err := proto.Unmarshal(data, HybridEcdhResponse)
	if err != nil {
		return nil, err
	}

	ecdhClient.HybridDecryptHash.Write(HybridEcdhResponse.Decryptdata)
	DecryptDataHash := ecdhClient.HybridDecryptHash.Sum(nil)

	// 校验签名
	r, _ := EcdsaVerify(ecdhClient.HybridEcdsaVerifyPubKey, DecryptDataHash, HybridEcdhResponse.Randomkeyextenddata)
	if !r {
		return nil, errors.New("verify signature faild")
	}

	ecdhClient.HybridServerpubhashFinal.Write([]byte("415"))
	ecdhClient.HybridServerpubhashFinal.Write(HybridEcdhResponse.SecECDHKey.Buffer)
	ecdhClient.HybridServerpubhashFinal.Write([]byte("1"))
	mServerpubhashFinal_digest := ecdhClient.HybridServerpubhashFinal.Sum(nil)

	// 计算共享秘钥
	EcdhKey := EcdhSharedSecret(elliptic.P256(), HybridEcdhResponse.SecECDHKey.Buffer, ecdhClient.HybridEcdhPriKey, 0)
	if len(EcdhKey) == 0 {
		return nil, nil
	}
	return AesGcmDecryptWithUncompress(EcdhKey[:24], HybridEcdhResponse.Decryptdata, mServerpubhashFinal_digest), nil
}
