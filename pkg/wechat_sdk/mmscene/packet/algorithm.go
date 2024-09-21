package packet

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"
	"io"
	"math/big"
)

// 计算request
func RqtCalcData(srcdata []byte) int {
	h := md5.New()
	h.Write([]byte(srcdata))
	md5sign := hex.EncodeToString(h.Sum(nil))
	key, _ := hex.DecodeString("6a664d5d537c253f736e48273a295e4f")
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(md5sign))
	mac_byte := string(mac.Sum(nil))
	randvalue := 1
	index := 0
	temp0 := 0
	temp1 := 0
	temp2 := 0
	for index = 0; index+2 < 20; index++ {
		temp0 = (temp0&0xff)*0x83 + int(mac_byte[index])
		temp1 = (temp1&0xff)*0x83 + int(mac_byte[index+1])
		temp2 = (temp2&0xff)*0x83 + int(mac_byte[index+2])
	}
	result := (temp2<<16)&0x7f0000 | temp0&0x7f | (randvalue&0x1f|0x20)<<24 | ((temp1 & 0x7f) << 8)
	return result
}

// 计算校验和
func CalculateChecksum(checksumSeed uint32, data []byte) uint32 {
	if data == nil {
		// 对于指向nil的切片，返回1
		return 1
	}

	var (
		HiChecksumSeed  = checksumSeed >> 16
		checksumSeedLow = checksumSeed & 0xFFFF
	)

	if len(data) == 1 {
		// 特殊处理单字节数据
		checksumSeedLow += uint32(data[0])
		if checksumSeedLow >= 0xFFF1 {
			checksumSeedLow -= 0xFFF1
		}
		HiChecksumSeed += checksumSeedLow
		if HiChecksumSeed >= 0xFFF1 {
			HiChecksumSeed -= 0xFFF1
		}
	} else {
		for i := 0; i < len(data); i++ {
			checksumSeedLow += uint32(data[i])
			HiChecksumSeed += checksumSeedLow
			if checksumSeedLow >= 0xFFF1 {
				checksumSeedLow -= 0xFFF1
			}
			if HiChecksumSeed >= 0xFFF1 {
				HiChecksumSeed -= 0xFFF1
			}
		}
	}
	// 最终校验和为高低部分的组合
	return (HiChecksumSeed << 16) | checksumSeedLow
}

// 计算校验和MD5
func CalculateMD5Checksum(uin uint32, stringData []byte, data []byte) uint32 {
	// 第一轮MD5：基于uin和stringData
	hash1 := md5.New()
	binary.Write(hash1, binary.BigEndian, uin)
	hash1.Write(stringData)
	md5Result1 := hash1.Sum(nil)

	// 第二轮MD5：基于第一轮MD5结果、data长度和data
	hash2 := md5.New()
	binary.Write(hash2, binary.BigEndian, uint32(len(data)))
	hash2.Write(stringData)
	hash2.Write(md5Result1)
	md5Result2 := hash2.Sum(nil)

	// 计算校验和
	sum1 := CalculateChecksum(0, nil)
	sum2 := CalculateChecksum(sum1, md5Result2)
	sum3 := CalculateChecksum(sum2, data)
	return sum3
}

// 生成ecdh密钥对
func GenEcdhKeyPair(CurveNid elliptic.Curve) (privKey []byte, pubKey []byte) {
	privateKey, err := ecdsa.GenerateKey(CurveNid, rand.Reader)
	if err != nil {
		return nil, nil
	}
	pub := &privateKey.PublicKey
	pubKey = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	privKey = privateKey.D.Bytes()
	return privKey, pubKey
}

// 协商ecdh共享秘钥
func EcdhSharedSecret(CurveNid elliptic.Curve, pubkey []byte, privatekey []byte, hashType int) []byte {
	// 选择椭圆曲线
	curve := CurveNid

	// 解析公钥
	x, y := elliptic.Unmarshal(curve, pubkey)
	if x == nil {
		return nil
	}

	// 计算共享密钥
	secret, _ := curve.ScalarMult(x, y, privatekey)
	var hashdata []byte
	switch hashType {
	case 0:
		tmpData := sha256.Sum256(secret.Bytes())
		hashdata = append(hashdata, tmpData[:]...)
	case 1:
		tmpData := md5.Sum(secret.Bytes())
		hashdata = append(hashdata, tmpData[:]...)
	}

	return hashdata
}

// 生成随机数
func Random(n int) []byte {
	key := make([]byte, n)
	rand.Read(key)
	return key
}

// ecdsa 签名校验
func EcdsaVerify(publicKeyPem []byte, message []byte, signature []byte) (bool, error) {
	// 1. 解析公钥
	publicKey, err := ParsePublicKey(publicKeyPem)
	if err != nil {
		return false, err
	}

	// 2. 计算哈希值
	hash := sha256.Sum256(message)

	// asn1 解析签名
	var sig struct {
		R, S *big.Int
	}
	asn1.Unmarshal(signature, &sig)

	// 3. 验证签名
	ok := ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)
	if !ok {
		return false, errors.New("signature verification failed")
	}

	return true, nil
}

// 解析公钥
func ParsePublicKey(publicKeyPem []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	default:
		return nil, errors.New("public key is not ECDSA")
	}
}

// 进行zlib压缩
func ZlibCompress(src []byte) []byte {
	var in bytes.Buffer
	w, _ := zlib.NewWriterLevel(&in, zlib.DefaultCompression)
	w.Write(src)
	w.Close()
	return in.Bytes()
}

// 进行zlib解压缩
func ZlibUnCompress(compressSrc []byte) []byte {
	b := bytes.NewReader(compressSrc)
	var out bytes.Buffer
	r, _ := zlib.NewReader(b)
	io.Copy(&out, r)
	return out.Bytes()
}

// aes gcm加密
func AesGcmEncrypt(key []byte, plaintext []byte, nonce []byte, aad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext
}

// aes gcm 解密
func AesGcmDecrypt(key []byte, ciphertext []byte, nonce []byte, aad []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil
	}
	return plaintext
}

// zlib压缩后aes gcm加密
func AesGcmEncryptWithCompress(key []byte, plaintext []byte, aad []byte) []byte {
	compressData := ZlibCompress(plaintext)
	nonce := []byte(Random(12)) //获取随机密钥
	encrypt_data := AesGcmEncrypt(key, compressData, nonce, aad)
	outdata := encrypt_data[:len(encrypt_data)-16]
	retdata := new(bytes.Buffer)
	retdata.Write(outdata)
	retdata.Write(nonce)
	retdata.Write(encrypt_data[len(encrypt_data)-16:])
	return retdata.Bytes()
}

// aes gcm解密后 zlib解压缩
func AesGcmDecryptWithUncompress(key []byte, ciphertext []byte, aad []byte) []byte {
	ciphertextinput := ciphertext[:len(ciphertext)-0x1c]
	endatanonce := ciphertext[len(ciphertext)-0x1c : len(ciphertext)-0x10]
	data := new(bytes.Buffer)
	data.Write(ciphertextinput)
	data.Write(ciphertext[len(ciphertext)-0x10:])
	decrypt_data := AesGcmDecrypt(key, data.Bytes(), endatanonce, aad)
	if len(decrypt_data) > 0 {
		return ZlibUnCompress(decrypt_data)
	} else {
		return []byte{}
	}
}

// HKDF扩展
func HkdfExpand(h func() hash.Hash, prk, info []byte, outLen int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < outLen {
		block := append(T, info...)
		block = append(block, i)

		h := hmac.New(h, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i++
	}
	return out[:outLen]
}

// HKDF扩展
func HybridHkdfExpand(prikey []byte, salt []byte, info []byte, outLen int) []byte {
	h := hmac.New(sha256.New, prikey)
	h.Write(salt)
	T := h.Sum(nil)
	return HkdfExpand(sha256.New, T, info, outLen)
}

// aes 解密
func AesDecrypt(body []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(key))
	origData := make([]byte, len(body))
	blockMode.CryptBlocks(origData, body)
	origData = PKCS5UnPadding(origData)
	return origData
}

// aes 加密
func AesEncrypt(RequestSerialize []byte, key []byte) []byte {
	//根据key 生成密文
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	blockSize := block.BlockSize()
	RequestSerialize = PKCS5Padding(RequestSerialize, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, []byte(key))
	crypted := make([]byte, len(RequestSerialize))
	blockMode.CryptBlocks(crypted, RequestSerialize)

	return crypted
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	//填充
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	if length < unpadding {
		return nil
	}
	return origData[:(length - unpadding)]
}
