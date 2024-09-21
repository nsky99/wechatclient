package mmtls

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
)

// 验证秘钥
var (

	/*
		// 内部包含 pem
		   "000000be000000030000019f00b22d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414548614633747158744e4e7137507973456470664b693736336a4767340a6e4f31444d586f706a586378625652426463417976466339584f537a7241742f4b35714e534d704c6d517a692b6a7a6e584d6e524a7944364e513d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a0000"
		   "000000be000000040000019f00b22d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414571354658414159675a4e726f507472387a72686358485962784774650a3753354d6e4c6a6c4461766b7346754c787365317256714b792f786c45757543634b6831637542756544676a486f536c712b526c716a515855773d3d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a0000"

	*/
	// 用于验证签名的秘钥
	ecdhVerifyPubKey_3 = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHaF3tqXtNNq7PysEdpfKi763jGg4
nO1DMXopjXcxbVRBdcAyvFc9XOSzrAt/K5qNSMpLmQzi+jznXMnRJyD6NQ==    
-----END PUBLIC KEY-----`)

	ecdhVerifyPubKey_4 = []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEq5FXAAYgZNroPtr8zrhcXHYbxGte
7S5MnLjlDavksFuLxse1rVqKy/xlEuuCcKh1cuBueDgjHoSlq+RlqjQXUw==
-----END PUBLIC KEY-----`)
)

type CertificateVerify struct {
	Signature []byte
}

type EcdsaSignature struct {
	R, S *big.Int
}

func (cv *CertificateVerify) deserialize(data []byte) error {

	// current
	current := uint32(0)

	// skip record len
	current += 4

	// tmpType
	if data[current] != CertificateVerifyType {
		return errors.New("the record is not CertificateVerifyType")
	}
	current = current + 1

	// SignatureSize
	size := uint32(binary.BigEndian.Uint16((data[current : current+2])))
	current = current + 2

	// Signature
	cv.Signature = data[current : current+size]
	current = current + size

	// 判断数据是否完整解析
	if current != uint32(len(data)) {
		return errors.New("err: current != uint32(len(data)")
	}

	return nil
}

func (cv *CertificateVerify) verify_ecdsa(version uint32, message []byte) error {

	if version == 3 {
		block, _ := pem.Decode(ecdhVerifyPubKey_3)
		publicStream, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		//接口转换成公钥
		publicKey := publicStream.(*ecdsa.PublicKey)

		flag := ecdsa.VerifyASN1(publicKey, sha256.New().Sum(message), cv.Signature)

		if flag {
			return nil
		} else {
			return errors.New("verify_ecdsa faild")
		}
	} else if version == 4 {
		block, _ := pem.Decode(ecdhVerifyPubKey_4)
		publicStream, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		//接口转换成公钥
		publicKey := publicStream.(*ecdsa.PublicKey)

		flag := ecdsa.VerifyASN1(publicKey, sha256.New().Sum(message), cv.Signature)

		if flag {
			return nil
		} else {
			return errors.New("verify_ecdsa faild")
		}
	}
	return errors.New("cert version is not match")
}
