package mmtls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

func aes_gcm_encrypt(key, nonce, aad, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, nil
	}
	ciphertext := aesgcm.Seal(nil, nonce, data, aad)
	return ciphertext, nil
}

func aes_gcm_decrypt(key, nonce, aad, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := aesgcm.Open(nil, nonce, data, aad)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func hkdf_expand(key, message []byte, outLen int) []byte {
	result := make([]byte, outLen)
	hkdf.Expand(sha256.New, key, message).Read(result)
	return result[:]
}

func hmac_hash256(key []byte, data []byte) []byte {
	hmacTool := hmac.New(sha256.New, key)
	hmacTool.Write(data)
	return hmacTool.Sum(nil)
}
