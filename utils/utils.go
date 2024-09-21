package utils

import (
	"encoding/base64"
)

func Base64Decode(data string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	return string(decodedBytes), nil
}
