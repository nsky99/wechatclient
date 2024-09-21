package mmtls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ServerFinished struct {
	VerifyData []byte
}

func (sf *ServerFinished) deserialize(data []byte) error {

	// skip record len
	current := uint32(4)

	// tmpType
	if data[current] != FinishedType {
		return errors.New("server finish deserialize err: the record is not FinishedType")
	}
	current = current + 1

	// VerifyData
	verifyDataLen := uint32(binary.BigEndian.Uint16(data[current : current+2]))
	current = current + 2
	sf.VerifyData = data[current : current+verifyDataLen]
	current = current + verifyDataLen

	// 判断数据是否完整解析
	if current != uint32(len(data)) {
		return errors.New("server finish deserialize err: current != uint32(len(data)")
	}

	return nil
}

func (sf *ServerFinished) verify_data(key []byte, shaValue []byte) error {
	tmpHkdfValue := hkdf_expand(key, []byte("server finished"), len(sf.VerifyData)) // hkdf expand finished secret
	verifyData := hmac_hash256(tmpHkdfValue, shaValue)

	if bytes.Equal(verifyData, sf.VerifyData) {
		return nil
	} else {
		return errors.New("server finish err: verify data faild")
	}
}
