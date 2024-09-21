package mmtls

import "encoding/binary"

type ClientFinished struct {
	VerifyData []byte
}

func new_client_finished(key []byte, hash_data []byte) *ClientFinished {
	retFinished := &ClientFinished{}
	hkdfClientFinish := hkdf_expand(key, []byte("client finished"), 32)
	retFinished.VerifyData = hmac_hash256(hkdfClientFinish, hash_data)
	return retFinished
}

func (cf *ClientFinished) serialize() []byte {
	bodyData := make([]byte, 0)
	// Type
	bodyData = append(bodyData, FinishedType)

	// VerifyData
	verifyDataLen := uint16(len(cf.VerifyData))
	bodyData = binary.BigEndian.AppendUint16(bodyData, verifyDataLen)
	bodyData = append(bodyData, cf.VerifyData[:]...)

	// 返回数据
	retBytes := make([]byte, 0)
	bodyDataLen := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, bodyDataLen)
	retBytes = append(retBytes, bodyData[0:]...)
	return retBytes
}
