package mmtls

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
)

// 这是TLS协议中使用的不同记录类型的列表
const (
	RECORD_ALERT            byte = 0x15 // 表示包含警告级别和警告描述的消息
	RECORD_HANDSHAKE        byte = 0x16 // 表示包含握手协议消息的消息
	RECORD_APPLICATION_DATA byte = 0x17 // 表示包含应用数据的消息
	RECORD_HEARTBEAT        byte = 0x18 // 表示心跳数据
	RECORD_EARLY_HANDSHAKE  byte = 0x19 // 表示包含早期握手协议消息的消息
)

type LongLinkAppDataRecord struct {
	HeaderLen uint16 //
	Version   uint16 // 长连接版本
	CmdId     uint32 // 具体的操作 cmdid
	Seq       uint32 // 用来确定同一条消息
	Data      []byte // 要发送的app 数据
}

type Record struct {
	Type    byte   // 类型
	Version uint16 // 版本
	Size    uint16 // RecordBody大小
	Data    []byte
}

func create_record(record_type byte, data []byte) *Record {
	return &Record{
		Type:    record_type,
		Version: MMTLS_VERSION_F104,
		Size:    uint16(len(data)),
		Data:    data,
	}
}

func create_aleret_record(data []byte) *Record {
	return create_record(RECORD_ALERT, data)
}

func create_handshake_record(data []byte) *Record {
	return create_record(RECORD_HANDSHAKE, data)
}

func create_early_handshake_record(data []byte) *Record {
	return create_record(RECORD_EARLY_HANDSHAKE, data)
}

func create_app_data_record_longlink(cmdid uint32, data []byte, seq uint32) *Record {
	a := &LongLinkAppDataRecord{
		HeaderLen: 0x10,
		Version:   1,
		CmdId:     cmdid,
		Seq:       seq,
		Data:      data,
	}
	return create_record(RECORD_APPLICATION_DATA, a.serialize())
}

func create_app_data_record_shortlink(data []byte) *Record {
	return create_record(RECORD_APPLICATION_DATA, data)
}

func (d *LongLinkAppDataRecord) serialize() []byte {
	retBytes := make([]byte, 0)

	retBytes = binary.BigEndian.AppendUint32(retBytes, uint32(len(d.Data)+16))

	// HeaderLen
	retBytes = binary.BigEndian.AppendUint16(retBytes, d.HeaderLen)

	// Version
	retBytes = binary.BigEndian.AppendUint16(retBytes, d.Version)

	// cmd
	retBytes = binary.BigEndian.AppendUint32(retBytes, d.CmdId)

	// seq
	retBytes = binary.BigEndian.AppendUint32(retBytes, d.Seq)

	// Data
	retBytes = append(retBytes, d.Data...)
	return retBytes
}

func (d *LongLinkAppDataRecord) deserialize(data []byte) error {
	currentPos := 0

	AppDataRecordLen := binary.BigEndian.Uint32(data[currentPos : currentPos+4])
	currentPos += 4

	d.HeaderLen = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
	currentPos += 2

	d.Version = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
	currentPos += 2

	d.CmdId = binary.BigEndian.Uint32(data[currentPos : currentPos+4])
	currentPos += 4

	d.Seq = binary.BigEndian.Uint32(data[currentPos : currentPos+4])
	currentPos += 4

	// AppDataRecordLen = head+payload
	if AppDataRecordLen != uint32(len(data[currentPos:])+0x10) {
		return errors.New("response packet length invalid")
	}

	d.Data = data[currentPos:]
	return nil
}

func (r *Record) serialize() []byte {
	retBytes := make([]byte, 0)

	// Type
	retBytes = append(retBytes, r.Type)

	// Version
	retBytes = binary.BigEndian.AppendUint16(retBytes, r.Version)

	// Size
	retBytes = binary.BigEndian.AppendUint16(retBytes, r.Size)

	// Data
	retBytes = append(retBytes, r.Data...)
	return retBytes
}

func (r *Record) serialize_header() []byte {
	retBytes := make([]byte, 0)

	// Type
	retBytes = append(retBytes, r.Type)

	// Version
	retBytes = binary.BigEndian.AppendUint16(retBytes, r.Version)

	// Size
	retBytes = binary.BigEndian.AppendUint16(retBytes, r.Size)

	return retBytes
}

func (r *Record) serialize_header_by_len(len uint16) []byte {
	retBytes := make([]byte, 0)

	// Type
	retBytes = append(retBytes, r.Type)

	// Version
	retBytes = binary.BigEndian.AppendUint16(retBytes, r.Version)

	// Size
	retBytes = binary.BigEndian.AppendUint16(retBytes, r.Size+len)

	return retBytes
}

func (r *Record) deserialize_header(data []byte) {
	currentPos := 0

	r.Type = data[0]
	currentPos += 1

	r.Version = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
	currentPos += 2

	r.Size = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
	currentPos += 2
}

func (r *Record) deserialize(data []byte) {
	currentPos := 0

	r.Type = data[0]
	currentPos += 1

	r.Version = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
	currentPos += 2

	r.Size = binary.BigEndian.Uint16(data[currentPos : currentPos+2])
	currentPos += 2

	r.Data = data[currentPos : currentPos+int(r.Size)]
}

func (r *Record) encrypt(key *TrafficKeyPair, client_seq uint32) error {
	// nonce
	nonce := xor_nonce(key.ClientWriteIv, client_seq)

	// add
	record_head := r.serialize_header_by_len(0x10)
	add := []byte{0x00, 0x00, 0x00, 0x00}
	add = binary.BigEndian.AppendUint32(add, atomic.LoadUint32(&client_seq))
	add = append(add, record_head...)

	// 加密record_data
	encodeData, err := aes_gcm_encrypt(key.ClientWriteKey, nonce, add, r.Data)
	if err != nil {
		return err
	}
	r.Data = encodeData
	r.Size = uint16(len(encodeData))
	return nil
}

func (r *Record) decrypt(key *TrafficKeyPair, server_seq uint32) error {
	// nonce
	nonce := xor_nonce(key.ClientReadIv, server_seq)

	// add
	add := []byte{0x00, 0x00, 0x00, 0x00}
	add = binary.BigEndian.AppendUint32(add, atomic.LoadUint32(&server_seq))
	add = append(add, r.serialize_header()...)

	// 解密record_data
	encodeData, err := aes_gcm_decrypt(key.ClientReadKey, nonce, add, r.Data)
	if err != nil {
		return err
	}

	r.Data = encodeData
	r.Size = uint16(len(encodeData))
	return nil
}
