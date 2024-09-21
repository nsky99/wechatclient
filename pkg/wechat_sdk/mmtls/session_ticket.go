package mmtls

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/hkdf"
)

// 票据信息
type SessionTicket struct {
	Type                byte
	TicketKLifeTimeHint uint32
	MacValue            []byte
	KeyVersion          uint32
	Iv                  []byte
	EncryptedTicket     []byte
}

func (s *SessionTicket) deserialize(data []byte) error {
	// current
	current := uint32(0)

	// Type
	s.Type = data[current]
	current = current + 1

	// TicketKLifeTimeHint
	s.TicketKLifeTimeHint = binary.BigEndian.Uint32(data[current : current+4])
	current = current + 4

	// MacValue
	macValueLength := uint32(binary.BigEndian.Uint16(data[current : current+2]))
	current = current + 2
	s.MacValue = data[current : current+macValueLength]
	current = current + macValueLength

	// KeyVersion
	s.KeyVersion = binary.BigEndian.Uint32(data[current : current+4])
	current = current + 4

	// IV
	ivLength := uint32(binary.BigEndian.Uint16(data[current : current+2]))
	current = current + 2
	s.Iv = data[current : current+ivLength]
	current = current + ivLength

	// EncryptedTicket
	encryptedTicketLength := uint32(binary.BigEndian.Uint16(data[current : current+2]))
	current = current + 2
	s.EncryptedTicket = data[current : current+encryptedTicketLength]
	current = current + encryptedTicketLength
	if current != uint32(len(data)) {
		return errors.New("err: current - startPos != pskTotalLength")
	}

	return nil
}

func (s *SessionTicket) serialize() []byte {
	// BodyData
	bodyData := make([]byte, 0)

	// Type
	bodyData = append(bodyData, s.Type)

	// TicketLifeTimeHint
	bodyData = binary.BigEndian.AppendUint32(bodyData, s.TicketKLifeTimeHint)

	// MacValue
	macValueLen := uint16(len(s.MacValue))
	bodyData = binary.BigEndian.AppendUint16(bodyData, macValueLen)
	bodyData = append(bodyData, s.MacValue[0:]...)

	// KeyVersion
	bodyData = binary.BigEndian.AppendUint32(bodyData, s.KeyVersion)

	// IV
	ivLen := uint16(len(s.Iv))
	bodyData = binary.BigEndian.AppendUint16(bodyData, ivLen)
	bodyData = append(bodyData, s.Iv[0:]...)

	// EncryptTicket
	encryptTicketLen := uint16(len(s.EncryptedTicket))
	bodyData = binary.BigEndian.AppendUint16(bodyData, encryptTicketLen)
	bodyData = append(bodyData, s.EncryptedTicket[0:]...)

	// 返回数据
	retBytes := make([]byte, 0)
	bodyLen := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, bodyLen)
	retBytes = append(retBytes, bodyData[0:]...)

	return retBytes
}

func create_psk_extension(st *SessionTicket) *Extension {
	preSharedKeyExtension := &NewSessionTicket{}
	// 选取前面协商的最后一个Psk
	preSharedKeyExtension.SessionTickets = append(preSharedKeyExtension.SessionTickets, st)
	// 序列化
	retExtension := preSharedKeyExtension.serialize()
	return retExtension
}

func (nst *NewSessionTicket) serialize() *Extension {
	// ExtensionBytes
	extensionBytes := make([]byte, 0)

	// PreSharedKeyExtensionType
	extensionBytes = binary.BigEndian.AppendUint16(extensionBytes, PreSharedKeyExtensionType)

	// pskCount
	pskCount := byte(len(nst.SessionTickets))
	extensionBytes = append(extensionBytes, pskCount)

	// PskList
	for index := 0; index < int(pskCount); index++ {
		session_ticket := nst.SessionTickets[index]
		pskData := session_ticket.serialize()
		extensionBytes = append(extensionBytes, pskData[0:]...)
	}

	// 返回数据
	retExtension := &Extension{}
	retExtension.ExtensionType = PreSharedKeyExtensionType
	retExtension.ExtensionData = extensionBytes
	return retExtension
}

type TrafficKeyPair struct {
	ClientWriteKey []byte
	ClientWriteIv  []byte
	ClientReadKey  []byte
	ClientReadIv   []byte
}

func calc_traffic_key(lable string, handshake_hash []byte, traffic_secret []byte) (*TrafficKeyPair, error) {

	expand_label := append([]byte(lable), handshake_hash...)

	trafficKey := make([]byte, 56)
	if _, err := hkdf.Expand(sha256.New, traffic_secret, expand_label).Read(trafficKey); err != nil {
		return nil, err
	}

	pair := &TrafficKeyPair{}
	pair.ClientWriteKey = trafficKey[:16]
	pair.ClientReadKey = trafficKey[16:32]
	pair.ClientWriteIv = trafficKey[32:44]
	pair.ClientReadIv = trafficKey[44:]

	return pair, nil
}

type NewSessionTicket struct {
	SessionTickets []*SessionTicket
}

func (tickets *NewSessionTicket) deserialize(data []byte) error {
	// skip len
	current := uint32(4)

	// tmpType
	if data[current] != NewSessionTicketType {
		return errors.New("the handshake msg is not new session ticket")
	}
	current = current + 1

	// pskListSize
	pskListSize := data[current]
	current = current + 1

	// PskList
	tickets.SessionTickets = make([]*SessionTicket, pskListSize)
	for index := 0; index < int(pskListSize); index++ {
		// pskTotalLength
		pskTotalLength := binary.BigEndian.Uint32(data[current : current+4])
		current = current + 4

		// PskDeSerialize
		ts := &SessionTicket{}
		err := ts.deserialize(data[current : current+pskTotalLength])
		if err != nil {
			return err
		}

		// Add to PskList
		tickets.SessionTickets[index] = ts
		current = current + pskTotalLength
	}

	return nil
}
