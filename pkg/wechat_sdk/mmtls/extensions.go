package mmtls

import (
	"encoding/binary"
	"errors"
	"time"
)

type ClientKeyOffer struct {
	Version     uint32
	PublicValue []byte
}

func create_client_key_offer(version uint32, publicKey []byte) *ClientKeyOffer {
	return &ClientKeyOffer{
		PublicValue: publicKey,
		Version:     version,
	}
}

func (k *ClientKeyOffer) serialize() []byte {
	// BodyData
	bodyData := make([]byte, 0)

	// Version
	bodyData = binary.BigEndian.AppendUint32(bodyData, k.Version)

	// PublicValue
	publicValueLen := uint16(len(k.PublicValue))
	bodyData = binary.BigEndian.AppendUint16(bodyData, publicValueLen)
	if publicValueLen > 0 {
		bodyData = append(bodyData, k.PublicValue[0:]...)
	}

	// 返回数据
	retBytes := make([]byte, 0)
	bodyDataLen := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, bodyDataLen)
	retBytes = append(retBytes, bodyData[0:]...)
	return retBytes
}

type ClientKeyShareExtension struct {
	ClientKeyOfferList []*ClientKeyOffer
	CertificateVersion uint32
}

func create_client_key_share_extension(ecdh_keys *ClientEcdhKeys) *Extension {
	client_key_share_extension := &ClientKeyShareExtension{}

	client_key_share_extension.ClientKeyOfferList =
		append(client_key_share_extension.ClientKeyOfferList, create_client_key_offer(5, ecdh_keys.EcdhPubKeyBuf))

	client_key_share_extension.ClientKeyOfferList =
		append(client_key_share_extension.ClientKeyOfferList, create_client_key_offer(6, ecdh_keys.EcdhVerifyPubKeyBuf))

	return client_key_share_extension.serialize()
}

// application_layer_protocol_negotiation
func (e *ClientKeyShareExtension) serialize() *Extension {
	// ExtensionBytes
	extensionBytes := make([]byte, 0)

	// ClientKeyShareType
	extensionBytes = binary.BigEndian.AppendUint16(extensionBytes, ClientKeyShareType)

	// KeyOfferCount
	keyOfferCount := byte(len(e.ClientKeyOfferList))
	extensionBytes = append(extensionBytes, keyOfferCount)

	// KeyOfferList
	for _, client_key_offer := range e.ClientKeyOfferList {
		extensionBytes = append(extensionBytes, client_key_offer.serialize()...)
	}

	// magic
	magic := []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04}
	extensionBytes = append(extensionBytes, magic...)

	// 返回数据
	retExtension := &Extension{}
	retExtension.ExtensionType = ClientKeyShareType
	retExtension.ExtensionData = extensionBytes
	return retExtension
}

type ServerKeyShareExtension struct {
	KeyOfferNameGroup uint32
	PublicValue       []byte
}

func (e *ServerKeyShareExtension) deserialize(data []byte) error {
	current := uint32(0)

	// tmpType
	tmpType := binary.BigEndian.Uint16(data[current : current+2])
	if tmpType != ServerKeyShareType {
		return errors.New("extension type is not ServerKeyShareType")
	}
	current = current + 2

	// KeyOfferNameGroup
	e.KeyOfferNameGroup = binary.BigEndian.Uint32(data[current : current+4])
	current = current + 4

	// PublicValue
	publicValueSize := uint32(binary.BigEndian.Uint16(data[current : current+2]))
	current = current + 2
	e.PublicValue = data[current : current+publicValueSize]

	return nil
}

type CertRegionExtension struct {
	CertRegion  uint32
	CertVersion uint32
}

func (e *CertRegionExtension) deserialize(data []byte) error {
	current := uint32(0)

	// tmpType
	tmpType := binary.BigEndian.Uint16(data[current : current+2])
	if tmpType != CertRegionType {
		return errors.New("extension type is not ServerKeyShareType")
	}
	current = current + 2

	// CertRegion
	e.CertRegion = binary.BigEndian.Uint32(data[current : current+4])
	current = current + 4

	// CertVersion
	e.CertVersion = binary.BigEndian.Uint32(data[current : current+4])

	return nil
}

type Extension struct {
	ExtensionType uint16
	ExtensionData []byte
}

func extensions_serialize(extensionList []*Extension) []byte {
	retBytes := make([]byte, 0)

	// bodyData
	bodyData := make([]byte, 0)

	// Extensions Count
	extensionCount := byte(len(extensionList))
	bodyData = append(bodyData, extensionCount)

	// serialize extension
	for _, extension := range extensionList {
		// Extension TotalLength
		bodyData = binary.BigEndian.AppendUint32(bodyData, uint32(len(extension.ExtensionData)))

		// extensionData
		bodyData = append(bodyData, extension.ExtensionData...)
	}

	// Extensions Size
	extensionsSize := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, extensionsSize)

	// ExtensionsData
	retBytes = append(retBytes, bodyData[0:]...)
	return retBytes
}

func extensions_deserialize(data []byte) []*Extension {
	// 初始化返回数组
	retExtensions := make([]*Extension, 0)

	// 初始化索引
	current := uint32(0)

	// totalLength
	totalLength := binary.BigEndian.Uint32(data[current : current+4])
	current = current + 4

	// extensionCount := data[current]
	current = current + 1
	// ExtensionList
	for current-4 < totalLength {
		extension := &Extension{}

		// ExtensionData
		extensionLength := binary.BigEndian.Uint32(data[current : current+4])
		current = current + 4

		// ExtensionType
		extension.ExtensionType = binary.BigEndian.Uint16(data[current : current+2])

		// ExtensionData
		extension.ExtensionData = data[current : current+extensionLength]

		// 放入列表
		retExtensions = append(retExtensions, extension)
		current = current + extensionLength
	}

	return retExtensions
}

type EncryptedExtensions struct {
	ExtensionList []*Extension
}

func create_encrypted_extensions() *EncryptedExtensions {
	retEncryptedExtensions := &EncryptedExtensions{}

	// ExtensionList
	retEncryptedExtensions.ExtensionList = append(retEncryptedExtensions.ExtensionList, create_early_encrypt_extension())

	return retEncryptedExtensions
}

func (es *EncryptedExtensions) serialize() []byte {
	bodyData := make([]byte, 0)
	// Type
	bodyData = append(bodyData, EncryptedExtensionsType)

	// ExtensionList
	extensionsData := extensions_serialize(es.ExtensionList)
	bodyData = append(bodyData, extensionsData[0:]...)

	// 返回数据
	retBytes := make([]byte, 0)
	bodyDataLen := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, bodyDataLen)
	retBytes = append(retBytes, bodyData[0:]...)
	return retBytes
}

type EarlyEncryptDataExtension struct {
	ClientGmtTime uint32
}

func create_early_encrypt_extension() *Extension {
	retEarlyEncryptDataExtension := &EarlyEncryptDataExtension{}
	retEarlyEncryptDataExtension.ClientGmtTime = (uint32)(time.Now().UnixNano() / 1000000000)
	return retEarlyEncryptDataExtension.serialize()
}

func (earlyEncryptDataExtension *EarlyEncryptDataExtension) serialize() *Extension {
	// ExtensionBytes
	extensionBytes := make([]byte, 0)

	// ClientKeyShareType
	extensionBytes = binary.BigEndian.AppendUint16(extensionBytes, EarlyEncryptDataType)

	// ClientGmtTime
	extensionBytes = binary.BigEndian.AppendUint32(extensionBytes, earlyEncryptDataExtension.ClientGmtTime)

	// 返回数据
	retExtension := &Extension{}
	retExtension.ExtensionType = EarlyEncryptDataType
	retExtension.ExtensionData = extensionBytes
	return retExtension
}
