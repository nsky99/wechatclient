package mmtls

import (
	"encoding/binary"
	"errors"
)

type ServerHello struct {
	Version       uint16       // mmtls 版本
	CipherSuite   *CipherSuite // 服务端选择的加密套件
	RandomBytes   []byte       // 服务端随机数 0x20
	ExtensionList []*Extension // mmtls 扩展信息
}

func (sh *ServerHello) deserialize(data []byte) error {
	current := uint32(0)

	// skip len
	current += 4

	// handshake type
	if data[current] != ServerHelloType {
		return errors.New("the handshake msg is not server hello")
	}
	current = current + 1

	// Version
	sh.Version = binary.LittleEndian.Uint16(data[current : current+2])
	current = current + 2

	// CipherSuite
	suiteCode := binary.BigEndian.Uint16(data[current : current+2])
	current = current + 2
	sh.CipherSuite = get_cipher_suite_by_code(suiteCode)

	// RandomBytes
	sh.RandomBytes = data[current : current+32]
	current = current + 32

	// ExtensionList
	sh.ExtensionList = extensions_deserialize(data[current:])
	return nil
}
