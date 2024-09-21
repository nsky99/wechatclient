package mmtls

import (
	"encoding/binary"
	"time"
)

type CipherSuiteInfo struct {
	SuiteCode         uint16 // 密码套件代码
	ClipherKeyChange  string // 秘钥交换算法
	ClipherSign       string // 数字签名算法
	ClipherDigst      string // 消息摘要算法
	ClipherEncryption string // 对称加密算法
	ClipherMode       string // 加密模式
	Length1           uint32
	Length2           uint32
	Length3           uint32
}

type CipherSuite struct {
	SuiteCode uint16           // 密码套件代码
	SuiteInfo *CipherSuiteInfo // 密码套件信息
}

type ClientHello struct {
	Version         uint16         // mmtls 版本
	CipherSuiteList []*CipherSuite // 客户端支持的加密套件
	RandomBytes     []byte         // 客户端随机数 0x20
	ClientGmtTime   uint32         // 时间戳
	ExtensionList   []*Extension   // mmtls 拓展信息
}

// 1-RTT ECDHE
func new_ecdh_hello(ecdh_keys *ClientEcdhKeys) *ClientHello {
	client_hello := &ClientHello{}

	// version
	client_hello.Version = MMTLS_VERSION_F104

	// cipher_suite_list
	client_hello.CipherSuiteList = append(client_hello.CipherSuiteList, &CipherSuite{
		SuiteCode: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	})

	// random
	client_hello.RandomBytes = random_bytes(0x20)

	// time stamp
	client_hello.ClientGmtTime = (uint32)(time.Now().Unix())

	// extension_list
	client_hello.ExtensionList = append(client_hello.ExtensionList, create_client_key_share_extension(ecdh_keys))

	return client_hello
}

// 1-RTT PSK
func new_psk_hello_one(ticket []*SessionTicket, ecdh_keys *ClientEcdhKeys) *ClientHello {
	client_hello := &ClientHello{}

	// version
	client_hello.Version = MMTLS_VERSION_F104

	// cipher_suite_list
	client_hello.CipherSuiteList = append(client_hello.CipherSuiteList, &CipherSuite{
		SuiteCode: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	})

	if len(ticket) > 1 {
		client_hello.CipherSuiteList = append(client_hello.CipherSuiteList, &CipherSuite{
			SuiteCode: TLS_PSK_WITH_AES_128_GCM_SHA256,
		})
	}

	// random
	client_hello.RandomBytes = random_bytes(0x20)

	// time stamp
	client_hello.ClientGmtTime = (uint32)(time.Now().Unix())

	// extension_list
	if len(ticket) > 1 {
		client_hello.ExtensionList = append(client_hello.ExtensionList, create_psk_extension(ticket[1]))
	}
	client_hello.ExtensionList = append(client_hello.ExtensionList, create_client_key_share_extension(ecdh_keys))

	return client_hello
}

// 0-RTT PSK
func new_psk_hello_zero(ticket []*SessionTicket) *ClientHello {
	client_hello := &ClientHello{}

	if len(ticket) < 1 {
		panic("0-rtt psk 模式 ticket 不能为空")
	}
	// version
	client_hello.Version = MMTLS_VERSION_F104

	// cipher_suite_list
	client_hello.CipherSuiteList = append(client_hello.CipherSuiteList, &CipherSuite{
		SuiteCode: TLS_PSK_WITH_AES_128_GCM_SHA256,
	})

	// random
	client_hello.RandomBytes = random_bytes(0x20)

	// time stamp
	client_hello.ClientGmtTime = (uint32)(time.Now().Unix())

	// extension_list
	client_hello.ExtensionList = append(client_hello.ExtensionList, create_psk_extension(ticket[0]))

	return client_hello
}

func (ch *ClientHello) serialize() []byte {
	bodyData := make([]byte, 0)
	// Type
	bodyData = append(bodyData, ClientHelloType)

	// Version
	bodyData = binary.LittleEndian.AppendUint16(bodyData, ch.Version)

	// suiteCount
	suiteCount := byte(len(ch.CipherSuiteList))
	bodyData = append(bodyData, suiteCount)

	// suiteList
	suiteList := ch.CipherSuiteList
	for index := 0; index < int(suiteCount); index++ {
		// suiteCode
		bodyData = binary.BigEndian.AppendUint16(bodyData, suiteList[index].SuiteCode)
	}

	// RandomBytes
	bodyData = append(bodyData, ch.RandomBytes[:]...)

	// ClientGmtTime
	bodyData = binary.BigEndian.AppendUint32(bodyData, ch.ClientGmtTime)

	// Extensions
	bodyData = append(bodyData, extensions_serialize(ch.ExtensionList)...)

	// 返回数据
	retBytes := make([]byte, 0)
	totalLength := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, totalLength)
	retBytes = append(retBytes, bodyData[0:]...)
	return retBytes
}
