package mmtls

// mmtls 版本
const (
	MMTLS_VERSION_F103 = 0xF103
	MMTLS_VERSION_F104 = 0xF104
)

// mmtls 密码加密套件
const (
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_PSK_WITH_AES_128_GCM_SHA256         uint16 = 0x00a8
)

// 加密算法对应类型
const (
	PreSharedKeyExtensionType uint16 = 0x0f
	ClientKeyShareType        uint16 = 0x10
	ServerKeyShareType        uint16 = 0x11
	EarlyEncryptDataType      uint16 = 0x12
	CertRegionType            uint16 = 0x13
)

// mmtls握手对应步骤
const (
	ClientHelloType         byte = 1  // 客户端发送打招呼
	ServerHelloType         byte = 2  // 服务端发送打招呼
	NewSessionTicketType    byte = 4  // 会话票据
	EncryptedExtensionsType byte = 8  // 发送加密扩展信息
	ServerHelloDoneType     byte = 14 // 服务端握手完成
	CertificateVerifyType   byte = 15 // 验证签名
	FinishedType            byte = 20 // 结束握手
)

const (
	TCP_NoopRequest  uint32 = 0x6
	TCP_NoopResponse uint32 = 0x3B9ACA06
)
