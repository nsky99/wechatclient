package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/golang/protobuf/proto"
)

type MmPacket struct {
	ClientVersion         uint32
	ReturnCode            uint32
	Uin                   uint32 // 如果是packet就是输入参数，如果是unpacket就是输出参数
	ReportArg             uint32 // 如果是packet就是输入参数，如果是unpacket就是输出参数
	Sn                    uint32
	Cookies               []byte // 如果是packet就是输入参数，如果是unpacket就是输出参数
	Calgo                 byte   // 0x2 Calgo == 2是未压缩否则是压缩, 1是压缩
	Ealgo                 byte   // 0xc CryptAlgorithm
	HaveCheckSum          bool   // 是否需要计算校验和
	Clen                  int    // 数据压缩前的长度
	Cdlen                 int    // 数据压缩后的长度
	UnpackCode            uint32
	SessionKey            []byte // 加密时候用到的秘钥
	ServerSessionKey      []byte // 解密中会用到的秘钥
	SessionKeyOrNotifyKey []byte // 解密中会用到的秘钥
	Loginecdhkey          []byte // 计算校验和
	EcdhClient            *HybridEcdhClient
}

// 组包
func (mmpkt *MmPacket) PackMessage(data []byte) []byte {
	header := new(bytes.Buffer)

	header.Write([]byte{0xbf})
	header.Write([]byte{mmpkt.Calgo&3 | 4*0}) // 0不知道是什么

	// cookieLen & 0xF + Ealog<<4
	// 高4位存放Ealog，低4位存放cookieLen
	header.Write([]byte{(byte(len(mmpkt.Cookies)) & 0xF) | (0x10 * mmpkt.Ealgo)})

	// 写入clientVersion
	binary.Write(header, binary.BigEndian, mmpkt.ClientVersion)

	// 写入uin
	binary.Write(header, binary.BigEndian, mmpkt.Uin)

	// 写入cookies
	header.Write(mmpkt.Cookies)

	// 写入功能id
	header.Write(proto.EncodeVarint(uint64(mmpkt.ReportArg)))

	// clen - 原数据长度
	header.Write(proto.EncodeVarint(uint64(mmpkt.Clen)))

	// cdlen - 压缩后的长度
	header.Write(proto.EncodeVarint(uint64(mmpkt.Cdlen)))

	// sn - HybridKeyVer
	header.Write(proto.EncodeVarint(uint64(mmpkt.Sn)))

	// 固定值0xf,不知道是什么的长度，应该是cookieslen的最大长度吧
	header.Write(proto.EncodeVarint(uint64(0xF)))

	if mmpkt.HaveCheckSum {
		// checksum
		header.Write(proto.EncodeVarint(uint64(CalculateMD5Checksum(mmpkt.Uin, mmpkt.Loginecdhkey, data))))

		if header.Len()+1 <= 0x400 {
			header.Write([]byte{0})
			// rqt
			header.Write(proto.EncodeVarint(uint64(RqtCalcData(data))))
		}

		if header.Len()+1 <= 0x400 {
			header.Write([]byte{0})
		}

		if header.Len()+1 <= 0x400 {
			header.Write([]byte{0})
			// debug port
			header.Write(proto.EncodeVarint(uint64(0x0000)))
		}
	}

	// check len
	lens := header.Len()

	// have checksum
	if mmpkt.HaveCheckSum {
		if lens-1 <= 0x3d {
			header.Bytes()[1] &= 3
			header.Bytes()[1] |= byte(lens * 4)
		}
	} else if lens < 0x2f {
		header.Bytes()[0] &= 3
		header.Bytes()[0] |= byte(lens * 4)
	}

	// encodeData
	header.Write(data)
	return header.Bytes()
}

// 解包
func (mmpkt *MmPacket) UnPackMessage(data []byte) []byte {
	var bfbit byte
	var nCur int64
	srcreader := bytes.NewReader(data)
	binary.Read(srcreader, binary.BigEndian, &bfbit)
	if bfbit == byte(0xbf) {
		// have_checksum=1
		nCur += 1 // 表示第一个bfbit已经读取
	}

	// 读取len header
	mmpkt.Calgo = data[nCur] & 3 // 0x2
	nLenHeader := data[nCur] >> 2
	nCur += 1

	// 读取cookies长度
	mmpkt.Ealgo = data[nCur] >> 4 // 0xc
	nLenCookie := data[nCur] & 0xf
	nCur += 1

	// 读取server retcode
	var retCode uint32
	srcreader.Seek(nCur, io.SeekStart)
	binary.Read(srcreader, binary.BigEndian, &retCode)
	mmpkt.ReturnCode = retCode
	nCur += 4 // UnpackCode

	// 读取uin
	var Uin uint32
	srcreader.Seek(nCur, io.SeekStart)
	binary.Read(srcreader, binary.BigEndian, &Uin)
	mmpkt.Uin = Uin
	nCur += 4 // uin

	// cookies, 服务端返回的cookies
	mmpkt.Cookies = data[nCur : nCur+int64(nLenCookie)]
	nCur += int64(nLenCookie)

	// ReportArg
	Value, Len := proto.DecodeVarint(data[nCur:])
	mmpkt.ReportArg = uint32(Value)
	nCur += int64(Len)

	return data[nLenHeader:]
}

// 000000018296ECD0 EncodeEcdhEncryptPack
func (mmpkt *MmPacket) EncodeEcdhEncryptPack(data []byte) []byte {
	return mmpkt.EcdhClient.Encrypt(data)
}

// 普通组包
func (mmpkt *MmPacket) EncodePack(data []byte) []byte {
	var body []byte

	mmpkt.Clen = len(data)
	if mmpkt.Ealgo == 13 {
		body = append(body, data...)
		mmpkt.Calgo = 2 // 没有在加密前压缩
		mmpkt.Cdlen = len(data)
	} else {
		// 压缩会出问题，现在没有找到问题所在
		compressData := ZlibCompress(data)
		// 压缩成功并且压缩后的数据小于压缩前的数据, 和组包细节有关， pack细节
		if len(compressData) < len(data) {
			body = append(body, compressData...)
			mmpkt.Cdlen = len(compressData)
			mmpkt.Calgo = 1 // 在加密前进行压缩
		} else {
			body = append(body, data...)
			mmpkt.Cdlen = len(data)
			mmpkt.Calgo = 2 // 没有在加密前压缩
		}
	}
	encodeData := mmpkt.EncryptPack(body)
	return mmpkt.PackMessage(encodeData)
}

// 普通加密，根据 ealog选择不同加密模式
func (mmpkt *MmPacket) EncryptPack(body []byte) []byte {
	switch mmpkt.Ealgo {
	case 1: //RSA
		break
	case 3: //DES
		break
	case 5: //AES
		return AesEncrypt(body, mmpkt.SessionKey)
	case 13: //AESWithCompress
		return AesGcmEncryptWithCompress(mmpkt.SessionKey, body, nil)
	}
	return nil
}

// 解码包
func (mmpkt *MmPacket) DecodePack(body []byte) []byte {
	// 区分解包方式
	if body[0]&0xfc <= 0xf4 {
		// unpackByMini
		return mmpkt.unpackByMini(body)
	} else if body[0] == 0xbe || body[len(body)-1] == 0xed {
		// unpackByTlv
		return mmpkt.unpackByTlv(body)
	}

	return nil
}

func (mmpkt *MmPacket) unpackByMini(body []byte) []byte {
	payload := mmpkt.UnPackMessage(body)

	// cookies is server id
	if mmpkt.ReturnCode == 0xfffffff3 {
		panic("unpack error: session timeout")
	}

	if mmpkt.ReturnCode == 0xffffff9a {
		panic("unpack error: cert expired")
	}

	// 检测应该使用哪个key
	var key []byte
	if mmpkt.Ealgo == 0xd {
		//server session keys
		key = append(key, mmpkt.ServerSessionKey...)
	} else {
		key = append(key, mmpkt.SessionKeyOrNotifyKey...)
	}

	payload = mmpkt.DecryptPack(payload, key)
	if mmpkt.Calgo == 2 {
		return payload
	} else if mmpkt.Calgo == 1 {
		return ZlibUnCompress(payload)
	}
	return nil
}

func (mmpkt *MmPacket) unpackByTlv(body []byte) []byte {
	fmt.Print("unpackByTlv\n", body)
	return nil
}

// 解密包
func (mmpkt *MmPacket) DecryptPack(body []byte, key []byte) []byte {
	if mmpkt.Ealgo == 0 {
		return nil
	}

	switch mmpkt.Ealgo {
	case 5:
		return AesDecrypt(body, key)
	case 13:
		// AesGcmDecryptWithUncompress
		return AesGcmDecryptWithUncompress(key, body, nil)
	case 12:
		payload, _ := mmpkt.EcdhClient.Decrypt(body)
		return payload
	default:
		// des
	}
	return nil
}
