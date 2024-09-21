package mmtls

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync/atomic"

	"github.com/wsddn/go-ecdh"
)

type MmtlsLinkLong struct {
	long_host        string          // szlong.weixin.qq.com; long.weixin.qq.com
	long_port        string          // 443; 8080; 80
	conn             net.Conn        // mmtls long link connect 用于网络通讯
	client_ecdh_keys *ClientEcdhKeys // mmtls long link 客户端交换密钥
	certSignVersion  uint32          // 签名使用的是哪个密钥
	handshake_hasher hash.Hash       // mmtls 记录每个握手过程
	server_seq       uint32          // 服务端seq
	client_seq       uint32          // 客户端seq

	// 握手的过程中计算得到
	session_tickets              []*SessionTicket // 会话票据
	handshake_traffic_key        *TrafficKeyPair  // handshake        数据加解密
	application_data_traffic_key *TrafficKeyPair  // application_data 数据加解密
	psk_access                   []byte           // psk access
	psk_refresh                  []byte           // psk refresh
}

// export NewMmtlsLinkLong
func NewMmtlsLinkLong(host string, port string) *MmtlsLinkLong {
	longlink := &MmtlsLinkLong{
		long_host:        host,
		long_port:        port,
		handshake_hasher: sha256.New(),
	}

	// 建立网络连接
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", longlink.long_host, longlink.long_port))
	if err != nil {
		panic(err)
	} else {
		longlink.conn = conn
	}

	// 生成客户端ecdh秘钥
	longlink.client_ecdh_keys = create_client_ecdh_keys()
	return longlink
}

// export Handshake
func (longlink *MmtlsLinkLong) Handshake() error {
	// send client hello
	if err := longlink.process_client_hello(); err != nil {
		return err
	}

	// recv server hello
	secret_key, err := longlink.process_server_hello()
	if err != nil {
		return err
	}
	longlink.handshake_traffic_key, err = calc_traffic_key(
		"handshake key expansion",
		longlink.handshake_hasher.Sum(nil),
		secret_key)
	if err != nil {
		return errors.New("calc_traffic_key faild ")
	}

	// recv CertificateVerify
	if err := longlink.process_certificate_verify(); err != nil {
		return errors.New("certificate_verify faild ")
	}

	// recv new session ticket
	if err := longlink.process_new_session_ticket(secret_key); err != nil {
		return errors.New("new_session_ticket faild ")
	}

	// server finish
	if err := longlink.process_server_finish(secret_key); err != nil {
		return errors.New("server_finish faild ")
	}

	// client finish
	if err := longlink.process_client_finish(secret_key); err != nil {
		return errors.New("server_finish faild ")
	}

	// 保存应用程序数据加解密key
	app_data_traffic_key, err := longlink.calc_application_data_traffic_key(secret_key)
	if err != nil {
		return err
	}
	longlink.application_data_traffic_key = app_data_traffic_key

	return nil
}

func (longlink *MmtlsLinkLong) SendNoop() error {
	// build
	noop := create_app_data_record_longlink(TCP_NoopRequest, nil, 0xFFFFFFFF)
	err := noop.encrypt(longlink.application_data_traffic_key, atomic.LoadUint32(&longlink.client_seq))
	if err != nil {
		return err
	}

	// send
	_, err = longlink.conn.Write(noop.serialize())
	atomic.AddUint32(&longlink.client_seq, 1)
	return err
}

func (longlink *MmtlsLinkLong) RecvNoop() error {
	noop, err := longlink.recv_record()
	if err != nil {
		return err
	}

	err = noop.decrypt(longlink.application_data_traffic_key, atomic.LoadUint32(&longlink.server_seq))
	if err != nil {
		return err
	}

	AppRecord := &LongLinkAppDataRecord{}
	err = AppRecord.deserialize(noop.Data)
	if err != nil {
		return err
	}
	if AppRecord.CmdId != TCP_NoopResponse {
		return errors.New("noop response packet type mismatch")
	}
	atomic.AddUint32(&longlink.server_seq, 1)
	return nil
}

func (longlink *MmtlsLinkLong) SendAppData(cmdid uint32, data []byte) (uint32, error) {
	// build
	record := create_app_data_record_longlink(cmdid, data, atomic.LoadUint32(&longlink.client_seq))
	err := record.encrypt(longlink.application_data_traffic_key, atomic.LoadUint32(&longlink.client_seq))
	if err != nil {
		return 0, err
	}

	// send
	_, err = longlink.conn.Write(record.serialize())
	return atomic.AddUint32(&longlink.client_seq, 1), err
}

func (longlink *MmtlsLinkLong) RecvAppData() (cmdid, server_seq uint32, data []byte, err error) {
	record, err := longlink.recv_record()
	if err != nil {
		return cmdid, server_seq, data, err
	}

	// 解密
	err = record.decrypt(longlink.application_data_traffic_key, atomic.LoadUint32(&longlink.server_seq))
	if err != nil {
		return cmdid, server_seq, data, err

	}

	// 检测是否断开连接
	if bytes.Equal(record.Data, get_alert_data()) {
		panic("longlink disconnect")
	}

	app_record := &LongLinkAppDataRecord{}
	err = app_record.deserialize(record.Data)
	if err != nil {
		return cmdid, server_seq, data, err
	}

	atomic.AddUint32(&longlink.server_seq, 1)
	return app_record.CmdId, app_record.Seq, app_record.Data, err
}

func (longlink *MmtlsLinkLong) Close() error {
	return longlink.conn.Close()
}

func (longlink *MmtlsLinkLong) process_client_hello() error {
	// build client hello
	var ch *ClientHello
	if len(longlink.session_tickets) > 1 {
		ch = new_psk_hello_one(longlink.session_tickets, longlink.client_ecdh_keys)

	} else {
		ch = new_ecdh_hello(longlink.client_ecdh_keys)
	}

	// 序列化client hello
	client_hello_data := ch.serialize()

	// build client hello record
	client_hello_record_data := create_handshake_record(client_hello_data).serialize()

	// send to server
	_, err := longlink.conn.Write(client_hello_record_data)
	atomic.AddUint32(&longlink.client_seq, 1)

	// update hash
	longlink.handshake_hasher.Write(client_hello_data)
	return err
}

func (longlink *MmtlsLinkLong) process_server_hello() ([]byte, error) {
	// read server hello
	record, err := longlink.recv_record()
	if err != nil {
		return nil, err
	}
	if record.Type != RECORD_HANDSHAKE {
		return nil, errors.New("record is not handshake record")
	}

	// 解析server hello
	sh := &ServerHello{}
	err = sh.deserialize(record.Data)
	if err != nil {
		return []byte{}, err
	}

	// 解析server key share
	ske := &ServerKeyShareExtension{}
	err = ske.deserialize(sh.ExtensionList[0].ExtensionData)
	if err != nil {
		return []byte{}, err
	}
	ecdhTool := ecdh.NewEllipticECDH(elliptic.P256())
	serverPubKey, isOk := ecdhTool.Unmarshal(ske.PublicValue)
	if !isOk {
		return []byte{}, errors.New("ecdhTool.Unmarshal(ske.PublicValue) failed")
	}

	// 根据NameGroup 决定使用哪个Privakey
	ecdhPriKey := longlink.client_ecdh_keys.EcdhPriKey
	if ske.KeyOfferNameGroup == 6 {
		ecdhPriKey = longlink.client_ecdh_keys.EcdhVerifyPriKey
	}

	// 协商密钥
	secretKey, err := ecdhTool.GenerateSharedSecret(ecdhPriKey, serverPubKey)
	if err != nil {
		return []byte{}, err
	}
	secretKeySha := sha256.Sum256(secretKey)

	// 决定使用那个ecdsa 校验签名数据
	cr := &CertRegionExtension{}
	err = cr.deserialize(sh.ExtensionList[1].ExtensionData)
	if err != nil {
		return []byte{}, err
	}
	longlink.certSignVersion = cr.CertVersion

	// update hash
	longlink.handshake_hasher.Write(record.Data)
	atomic.AddUint32(&longlink.server_seq, 1)

	return secretKeySha[:], err
}

func (longlink *MmtlsLinkLong) process_certificate_verify() error {

	// read data
	record, err := longlink.recv_record()
	if err != nil {
		return err
	}
	if record.Type != RECORD_HANDSHAKE {
		return errors.New("record is not handshake record")
	}

	// 解密
	err = record.decrypt(longlink.handshake_traffic_key, atomic.LoadUint32(&longlink.server_seq))
	if err != nil {
		return err
	}

	// 解析
	cv := &CertificateVerify{}
	err = cv.deserialize(record.Data)
	if err != nil {
		return err
	}

	// process
	message := sha256.Sum256(longlink.handshake_hasher.Sum(nil))
	err = cv.verify_ecdsa(longlink.certSignVersion, message[:])
	if err != nil {
		return err
	}

	// update hash
	longlink.handshake_hasher.Write(record.Data)
	atomic.AddUint32(&longlink.server_seq, 1)
	return nil
}

func (longlink *MmtlsLinkLong) process_new_session_ticket(secret_key []byte) error {
	// read data
	record, err := longlink.recv_record()
	if err != nil {
		return err
	}
	if record.Type != RECORD_HANDSHAKE {
		return errors.New("record is not handshake record")
	}

	// 解密
	err = record.decrypt(longlink.handshake_traffic_key, atomic.LoadUint32(&longlink.server_seq))
	if err != nil {
		return err
	}

	// 解析
	new_session_tickets := &NewSessionTicket{}
	err = new_session_tickets.deserialize(record.Data)
	if err != nil {
		return err
	}
	longlink.session_tickets = new_session_tickets.SessionTickets

	// psk access
	expandPskAccessData := append([]byte("PSK_ACCESS"), longlink.handshake_hasher.Sum(nil)...)
	longlink.psk_access = hkdf_expand(secret_key, expandPskAccessData, 32)

	expandPskRefReshData := append([]byte("PSK_REFRESH"), longlink.handshake_hasher.Sum(nil)...)
	longlink.psk_refresh = hkdf_expand(secret_key, expandPskRefReshData, 32)

	// update hash
	longlink.handshake_hasher.Write(record.Data)
	atomic.AddUint32(&longlink.server_seq, 1)
	return nil
}

func (longlink *MmtlsLinkLong) process_server_finish(secret_key []byte) error {

	// read data
	record, err := longlink.recv_record()
	if err != nil {
		return err
	}
	if record.Type != RECORD_HANDSHAKE {
		return errors.New("process_server_finish record is not handshake record")
	}

	// 解密
	err = record.decrypt(longlink.handshake_traffic_key, atomic.LoadUint32(&longlink.server_seq))
	if err != nil {
		return err
	}

	// 解析
	sf := &ServerFinished{}
	err = sf.deserialize(record.Data)
	if err != nil {
		return err
	}

	// 验证数据
	err = sf.verify_data(secret_key, longlink.handshake_hasher.Sum(nil))
	if err != nil {
		return err
	}

	atomic.AddUint32(&longlink.server_seq, 1)

	return nil
}

func (longlink *MmtlsLinkLong) process_client_finish(secret_key []byte) error {
	// build handshake data
	cf := new_client_finished(secret_key, longlink.handshake_hasher.Sum(nil))
	client_finished_data := cf.serialize()

	// build record data and encrypt
	cf_record := create_handshake_record(client_finished_data)
	err := cf_record.encrypt(longlink.handshake_traffic_key, atomic.LoadUint32(&longlink.client_seq))
	if err != nil {
		return err
	}
	client_finished_record_data := cf_record.serialize()

	// send
	_, err = longlink.conn.Write(client_finished_record_data)
	atomic.AddUint32(&longlink.client_seq, 1)
	return err
}

func (longlink *MmtlsLinkLong) recv_record() (*Record, error) {
	// read record header - 用于确认后面要读取的数据长度
	header := make([]byte, 5)
	if _, err := io.ReadFull(longlink.conn, header); err != nil {
		return nil, err
	}
	record := &Record{}
	record.deserialize_header(header)

	// read record data
	payload := make([]byte, record.Size)
	if _, err := io.ReadFull(longlink.conn, payload); err != nil {
		return nil, err
	}
	record.Data = payload
	return record, nil
}

func (longlink *MmtlsLinkLong) calc_application_data_traffic_key(secret_key []byte) (*TrafficKeyPair, error) {
	expandedSecret := hkdf_expand(
		secret_key,
		append([]byte("expanded secret"), longlink.handshake_hasher.Sum(nil)...),
		32)

	return calc_traffic_key("application data key expansion", longlink.handshake_hasher.Sum(nil), expandedSecret)
}
