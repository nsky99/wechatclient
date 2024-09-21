package mmtls

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/wsddn/go-ecdh"
)

type MmtlsLinkShort struct {
	host                         string           // szlong.weixin.qq.com; long.weixin.qq.com
	port                         string           // 443; 8080; 80
	client_ecdh_keys             *ClientEcdhKeys  // mmtls long link 客户端交换密钥
	certSignVersion              uint32           // 签名使用的是哪个密钥
	handshake_hasher             hash.Hash        // mmtls 记录每个握手过程
	server_seq                   uint32           // 服务端seq
	client_seq                   uint32           // 客户端seq
	session_tickets              []*SessionTicket // 会话票据
	handshake_traffic_key        *TrafficKeyPair  // handshake        数据加解密
	application_data_traffic_key *TrafficKeyPair  // application_data 数据加解密
	psk_access                   []byte           // psk access
	psk_refresh                  []byte           // psk refresh
}

func NewMmtlsLinkShort(host, port string) *MmtlsLinkShort {
	ls := &MmtlsLinkShort{
		host:             host,
		port:             port,
		handshake_hasher: sha256.New(),
	}

	ls.client_ecdh_keys = create_client_ecdh_keys()
	return ls
}

func (ls *MmtlsLinkShort) Handshake() error {
	client_hello_pkt, err := ls.process_client_hello()
	if err != nil {
		return err
	}
	response, err := ls.post(client_hello_pkt)
	if err != nil {
		return err
	}

	rs := ls.parser_record_items(response)
	if len(rs) < 4 {
		return errors.New("short link handshake faild")
	}

	// process server hello
	secret_key, err := ls.process_server_hello(rs[0])
	if err != nil {
		return err
	}

	// 计算握手流量秘钥
	ls.handshake_traffic_key, err = calc_traffic_key(
		"handshake key expansion",
		ls.handshake_hasher.Sum(nil),
		secret_key)
	if err != nil {
		return errors.New("calc_traffic_key faild ")
	}

	// recv CertificateVerify
	if err := ls.process_certificate_verify(rs[1]); err != nil {
		return errors.New("certificate_verify faild ")
	}

	// recv new session ticket
	if err := ls.process_new_session_ticket(secret_key, rs[2]); err != nil {
		return errors.New("new_session_ticket faild ")
	}

	// server finish
	if err := ls.process_server_finish(secret_key, rs[3]); err != nil {
		return errors.New("server_finish faild ")
	}

	// 保存应用程序数据加解密key
	app_data_traffic_key, err := ls.calc_application_data_traffic_key(secret_key)
	if err != nil {
		return err
	}
	ls.application_data_traffic_key = app_data_traffic_key

	return nil
}

func (ls *MmtlsLinkShort) Request(path string, data []byte) ([]byte, error) {
	ls.handshake_hasher.Reset()
	atomic.StoreUint32(&ls.client_seq, 0)
	atomic.StoreUint32(&ls.server_seq, 0)

	// packet http
	request_data, err := ls.serialize_request(path, data)
	if err != nil {
		return nil, err
	}
	response, err := ls.post(request_data)
	if err != nil {
		return nil, err
	}

	// 解析
	rs := ls.parser_record_items(response)
	if len(rs) < 4 {
		return nil, errors.New("response items < 4")
	}

	// 解析出来app response data
	return ls.deserialize_response(rs)
}

func (ls *MmtlsLinkShort) post(data []byte) ([]byte, error) {
	url := "http://" + ls.host + ":" + ls.port + "/mmtls/" + hex.EncodeToString(random_bytes(4))
	request, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", "*/*")
	request.Header.Add("Cache-Control", "no-cache")
	request.Header.Set("Connection", "Keep-Alive")
	request.Header.Add("Content-Type", "application/octet-stream")
	request.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
	request.Header.Add("Upgrade", "mmtls")
	request.Header.Add("Host", ls.host)
	request.Header.Add("UserAgent", "MicroMessenger Client")

	httpTransport := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 60 * time.Second,
		}).Dial,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     time.Second * 60,
	}

	client := &http.Client{Transport: httpTransport, Timeout: time.Second * 5}
	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func (ls *MmtlsLinkShort) process_client_hello() ([]byte, error) {
	// build client hello
	var ch *ClientHello
	if len(ls.session_tickets) > 1 {
		ch = new_psk_hello_one(ls.session_tickets, ls.client_ecdh_keys)

	} else {
		ch = new_ecdh_hello(ls.client_ecdh_keys)
	}

	// 序列化client hello
	client_hello_data := ch.serialize()

	// build client hello record
	client_hello_record_data := create_handshake_record(client_hello_data).serialize()

	// update hash
	atomic.AddUint32(&ls.client_seq, 1)
	ls.handshake_hasher.Write(client_hello_data)
	return client_hello_record_data, nil
}

func (ls *MmtlsLinkShort) process_server_hello(record *Record) ([]byte, error) {
	if (record.Type != RECORD_HANDSHAKE) && (record.Type != RECORD_EARLY_HANDSHAKE) {
		return nil, errors.New("record is not handshake record")
	}

	// 解析server hello
	sh := &ServerHello{}
	err := sh.deserialize(record.Data)
	if err != nil {
		return []byte{}, err
	}

	// 解析server key share
	if len(sh.ExtensionList) == 0 {
		return []byte{}, nil
	}

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
	ecdhPriKey := ls.client_ecdh_keys.EcdhPriKey
	if ske.KeyOfferNameGroup == 6 {
		ecdhPriKey = ls.client_ecdh_keys.EcdhVerifyPriKey
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
	ls.certSignVersion = cr.CertVersion

	// update hash
	ls.handshake_hasher.Write(record.Data)
	atomic.AddUint32(&ls.server_seq, 1)

	return secretKeySha[:], err
}

func (ls *MmtlsLinkShort) process_certificate_verify(record *Record) error {

	if record.Type != RECORD_HANDSHAKE {
		return errors.New("record is not handshake record")
	}

	// 解密
	err := record.decrypt(ls.handshake_traffic_key, atomic.LoadUint32(&ls.server_seq))
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
	message := sha256.Sum256(ls.handshake_hasher.Sum(nil))
	err = cv.verify_ecdsa(ls.certSignVersion, message[:])
	if err != nil {
		return err
	}

	// update hash
	ls.handshake_hasher.Write(record.Data)
	atomic.AddUint32(&ls.server_seq, 1)
	return nil
}

func (ls *MmtlsLinkShort) process_new_session_ticket(secret_key []byte, record *Record) error {
	if record.Type != RECORD_HANDSHAKE {
		return errors.New("record is not handshake record")
	}

	// 解密
	err := record.decrypt(ls.handshake_traffic_key, atomic.LoadUint32(&ls.server_seq))
	if err != nil {
		return err
	}

	// 解析
	new_session_tickets := &NewSessionTicket{}
	err = new_session_tickets.deserialize(record.Data)
	if err != nil {
		return err
	}
	ls.session_tickets = new_session_tickets.SessionTickets

	// psk access
	ls.psk_access = hkdf_expand(secret_key,
		append([]byte("PSK_ACCESS"), ls.handshake_hasher.Sum(nil)...),
		32)
	ls.psk_refresh = hkdf_expand(secret_key,
		append([]byte("PSK_REFRESH"), ls.handshake_hasher.Sum(nil)...),
		32)

	// update hash
	ls.handshake_hasher.Write(record.Data)
	atomic.AddUint32(&ls.server_seq, 1)
	return nil
}

func (ls *MmtlsLinkShort) process_server_finish(secret_key []byte, record *Record) error {

	if record.Type != RECORD_HANDSHAKE {
		return errors.New("process_server_finish record is not handshake record")
	}

	// 解密
	err := record.decrypt(ls.handshake_traffic_key, atomic.LoadUint32(&ls.server_seq))
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
	err = sf.verify_data(secret_key, ls.handshake_hasher.Sum(nil))
	if err != nil {
		return err
	}

	atomic.AddUint32(&ls.server_seq, 1)

	return nil
}

func (ls *MmtlsLinkShort) process_app_data(record *Record) ([]byte, error) {

	if record.Type != RECORD_APPLICATION_DATA {
		return nil, errors.New("process_server_finish record is not handshake record")
	}

	// 解密
	err := record.decrypt(ls.handshake_traffic_key, atomic.LoadUint32(&ls.server_seq))
	if err != nil {
		return nil, err
	}

	atomic.AddUint32(&ls.server_seq, 1)

	return record.Data, nil
}

func (ls *MmtlsLinkShort) process_alert(record *Record) error {

	if record.Type != RECORD_ALERT {
		return errors.New("process_server_finish record is not handshake record")
	}

	// 解密
	err := record.decrypt(ls.handshake_traffic_key, atomic.LoadUint32(&ls.server_seq))
	if err != nil {
		return err
	}

	atomic.AddUint32(&ls.server_seq, 1)
	return nil
}

func (ls *MmtlsLinkShort) parser_record_items(data []byte) []*Record {
	var rs []*Record
	for current := 0; current < len(data); {
		r := &Record{}
		r.deserialize(data[current:])
		current += int(r.Size) + 5
		rs = append(rs, r)
	}
	return rs
}

func (ls *MmtlsLinkShort) serialize_request(url string, data []byte) ([]byte, error) {
	var rs []*Record
	// client hello
	ch := new_psk_hello_zero(ls.session_tickets)
	rs = append(rs, create_early_handshake_record(ch.serialize()))
	ls.handshake_hasher.Write(rs[0].Data)

	// early key
	expandSecretData := append([]byte("early data key expansion"), ls.handshake_hasher.Sum(nil)...)
	tmpHkdfValue := hkdf_expand(ls.psk_access, expandSecretData, 28)
	early_traffic_key := &TrafficKeyPair{
		ClientWriteKey: tmpHkdfValue[0:0x10],
		ClientWriteIv:  tmpHkdfValue[0x10:],
	}

	// Encrypted Extensions
	es := create_encrypted_extensions()
	rs = append(rs, create_early_handshake_record(es.serialize()))
	ls.handshake_hasher.Write(rs[1].Data)

	// http request data
	http_handler := new_http_handler(url, ls.host, data)
	rs = append(rs, create_app_data_record_shortlink(http_handler.serialize()))

	// alert
	rs = append(rs, create_aleret_record(get_alert_data()))

	// client hello 1
	atomic.AddUint32(&ls.client_seq, 1)

	if err := rs[1].encrypt(early_traffic_key, atomic.LoadUint32(&ls.client_seq)); err != nil {
		return nil, errors.New("decode encrypted extensions error")
	}
	atomic.AddUint32(&ls.client_seq, 1)

	if err := rs[2].encrypt(early_traffic_key, atomic.LoadUint32(&ls.client_seq)); err != nil {
		return nil, errors.New("decode http request data error")
	}
	atomic.AddUint32(&ls.client_seq, 1)

	if err := rs[3].encrypt(early_traffic_key, atomic.LoadUint32(&ls.client_seq)); err != nil {
		return nil, errors.New("decode alert error")
	}

	var retBytes []byte
	for _, r := range rs {
		retBytes = append(retBytes, r.serialize()...)
	}
	return retBytes, nil
}

func (ls *MmtlsLinkShort) deserialize_response(records []*Record) ([]byte, error) {

	// update hash server hello
	if _, err := ls.process_server_hello(records[0]); err != nil {
		return nil, err
	}

	ls.handshake_hasher.Write(records[0].Data)
	atomic.AddUint32(&ls.server_seq, 1)

	// calc key
	sha256Value := ls.handshake_hasher.Sum(nil)
	tmpHkdfValue := hkdf_expand(
		ls.psk_access,
		append([]byte("handshake key expansion"), sha256Value[:]...),
		28)
	ls.handshake_traffic_key = &TrafficKeyPair{
		ClientReadKey: tmpHkdfValue[0x00:0x10],
		ClientReadIv:  tmpHkdfValue[0x10:0x1c],
	}

	var http_respnse []byte
	for i, r := range records {
		if i == 0 {
			continue
		}

		switch r.Type {
		case RECORD_HANDSHAKE:

			if err := ls.process_server_finish(ls.psk_access, r); err != nil {
				return nil, err
			}
		case RECORD_APPLICATION_DATA:
			tmp, err := ls.process_app_data(r)
			if err != nil {
				return nil, err
			}
			http_respnse = append(http_respnse, tmp...)
		case RECORD_ALERT:
			if err := ls.process_alert(r); err != nil {
				return nil, err
			}
		default:
			fmt.Printf("unknow record type: %d \n", r.Type)
		}
	}
	return http_respnse, nil
}

func (ls *MmtlsLinkShort) calc_application_data_traffic_key(secret_key []byte) (*TrafficKeyPair, error) {
	expandedSecret := hkdf_expand(
		secret_key,
		append([]byte("expanded secret"), ls.handshake_hasher.Sum(nil)...),
		32)

	return calc_traffic_key("application data key expansion", ls.handshake_hasher.Sum(nil), expandedSecret)
}
