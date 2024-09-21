package mmtls

import "encoding/binary"

type HttpHandler struct {
	Url       string
	Host      string
	MmPackage []byte
}

func new_http_handler(url, host string, data []byte) *HttpHandler {
	return &HttpHandler{
		Url:       url,
		Host:      host,
		MmPackage: data,
	}
}

func (hh *HttpHandler) serialize() []byte {
	bodyData := make([]byte, 0)
	// URL
	urlLength := uint16(len(hh.Url))
	bodyData = binary.BigEndian.AppendUint16(bodyData, urlLength)
	bodyData = append(bodyData, []byte(hh.Url)[0:]...)

	// Host
	hostLength := uint16(len(hh.Host))
	bodyData = binary.BigEndian.AppendUint16(bodyData, hostLength)
	bodyData = append(bodyData, []byte(hh.Host)[0:]...)

	// MMPkg
	mmpkgLength := uint32(len(hh.MmPackage))
	bodyData = binary.BigEndian.AppendUint32(bodyData, mmpkgLength)
	bodyData = append(bodyData, hh.MmPackage[:]...)

	// 返回数据
	retBytes := make([]byte, 0)
	bodyDataLen := uint32(len(bodyData))
	retBytes = binary.BigEndian.AppendUint32(retBytes, bodyDataLen)
	retBytes = append(retBytes, bodyData[0:]...)
	return retBytes
}
