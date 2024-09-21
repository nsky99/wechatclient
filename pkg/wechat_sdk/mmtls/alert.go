package mmtls

type Alert struct {
	AlertLevel   byte
	AlertType    uint16
	FallBackURL  []byte
	SignatureURL []byte
}

func get_alert_data() []byte {
	return []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x01}
}
