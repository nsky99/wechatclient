package util

var (
	AInfo AccountInfo
)

type AccountInfo struct {
	Uin                 uint32 // 登录的标识符
	Wxid                string
	DeviceId            string
	DeviceType          string
	DeviceName          string
	ClientVersion       int
	NewClientVersion    int
	NickName            string
	Alais               string
	Mobile              string
	SessionkeyPlaintext []byte
	Sessionkey          []byte
	Autoauthkey         []byte
	Clientsessionkey    []byte
	Serversessionkey    []byte
	Loginecdhkey        []byte
	AuthTicket          string
}
