package scene

import (
	wechatsdk "wechatclient/pkg/wechat_sdk"
	"wechatclient/pkg/wechat_sdk/config"
	micromsg "wechatclient/pkg/wechat_sdk/mmpb/src"
	"wechatclient/pkg/wechat_sdk/mmscene/packet"

	"google.golang.org/protobuf/proto"
)

type NetSceneGetLoginQrcode struct {
	UserInfo   *wechatsdk.WxUserInfo
	DeviceId   string
	DeviceType string
	DeviceName string
}

func (ns *NetSceneGetLoginQrcode) Req2Buf() ([]byte, error) {
	randomKey := []byte(packet.Random(0x10)) // 获取随机密钥

	GetLoginQrCodeProto := &micromsg.GetLoginQRCodeRequest{
		BaseRequest: &micromsg.BaseRequest{
			SessionKey:    []byte("\u0000"),
			Uin:           proto.Uint32(ns.UserInfo.AuthUin),
			DeviceId:      []byte(ns.DeviceId),
			ClientVersion: proto.Uint32(config.WechatClientVersion),
			DeviceType:    []byte(ns.DeviceType),
			Scene:         proto.Uint32(0),
		},
		RandomEncryKey: &micromsg.SKBuiltinBufferT{
			ILen:   proto.Int32(int32(len(randomKey))),
			Buffer: randomKey,
		},
		Opcode:           proto.Uint32(0),
		DeviceName:       []byte(ns.DeviceName),
		MsgContextPubKey: nil,
	}

	GetLoginQrCodeProtoData, _ := proto.Marshal(GetLoginQrCodeProto)

	nsb := NetSeceneBase{
		CmdId:     CmdIdGetLoginQrCode,
		ReportArg: ReportArgGetLoginQrCode,
		UserInfo:  ns.UserInfo,
	}

	return nsb.EncodeEcdhReqBuf(GetLoginQrCodeProtoData), nil
}

//	{
//		"baseResponse": {
//			"ret": 0,
//			"errMsg": {}
//		},
//		"qrcode": {
//			"iLen": 3748,
//			"buffer": "iVBORw0KGgoAAAANSUhEUgAAALkAAAC5CAYAAAB0rZ5cAAAOa0lEQVR4Ae3BwZHEyJJDwQca1UHqL0eMQNg9B+sQxmZN9/Cnu4DwRyQRjaQwkETcJCk0ScSApNAkEY2k0CQRA5JCk0Q8SFIYSCIGJIU/4rTNX2abb7PNXbaZsM1dtvk22zzJNn/FwcbGqx1sbLzawcbGq518UFV821qLb5MUBmxzV1XRSQpNEp4kKTwoCd1aiydVFd+21qI7+Ux8X/gy2/wLRGM7XIkH2eZh4io8S3xfaA42Nl7tYGPj1Q42Nl7tZEhSuCmJuKmquKuq6NZadFXFXZJCk4ROUmiSiAdVFd8mKTRJxE2Swk1JxMDJkG1+ibhPXIUrcZNtPhCN7fB94sts8yTbfNvBxsarHWxsvNrBxsarnfxxkkKTRDxIUhhIIpqqYqKq+CskhQHbvMHJH2ebb7PND4gZ8UfY5n/JwcbGqx1sbLzawcbGq538B0kKNyXhSZLCQBIxICk0tumqik5SGLDN/5KT/yDb/IB4kG2eZJsh0dgOG93BxsarHWxsvNrBxsarnQxVFX9ZVdGttegkhSaJaCSFgSR0ay06SaFJIh5UVUystfgrqopvO5kTf5u4Co1tJmwzJK5CY5t/gZgJf4f4soONjVc72Nh4tYONjVc7+UBS+DLb3FVVdJJCk4RurcVdVUUnKTRJ6NZa3FVVdJJCk0Q0kkKThG6tRVdVdGst7pIUvsw23ckHtvnjRGM7XImrcJ9obIcrcRXuE43tMGCbD8RVuBJX4Sbb/IaDjY1XO9jYeLWDjY1XO6uKv6yquEtSaGxzl6TQ2KaTFBrbdJJCY5uJqqKTFBrbPKmqmKgq/ooTEH+buMk2T7LNhG0mbPMDorEdvk/MiD/iYGPj1Q42Nl7tYGPj1U5+QFJokogBSaFJIm6qKrq1FhOSQpOEu9Za3FVVdJLCQBKeJCkMJBEDksJNSUQjKQyc/IBt7rLNw8RVGLDNB+K+cJ9obIcZ8SDbPMk2T7LNxMHGxqsdbGy82sHGxqudDEkKTRI6SaFJIpqq4i5JYSAJd0kKN9mmqyq6tRadpNDYZkJSaJKIRlJoktCttZiQFAaS8BtOhmzzgWhshxlxk22GxE22w7PEVWhsc5dtJmzzgbgKA7YZEr/gYGPj1Q42Nl7tYGPj1QSEgSR0kuhs01WVaCSFJoloJIXGNl1V8YFoJIUmibgKzVqLrqro1lp0VSWuQrPWoqsq7pJEl4QPxFVo1lp0VUW31qKrKtFICk0SMROatRbdaZsh0dgON9lmwjZDYsA2Q+IqXImrMCOuwpW4yXa4EjPiKlyJqzBgmx8QV6E52Nh4tYONjVc72Nh4tZOHVRWdpNAkoZMUGtt0VUUnKTRJRFNVTEgKTRImqopOUmiSiKaqmJAUBmzTSQpNEtFICk0SJqqKuySFJokYqCq6k+eJxna4Eo3tMCMa22FGDNjmAzEjGtthRgzY5i7bTNjmAzEjbrLND4jmYGPj1Q42Nl7tYGPj1U6GJIXGNp2k0CShkxQa23ybpDCQhAlJYSAJE5JCk0QMVBUTay3ukhSaJKKRFAaS0K21eNLJkG0mbPOBaGyHX2CbITFgmyExYJsfEDPhJttM2GZIXIUHHWxsvNrBxsarHWxsvNrJB1VFt9biLkmhScK3SQpNErq1Fp2kMJCECUlhIAkTVUUnKQzY5q6q4q6q4kmSwsDJZ+Iq3GSbD8SX2eYDcRUa2wyJAdthRsyIxnb4PnGfeJBtJg42Nl7tYGPj1Q42Nl7t5Aeqiom1Fp2kcFMS0VQVE5JCk4S7JIWBJHRrLTpJ4Sbb3CUpNEmYkBQa23SSQpNENFVFJyk0SejWWnQnPyNmQmObh4kB2+FK3GQ7zIir0NjmN9jmAzFgmwnbDInGdrgSV6E52Nh4tYONjVc72Nh4tZOhquKuquK/RlJokoibJIXGNk+qKrq1Fk+SFJokTKy16CSFJoloqopOUmiS0J3MifvEf4xtnmSbf4G4Cg+yzQdiJjS2GRKN7XAlmoONjVc72Nh4tYONjVdT/h+NJJ6URDSSQpNEfF+4Es1aKzT//PMPnW0mqoq71lp0VUUnic42XVUxJK5CI4mJJExIYiIJH4jmBERjO3yZbX6JuMk2PyDuC1eisR1mxH2isR1mxIDtMCMGDjY2Xu1gY+PVDjY2Xu1kqKqYWGsxUVVMSApNEnGTpDBgm7uqik5SuMk2E1VFt9aikxQGkohGUmhsc5ek0NjmLkmhOZkTM2FGDNjmSbb5F4jGdvg+cRUa29xlmyfZ5km26Q42Nl7tYGPj1Q42Nl7tlBSaJHSSQpNE3CQpNEnEgKQwkEQ0VUW31qKrKu6SFJok3LXW4q6qYmKtxV1VRbfWYqKq6NZaTEgKjW260zYfiMZ2eJBt7rLND4ircCVush2uxH3hPjET7hNXYUZchQHbTBxsbLzawcbGqx1sbLzaWVXcJSk0SZioKjpJoUlCt9aiqyomJIUmCZ2kMJBEfFlVMSEpDCQRN1UVnaTQ2KaTFAaS0K216KqKbq1FdwLiJtt8IGZEYztciatwJQZs84FobIe/QwzY5l8gGtthwDZD4ipciavQHGxsvNrBxsarHWxsvNopKQwkoVtr0UkKTRLRSAqNbTpJoUnChKTQJKGTFJokTEgKTRLukhRuSsKTJIWBJHRrLZ5UVXSSQpOE7rTNkLgKjW0mbDNhmw/EgG0+EI3tcCUGbIcrcZNtfkA8yDZD4io8SzS2w5VoDjY2Xu1gY+PVDjY2Xu3kB6qKCUmhSUK31mJCUmiSiKaq6CSFxjadpDCQhAlJYcA2T5IUmiRioKq4q6p4kqTQJKGTFJqTnxEDtsOVuAoDthkSje0wYJshMWCb32CbHxD3iQfZ5gPR2A7NwcbGqx1sbLzawcbGq538gKTQJBEDkkJjm4mqYkJSaGzTVRUTay06SWHANl1V0a216KqKJ0kKTRImJIUmiRiQFG6yTScpNLbpTn7ANnfZ5gfEgG2GxExobPMD4ipciQfZ5gMxYJu7bPMk20wcbGy82sHGxqsdbGy82skHVcVdkkJjm66q6NZadFXFf01V0a21+A1VRbfW4kmSwkASurUWE1VFt9Zi4uQzcZNthsRVuBL/PeIq/A5xFR5kmyFxFWbEVRg42Nh4tYONjVc72Nh4tZMPJIUmiRioKiYkhcY2naTQJBEDVcVdkkJjm66q6CSFJgmdpNAkoZMUmiSikRQGbDMhKTRJ6NZa3FVVdGstJqqKbq1Fd/KBbX5ADNgOA7b5AXGTbYZEYztcicZ2uBKN7TBgmyfZ5gNxFe4TV2FGXIXmYGPj1Q42Nl7tYGPj1c6q4kmSQpNENFVFt9aiqyo6SaFJIhpJ4SbbdFVFJyk0SegkhSYJv6GqmKgq7qoqOkmhSSKaqqKTFJokYuAExINsMySuwpVobIcB2zxMNLbDlWhshyvxO8SMuE80tsOMaGyHmw42Nl7tYGPj1Q42Nl7tlBSaJKKRFBrb3CUpNEnoJIXGNp2k0CShW2txl6TQJGGiqugkhYEkdJJCk4RurcWEpNAkEb9AUmiScNdpmwnbPMk2H4jGdhiwzQfiKtxkmw/EjGhshxnR2A5X4ioM2OavsM0H4qaDjY1XO9jYeLWDjY1XO6uKTlJoktCttZiQFJokdJJCY5tvqyq6tRZdVdFJCk0ScVNVMVFV3CUpNLbpJIUmiRiQFBrbdJJCk4QnnYBobIcrcRUGbPOBaGyH3yGuwpVobIdniRlxk20mbHOXbSZs84F40MHGxqsdbGy82sHGxqudkkJjm4mqYmKtRScpNEm4a61FJyk0tpmoKiaqiglJoUlCJyk0SUQjKQwk4a61Fp2k0NjmSZJCk0Q0kkKThO60zQ+ImdDY5gNxX2hs8wNiRgzY5gPR2A4DthkS94XGNt9mmwnbfCCag42NVzvY2Hi1g42NVzurim+rKu6SFJokoqkqJtZadJJCk0Q0kkKTRDSSQmObiaqikxQa20xICk0S0UgKjW0mqoq71lp0VcVdkkJzAuL7xE22GRIzobHNhG0mbPMDorEdbrLNhG1+QNwXrsRNtukONjZe7WBj49UONjZeTUD4I5KIq9BIYiKJuArNWouuqsRVuBJXoVlr0f3zzz90ScRVeJa4CgNrLbqqEo2k0CQRzVorNFUlGkmhsc3EaZs/TjS2w33iKsyIGXEVGtsMie8TM2HANk+yzV0HGxuvdrCx8WoHGxuvdvJBVfFtay3uqiomJIWBJExICjfZpqsqJiSFByURjaTQJBE3VRXfVlVMnHwmvi/cJwZshxkxYJuHiQHbfJttHia+TwwcbGy82sHGxqsdbGy82smQpHBTEvEgSaFJIm6SFJokoqkqurUWXVXRrbXoJIUmiWiqiom1FhOSQpOEuySFm2zTSQpNEjpJoUkimpMh2/wVtnmSbYbEVbgSV6GxzZCYCQO2+UDcZJsn2eYD0dgOAwcbG692sLHxagcbG6928sdJCk0S7qoqnlRVdJJCk4RurUUnKTRJxE1VxV2SQmObiapiYq1FV1V0kkJjm05SaE7+ONt8IO4TzxKN7XAlrkJjm4eJm2zzA2ImXInGdhiwTXewsfFqBxsbr3awsfFqJ39cVTEhKTS2uUtSaJKIRlJoknBXVXFXVTEhKQzYpqsq7pIUGtvcVVV0ay26k79PDNjmSbaZsM0H4j5xnxiwzQ+Im2zzMHEVmoONjVc72Nh4tYONjVc7Gaoq/gpJobHNhKTQJBEPkhQGbPNtkkJjm7skhSaJeJCk0CRhoqroTubEH2Gbu2zzbbb5K2zzJNt8m20+EDOiOdjYeLWDjY1XO9jYeLWTDySFL7PNt1UVE5JCY5tOUmiS0K216KqKJ0kKA7bpqoq71lp0ksKAbSaqiglJYeDkA9u8hBiwHQZs84G4ClfiQbb5AXFfaGzzMDFgm4mDjY1XO9jYeLWDjY1X+z+LSplXpsC/OgAAAABJRU5ErkJggg=="
//		},
//		"uuid": "492VGBAXEst7YekIyAMm",
//		"checkTime": 5,
//		"notifyKey": {
//			"iLen": 16,
//			"buffer": "osmSM5hLB2blK7y5ci2Dzw=="
//		},
//		"expiredTime": 290,
//		"blueToothBroadCastContent": {
//			"iLen": 0
//		},
//		"fileTransferAssistant": "https://filehelper.weixin.qq.com/?from=windows&type=recommend",
//		"qrScanUrl": "http://weixin.qq.com/x/492VGBAXEst7YekIyAMm"
//	}

func (ns *NetSceneGetLoginQrcode) Buf2Rsp(payload []byte) (interface{}, error) {

	nsb := NetSeceneBase{
		UserInfo: ns.UserInfo,
	}
	rspByte := nsb.DecodeEcdhRspBuf(payload)
	getLoginQrCodeRsp := &micromsg.GetLoginQRCodeResponse{}
	proto.Unmarshal(rspByte, getLoginQrCodeRsp)

	return getLoginQrCodeRsp, nil
}
