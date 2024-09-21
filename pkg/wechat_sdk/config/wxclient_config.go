package config

var (
	/*
		<domainlist connecttype="short" nettype="1" netstrategy="0" netproto="2" netchannel="1">
			<domain idc="1">short.weixin.qq.com</domain>
			<domain idc="1">shshort.weixin.qq.com</domain>
			<domain idc="2">hkshort.weixin.qq.com</domain>
			<domain idc="4">cashort.weixin.qq.com</domain>
			<domain idc="3">szshort.weixin.qq.com</domain>
			<domain idc="5">sh2tjshort.weixin.qq.com</domain>
			<domain idc="5">sz2tjshort.weixin.qq.com</domain>
			<domain idc="5">tjshort.weixin.qq.com</domain>
			<domain idc="8">mlshort.weixin.qq.com</domain>
			<domain idc="9">sgshort.wechat.com</domain>
		</domainlist>
	*/
	WxShortHostList = []string{
		"short.weixin.qq.com",
		"szshort.weixin.qq.com",
	}

	/*
	   <domainlist connecttype="long" nettype="3" netstrategy="0" netproto="1" netchannel="1">
	       <domain idc="1">long.weixin.qq.com</domain>
	       <domain idc="1">shlong.weixin.qq.com</domain>
	       <domain idc="2">hklong.weixin.qq.com</domain>
	       <domain idc="4">calong.weixin.qq.com</domain>
	       <domain idc="3">szlong.weixin.qq.com</domain>
	       <domain idc="5">sh2tjlong.weixin.qq.com</domain>
	       <domain idc="5">sz2tjlong.weixin.qq.com</domain>
	       <domain idc="5">tjlong.weixin.qq.com</domain>
	       <domain idc="8">mllong.weixin.qq.com</domain>
	       <domain idc="9">sglong.wechat.com</domain>
	   </domainlist>
	*/
	WxLongHostList = []string{
		"long.weixin.qq.com",
		"szlong.weixin.qq.com",
	}

	WxPortList = []string{
		"8080",
		"80",
		"443",
	}

	DeviceTypeList = []string{
		"Windows 10 x64",
		"Windows 7 x64",
		"Windows 8.1 x64",
		"Windows 10 Pro x64",
		"Windows 10 Home x64",
		"Windows 10 Enterprise x64",
		"Windows 10 Education x64",
		"Windows 11 x64",
		"Windows 11 Pro x64",
		"Windows 11 Home x64",
		"Windows 11 Enterprise x64",
		"Windows 11 Education x64",
		"Windows Server 2019 Standard x64",
		"Windows Server 2019 Datacenter x64",
		"Windows Server 2022 Standard x64",
		"Windows Server 2022 Datacenter x64",
		"Windows 10 IoT Core x64",
		"Windows 10 S x64",
		"Windows 8 x64",
		"Windows 8 Pro x64",
		"Windows 7 Home Premium x64",
		"Windows 7 Professional x64",
		"Windows 7 Ultimate x64",
		"Windows Server 2016 Standard x64",
		"Windows Server 2016 Datacenter x64",
	}

	WechatClientVersion uint32 = 0x6309092b // 0x63090a13
)
