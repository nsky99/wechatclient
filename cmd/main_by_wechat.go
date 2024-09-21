package main

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"encoding/json"
// 	"fmt"
// 	"syscall"
// 	"unsafe"
// 	"wechatclient/manager/wx_client_mgr/wx_client"

// 	"golang.org/x/sys/windows"
// )

// var (
// 	ProcNtReadVirtualMemory *windows.LazyProc
// )

// func init() {
// 	ModNt := windows.NewLazySystemDLL("ntdll.dll")
// 	ProcNtReadVirtualMemory = ModNt.NewProc("NtReadVirtualMemory")
// }

// func readProcessMemory(procHandle syscall.Handle, address uint64, size uint) []byte {
// 	var read uint

// 	buffer := make([]byte, size)

// 	ret, _, _ := ProcNtReadVirtualMemory.Call(
// 		uintptr(procHandle),
// 		uintptr(address),
// 		uintptr(unsafe.Pointer(&buffer[0])),
// 		uintptr(size),
// 		uintptr(unsafe.Pointer(&read)),
// 	)
// 	if int(ret) >= 0 && read > 0 {
// 		return buffer[:read]
// 	}
// 	return nil
// }

// type CppString struct {
// 	Pstr1    uint64
// 	Pstr2    uint64
// 	Length   uint64
// 	Capacity uint64
// }

// func ReadCppString(procHandle syscall.Handle, address uint64) string {
// 	retbyte := readProcessMemory(procHandle, uint64(address), uint(unsafe.Sizeof(CppString{})))
// 	str := CppString{}
// 	buffer := bytes.NewBuffer(retbyte)
// 	err := binary.Read(buffer, binary.LittleEndian, &str)
// 	if err != nil {
// 		return ""
// 	}
// 	if str.Length > 0xF {
// 		retbyte := readProcessMemory(procHandle, str.Pstr1, uint(str.Length))
// 		return string(retbyte[:])
// 	} else {
// 		return string(retbyte[:str.Length])
// 	}
// }

// func ReadCppInt(procHandle syscall.Handle, address uint64) uint32 {
// 	retbyte := readProcessMemory(procHandle, uint64(address), 4)
// 	buffer := bytes.NewBuffer(retbyte)
// 	data := uint32(0)
// 	err := binary.Read(buffer, binary.LittleEndian, &data)
// 	if err != nil {
// 		return 0
// 	} else {
// 		return data
// 	}
// }

// func findProcessIDByName(processName string) (uint32, error) {
// 	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
// 	if err != nil {
// 		return 0, err
// 	}
// 	defer windows.CloseHandle(snapshot)

// 	var procEntry windows.ProcessEntry32
// 	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
// 	for {
// 		err = windows.Process32Next(snapshot, &procEntry)
// 		if err != nil {
// 			if err == syscall.ERROR_NO_MORE_FILES {
// 				return 0, fmt.Errorf("进程未找到: %s", processName)
// 			}
// 			return 0, err
// 		}
// 		if syscall.UTF16ToString(procEntry.ExeFile[:]) == processName {
// 			return procEntry.ProcessID, nil
// 		}
// 	}
// }

// func getModuleBaseAddress(processID uint32, moduleName string) (uintptr, error) {
// 	// 打开进程获取句柄
// 	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
// 	if err != nil {
// 		return 0, err
// 	}
// 	defer windows.CloseHandle(handle)

// 	// 获取进程中的模块列表
// 	var modules [1024]windows.Handle
// 	var needed uint32
// 	if err := windows.EnumProcessModules(handle, &modules[0], uint32(unsafe.Sizeof(modules)), &needed); err != nil {
// 		return 0, err
// 	}

// 	// 计算模块数量
// 	count := needed / uint32(unsafe.Sizeof(modules[0]))

// 	// 遍历模块列表，匹配模块名称
// 	for i := uint32(0); i < count; i++ {
// 		var baseName [windows.MAX_PATH]uint16
// 		if err := windows.GetModuleBaseName(handle, windows.Handle(modules[i]), &baseName[0], uint32(len(baseName))); err != nil {
// 			continue
// 		}
// 		if syscall.UTF16ToString(baseName[:]) == moduleName {
// 			return uintptr(modules[i]), nil
// 		}
// 	}

// 	return 0, fmt.Errorf("模块未找到")
// }

// func main() {
// 	// 示例：从进程ID为12345的进程中读取内存
// 	processID, err := findProcessIDByName("WeChat.exe") // 目标进程ID
// 	if err != nil {
// 		panic("未找到WeChat进程")
// 	}

// 	wechtwinBase, err := getModuleBaseAddress(processID, "WeChatWin.dll")
// 	if err != nil {
// 		panic("未找到WeChatWin模块基址")
// 	}
// 	handle, err := syscall.OpenProcess(0x0010, false, processID)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	defer syscall.CloseHandle(handle)

// 	deviceId := "Wa7a9a176cdcf5361" // device id - wechatwin + 40B7430
// 	deviceType := "Windows 10 x64"  //
// 	deviceName := "Windows 10 x64"  //
// 	client := wx_client.NewWxClient(deviceId, deviceType, deviceName)
// 	client.UserInfo.AuthDecodeSessionKey = []byte(ReadCppString(handle, uint64(wechtwinBase+0x40E98B0+0x548)))
// 	client.UserInfo.AuthLoginEcdhKey = []byte(ReadCppString(handle, uint64(wechtwinBase+0x40E98B0+0x688)))
// 	client.UserInfo.AuthUin = ReadCppInt(handle, uint64(wechtwinBase+0x40E98B0+0x2bc)) //1494671306
// 	client.UserInfo.Cookies = []byte(ReadCppString(handle, uint64(wechtwinBase+0x40E98B0+0x5a8)))
// 	fmt.Println(client.HeartBeat())
// 	profile, err := client.GetProFile()
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	client.UserInfo.UserName = profile.(*micromsg.GetProfileResponse).GetUserInfo().GetUserName().GetString_()
// 	fmt.Println(client.NewInit())
// 	fmt.Println(client.SendMsgNew("filehelper", "outside short link send msg1", 1, 666))
// 	data, _ := client.NewSync(1)
// 	jsondata, _ := json.Marshal(data)
// 	fmt.Println(string(jsondata))

// 	// WxCurContact := int32(0)
// 	// var contactList []string
// 	// for {
// 	// 	contact, _ := client.InitContact(WxCurContact, 0)
// 	// 	contactRsp := contact.(*micromsg.InitContactResponse)
// 	// 	if contactRsp.GetCountinueFlag() != 1 {
// 	// 		break
// 	// 	}

// 	// 	WxCurContact = contactRsp.GetCurrentWxcontactSeq()
// 	// 	contactList = append(contactList, contactRsp.GetContactUsernameList()...)
// 	// }

// 	// for _, c := range contactList {
// 	// 	fmt.Println(c)
// 	// }
// 	// client.LogOut()
// 	// fmt.Println(client.GetContact("wxid_16bims1c5ufg22"))
// }
