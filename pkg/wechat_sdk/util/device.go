package util

import (
	"crypto/md5"
	"fmt"

	"github.com/google/uuid"
)

var (
	deviceId = ""
)

func GetDeviceId() string {
	if deviceId != "" {
		return deviceId
	}

	deviceUuidMd5 := md5.Sum([]byte(uuid.New().String()))
	deviceId = "W" + string(fmt.Sprintf("%x", deviceUuidMd5[:len(deviceUuidMd5)/2]))
	return deviceId
}
