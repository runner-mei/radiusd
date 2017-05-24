package config

import (
	"net"
	"strings"
)

var (
	HttpPort            = Int("http.port", 8088)
	HttpWhiteList       = String("http.white_list", "")
	RandomUser          = Bool("basic.random_user", true)
	LogFile             = String("basic.logfile", "")
	CallBackUrl         = String("basic.callback_logout", "")
	UseRemoteIpAsUserIp = Bool("basic.remote_ip_as_user_ip", false)
	HuaweiPort          = Int("huawei.port", 50100)
	HuaweiVersion       = Int("huawei.version", 1)
	HuaweiTimeout       = Int("huawei.timeout", 15)
	HuaweiSecret        = String("huawei.secret", "testing123")
	HuaweiNasPort       = Int("huawei.nas_port", 2000)
	HuaweiDomain        = String("huawei.domain", "huawei.com")
	LoginPage           = String("basic.login_page", "./login.html")
	NasIp               = String("basic.nas_ip", "")
	DefaultTimeout      = Uint64("basic.default_timeout", 0)
	AuthType            = String("radius.auth_type", "random")
)

func IsValid() bool {
	return true
}

func IsValidClient(addr string) bool {
	if *HttpWhiteList == "" {
		return true
	}
	if ip, _, err := net.SplitHostPort(addr); err == nil {
		if strings.Contains(*HttpWhiteList, ip) {
			return true
		}
	}
	return false
}
