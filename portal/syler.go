package main

import (
	"github.com/runner-mei/radiusd/portal/component"
	"github.com/runner-mei/radiusd/portal/config"
)

func main() {
	//http server
	//radius avp server
	//radius accounting server

	// go func() {
	// 	res, err := v1.Challenge(net.IPv4(192, 168, 10, 254), *config.PortalSecret, net.IPv4(192, 168, 56, 2))
	// }()

	//path := flag.String("config", "./syler.conf", "设置配置文件的路径")
	component.InitBasic()
	//flag.Parse()
	//*path = filepath.FromSlash(*path)
	//if err := toml.Parse(*path); err == nil {
	if config.IsValid() {
		component.InitLogger()
		go component.StartHuawei()
		// if *config.RadiusEnable {
		// 	go component.StartRadiusAuth()
		// 	go component.StartRadiusAcc()
		// }
		component.StartHttp()
	}
}
