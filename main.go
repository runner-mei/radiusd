package main

import (
	"flag"
	"fmt"
	"net"
	"sync"

	"github.com/runner-mei/radiusd/config"
	"github.com/runner-mei/radiusd/model"
	"github.com/runner-mei/radiusd/queue"
	"github.com/runner-mei/radiusd/radius"
)

var wg *sync.WaitGroup

func init() {
	radius.WriteRecord = func(r *radius.Record) {
		var username string
		if r.Data != nil {
			if o := r.Data["username"]; o != nil {
				username = fmt.Sprint(o)
			}
		}
		err := model.AuthReject(config.DB, username, r.Address, r.Code.Message+":"+r.Message)
		if err != nil {
			radius.DefaultWriteRecord(r)
			fmt.Println("AuthReject:", err)
		}
	}
}

func listenAndServe(l config.Listener) {
	defer wg.Done()

	if config.Verbose {
		config.Log.Printf("Listening on " + l.Addr)
	}
	conn, e := radius.Listen(l.Addr)
	if e != nil {
		panic(e)
	}
	config.Sock = append(config.Sock, conn)
	if e := radius.Serve(conn, func(addr net.IP) (*model.BAS, error) {
		return model.GetBAS(config.DB, addr)
	}); e != nil {
		if config.Stopping {
			// Ignore close errors
			return
		}
		panic(e)
	}
}

func main() {
	var configPath string
	flag.BoolVar(&config.Debug, "d", false, "Debug packetdata")
	flag.BoolVar(&config.Verbose, "v", false, "Show all that happens")
	flag.StringVar(&configPath, "c", "./config.toml", "Configuration")
	flag.Parse()

	if e := config.Init(configPath); e != nil {
		config.Log.Fatal(e)
	}
	if config.Verbose {
		config.Log.Printf("%+v", config.C)
	}
	if config.Debug {
		config.Log.Printf("Auth RFC2865 https://tools.ietf.org/html/rfc2865")
		config.Log.Printf("Acct RFC2866 https://tools.ietf.org/html/rfc2866")
	}

	/*
	    1      Start
	    2      Stop
	    3      Interim-Update
	    7      Accounting-On
	    8      Accounting-Off
	    9-14   Reserved for Tunnel Accounting
	   15      Reserved for Failed
	*/
	radius.HandleFunc(radius.AccessRequest, 0, auth)
	radius.HandleFunc(radius.AccountingRequest, 1, acctBegin)
	radius.HandleFunc(radius.AccountingRequest, 3, acctUpdate)
	radius.HandleFunc(radius.AccountingRequest, 2, acctStop)

	go Control()
	go queue.Loop(config.DB)

	wg = new(sync.WaitGroup)
	for _, listen := range config.C.Listen {
		wg.Add(1)
		go listenAndServe(listen)
	}
	wg.Wait()

	// Write all stats
	queue.Force(config.DB)
}
