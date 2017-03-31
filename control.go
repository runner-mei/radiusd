// Control offers an HTTP JSON API.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/runner-mei/radiusd/config"
)

var server *http.Server

func Control() {
	http.HandleFunc("/shutdown", shutdown)
	http.HandleFunc("/verbose", verbose)

	server = &http.Server{Addr: config.C.ControlListen}
	e := server.ListenAndServe()
	if e != nil {
		if !config.Stopping {
			panic(e)
		}
	}
}

// Finish pending jobs and close application
func shutdown(w http.ResponseWriter, r *http.Request) {
	if config.Stopping {
		if _, e := w.Write([]byte(fmt.Sprintf(`{"success": true, "msg": "Already stopping."}`))); e != nil {
			config.Log.Printf("control: " + e.Error())
			return
		}
	}

	config.Log.Printf("Disconnecting")
	config.Stopping = true
	/*
		if e := server.Close(); e != nil {
			if _, e := w.Write([]byte(fmt.Sprintf(`{"success": false, "msg": "Error stopping HTTP-listener"}`))); e != nil {
				config.Log.Printf("control: " + e.Error())
				return
			}
		}
	*/
	for _, sock := range config.Sock {
		if e := sock.Close(); e != nil {
			if _, e := w.Write([]byte(fmt.Sprintf(`{"success": false, "msg": "Error stopping listener"}`))); e != nil {
				config.Log.Printf("control: " + e.Error())
				return
			}
		}
	}
	if _, e := w.Write([]byte(`{"success": true, "msg": "Stopped listening, waiting for empty queue."}`)); e != nil {
		config.Log.Printf("control: " + e.Error())
		return
	}
}

func verbose(w http.ResponseWriter, r *http.Request) {
	msg := `{success: true, msg: "Set verbosity to `
	if config.Verbose {
		config.Verbose = false
		msg += "OFF"
	} else {
		config.Verbose = true
		msg += "ON"
	}
	msg += `"}`

	if _, e := w.Write([]byte(msg)); e != nil {
		Error(w, e, "Flush failed")
		return
	}
}

// Write msg as error and report e to log
func Error(w http.ResponseWriter, e error, msg string) {
	if e != nil {
		log.Println("%v", e)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	if e := FlushJson(w, Reply(false, msg)); e != nil {
		panic(e)
	}
}

// Write v as string to w
func FlushJson(w http.ResponseWriter, v interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if _, e := w.Write(b); e != nil {
		return e
	}
	return nil
}

type DefaultResponse struct {
	Status bool   `json:"status"`
	Text   string `json:"text"`
}

func Reply(status bool, text string) DefaultResponse {
	return DefaultResponse{status, text}
}
