package queue

import (
	"database/sql"
	"math/rand"
	"time"

	"github.com/runner-mei/radiusd/config"
	"github.com/runner-mei/radiusd/model"
)

func save(db *sql.DB) {
	entries := Flush()
	if config.Verbose {
		config.Log.Printf("flush %d metrics", len(entries))
	}
	for user, entry := range entries {
		if e := model.SessionAcct(db, user,
			config.Hostname,
			entry.InOctet,
			entry.OutOctet,
			entry.InPacket,
			entry.OutPacket,
			time.Now()); e != nil {
			config.Log.Printf("WARN: Losing statistic data err=" + e.Error())
		}
		if e := model.UpdateRemaining(db, user, entry.InOctet+entry.OutOctet); e != nil {
			config.Log.Printf("WARN: Losing statistic data err=" + e.Error())
		}
	}
}

func Loop(db *sql.DB) {
	rand.Seed(time.Now().Unix())
	rnd := time.Duration(rand.Int31n(20)) * time.Second
	sleep := time.Duration(time.Minute + rnd)
	if config.Verbose {
		config.Log.Printf("Sync every: %s", sleep.String())
	}

	for range time.Tick(sleep) {
		save(db)
	}
}

// Force writing stats now
func Force(db *sql.DB) {
	save(db)
}
