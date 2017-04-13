package config

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

type Listener struct {
	Addr string
	//Secret string
	//CIDR   []string
}

type Conf struct {
	Drv           string
	Dsn           string
	Listen        map[string]Listener
	ControlListen string
}

var (
	C         *Conf
	Log       *log.Logger
	Debug     bool = true
	Verbose   bool = true
	Hostname  string
	DB        *sql.DB
	ErrNoRows = sql.ErrNoRows
	Stopping  bool
	Sock      []*net.UDPConn
)

func Init(path string) error {
	r, e := os.Open(path)
	if e != nil {
		return e
	}
	defer r.Close()

	C = new(Conf)
	if _, e := toml.DecodeReader(r, &C); e != nil {
		return fmt.Errorf("TOML: %s", e)
	}
	Hostname, e = os.Hostname()
	if e != nil {
		panic(e)
	}

	Log = log.New(os.Stdout, "radiusd ", log.LstdFlags)

	DB, e = sql.Open(C.Drv, C.Dsn)
	if e != nil {
		return e
	}
	return DB.Ping()
}

func DbClose() error {
	return DB.Close()
}

var (
	// Question is a PlaceholderFormat instance that leaves placeholders as
	// question marks.
	Question = func(sql string) string {
		return sql
	}

	// Dollar is a PlaceholderFormat instance that replaces placeholders with
	// dollar-prefixed positional placeholders (e.g. $1, $2, $3).
	Dollar = func(sql string) string {
		buf := &bytes.Buffer{}
		i := 0
		for {
			p := strings.Index(sql, "?")
			if p == -1 {
				break
			}

			if len(sql[p:]) > 1 && sql[p:p+2] == "??" { // escape ?? => ?
				buf.WriteString(sql[:p])
				buf.WriteString("?")
				if len(sql[p:]) == 1 {
					break
				}
				sql = sql[p+2:]
			} else {
				i++
				buf.WriteString(sql[:p])
				fmt.Fprintf(buf, "$%d", i)
				sql = sql[p+1:]
			}
		}

		buf.WriteString(sql)
		return buf.String()
	}

	// PlaceholderFormat takes a SQL statement and replaces each question mark
	// placeholder with a (possibly different) SQL placeholder.
	PlaceholderFormat = Dollar

	// IsReturning use returning case in the insert statement.
	IsReturning bool
)
