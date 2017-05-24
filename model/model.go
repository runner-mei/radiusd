package model

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/runner-mei/radiusd/config"
)

const (
	address             = "tpt_network_addresses"
	device              = "tpt_network_devices"
	bas                 = "tpt_radius_bas"
	users               = "tpt_radius_users"
	products            = "tpt_radius_products"
	dns                 = "tpt_radius_dns"
	accounting          = "tpt_radius_accounting"
	sessions            = "tpt_radius_sessions"
	session_log_records = "tpt_radius_session_log_records"
	auth_log_records    = "tpt_radius_log_records"
)

type BAS struct {
	ID       int64
	DeviceID int64
	Secret   string
	VendorID int64
}

func GetBAS(db *sql.DB, addr net.IP) (*BAS, error) {
	var id int64
	var deviceID int64
	var secret string
	var vendorID sql.NullInt64
	// var dnsID sql.NullInt64
	// var dnsOne sql.NullString
	// var dnsTwo sql.NullString
	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			bas.id,
			bas.network_device_id,
			bas.secret,
			bas.vendor_id
		FROM
			`+bas+` as bas
		WHERE
		  EXISTS ( SELECT 1
		  	FROM `+device+`
		  	WHERE
		  	    id = bas.network_device_id
		  	  AND
			      address = ?)
			OR EXISTS ( SELECT 1
		  	FROM `+address+`
		  	WHERE
		  	    managed_object_id = bas.network_device_id
		  	  AND
			      address = ?)`),
		addr.String(), addr.String(),
	).Scan(&id,
		&deviceID,
		&secret,
		&vendorID,
	// &dnsID,
	// &dnsOne,
	// &dnsTwo,
	)
	if e != nil {
		if e == config.ErrNoRows {
			return nil, nil
		}
		return nil, e
	}

	basData := &BAS{
		ID:       id,
		DeviceID: deviceID,
		Secret:   secret}
	if vendorID.Valid {
		basData.VendorID = vendorID.Int64
	}
	// if dnsID.Valid {
	// 	basData.DnsID = dnsID.Int64
	// }
	// if dnsOne.Valid {
	// 	basData.DnsOne = dnsOne.String
	// }
	// if dnsTwo.Valid {
	// 	basData.DnsTwo = dnsTwo.String
	// }
	return basData, nil
}

type User struct {
	ID              int64
	Username        string
	Password        string
	ActiveUntil     *string // Account active until YYYY-MM-DD
	BlockRemain     *int64  // Remaining bandwidth
	SimultaneousUse *uint32 // Max conns allowed
	DedicatedIP     *string
	Ratelimit       *string
	DnsOne          *string
	DnsTwo          *string
	Ok              bool
}

func UserID(db *sql.DB, user string) (int64, error) {
	var userID int64
	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			id
		FROM
			`+users+`
		WHERE
			username = ?`),
		user,
	).Scan(&userID)
	if e == config.ErrNoRows {
		return userID, nil
	}
	return userID, e
}

func Auth(db *sql.DB, user string) (User, error) {
	u := User{}
	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			users.id,
			users.username,
			users.password,
			users.block_remaining,
			users.active_until,
			1,
			products.max_sessions,
			users.dedicated_address,
			CONCAT(products.ratelimit_up, products.ratelimit_unit, '/', products.ratelimit_down, products.ratelimit_unit),
			dns.one, 
			dns.two
		FROM
			`+users+` as users
		LEFT JOIN
			`+products+` as products
		ON
			users.product_id = products.id
		LEFT JOIN
			`+dns+` as dns
		ON
			users.dns_id = dns.id
		WHERE
			users.username = ?`),
		user,
	).Scan(&u.ID,
		&u.Username,
		&u.Password,
		&u.BlockRemain,
		&u.ActiveUntil,
		&u.Ok,
		&u.SimultaneousUse,
		&u.DedicatedIP,
		&u.Ratelimit,
		&u.DnsOne,
		&u.DnsTwo,
	)
	if e == config.ErrNoRows {
		return u, nil
	}
	return u, e
}

type Session struct {
	BytesIn     uint32
	BytesOut    uint32
	PacketsIn   uint32
	PacketsOut  uint32
	SessionID   string
	NasPort     string
	User        int64
	NasIP       string
	SessionTime uint32
}
type UserLimits struct {
	ID     int64
	Exists bool
}

var ErrNoRows = sql.ErrNoRows

func Begin() (*sql.Tx, error) {
	return config.DB.Begin()
}

func SessionCount(db *sql.DB, user string) (uint32, error) {
	var count uint32 = 0
	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			COUNT(*)
		FROM
			`+sessions+` as sessions
		WHERE
		  EXISTS (
		  	SELECT * 
		  	FROM `+users+` as users 
		  	WHERE 
		  		  sessions.user_id = users.id 
		  		AND 
		  		  users.username = ?
		  )
			`),
		user,
	).Scan(&count)
	return count, e
}

func Limits(db *sql.DB, user string) (UserLimits, error) {
	u := UserLimits{}
	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			users.id,
			1
		FROM
			`+users+` as users
		LEFT JOIN
			`+products+` as products
		ON
			users.product_id = products.id
		WHERE
			username = ?`),
		user,
	).Scan(&u.ID, &u.Exists)
	return u, e
}

func affectCheck(res sql.Result, expect int64, errMsg error) error {
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != expect {
		return errMsg
	}
	return nil
}

func AuthReject(db *sql.DB, username, bas, message string) error {
	_, err := db.Exec(config.PlaceholderFormat(`INSERT INTO `+auth_log_records+`(
		  	username, 
				nas_address,  
				message, 
				created_at)
		VALUES (?, ?, ?, ?)`),
		username, bas, message, time.Now())
	if err != nil {
		return err
	}
	return nil
}

func SessionAdd(db *sql.DB, sessionID string, user int64, nasIP, nasPort, assignedIP, clientIP string) error {
	exists := false
	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			1
		FROM
			`+sessions+` as sessions
		WHERE
			user_id = ?
		AND
			session_id = ?
		AND
			nas_address = ?`),
		user, sessionID, nasIP,
	).Scan(&exists)
	if e != nil && e != sql.ErrNoRows {
		return e
	}
	if exists {
		// Session already stored
		return nil
	}

	now := time.Now()
	res, e := db.Exec(
		config.PlaceholderFormat(`INSERT INTO `+sessions+` (
		  	session_id, 
				user_id,  
				nas_address,
				nas_port,
				assigned_address, 
				client_address, 
				bytes_in, 
				bytes_out, 
				packets_in, 
				packets_out, 
				session_time,
				created_at,
				updated_at
			)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, ?, ?)`),
		sessionID, user, nasIP, nasPort, assignedIP, clientIP, now, now)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.add fail for sess=%s user=%v",
		sessionID, user,
	))
}

func SessionUpdate(txn *sql.Tx, s Session) error {
	res, e := txn.Exec(
		config.PlaceholderFormat(`UPDATE
			`+sessions+`
		SET
			bytes_in = bytes_in + ?,
			bytes_out = bytes_out + ?,
			packets_in = packets_in + ?,
			packets_out = packets_out + ?,
			session_time = ?,
			updated_at = ?
		WHERE
			session_id = ?
		AND
			user_id = ?
		AND
			nas_address = ?`),
		s.BytesIn, s.BytesOut, s.PacketsIn, s.PacketsOut, s.SessionTime, time.Now(),
		s.SessionID, s.User, s.NasIP,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.update fail for sess=%s user=%v",
		s.SessionID, s.User,
	))

}

func SessionRemove(txn *sql.Tx, sessionID string, user int64, nasIP string) error {
	res, e := txn.Exec(
		config.PlaceholderFormat(`DELETE FROM
			`+sessions+`
		WHERE
			session_id = ?
		AND
			user_id = ?
		AND
			nas_address = ?`),
		sessionID, user, nasIP,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.remove fail for sess=%s",
		sessionID,
	))
	return nil
}

// Copy session to log
func SessionLog(txn *sql.Tx, sessionID string, user int64, nasIP string) error {
	res, e := txn.Exec(
		config.PlaceholderFormat(`INSERT INTO
			`+session_log_records+`
			(assigned_address, bytes_in, bytes_out, client_address,
			nas_address, nas_port, packets_in, packets_out, session_id,
			session_time, user_id, begin_at, end_at)
		SELECT
			assigned_address, bytes_in, bytes_out, client_address,
			nas_address, nas_port, packets_in, packets_out, session_id,
			session_time, user_id, created_at as begin_at, updated_at as end_at 
		FROM
			`+sessions+`
		WHERE
			session_id = ?
		AND
			user_id = ?
		AND
			nas_address = ?`),
		sessionID, user, nasIP,
	)
	if e != nil {
		return e
	}
	return affectCheck(res, 1, fmt.Errorf(
		"session.log fail for sess=%s",
		sessionID,
	))
}

// Copy session to log
func SessionExpire(db *sql.DB, d time.Time) error {
	txn, e := db.Begin()
	if e != nil {
		return e
	}
	defer txn.Rollback()

	res, e := txn.Exec(
		config.PlaceholderFormat(`INSERT INTO
			`+session_log_records+`
			(assigned_address, bytes_in, bytes_out, client_address,
			nas_address, nas_port, packets_in, packets_out, session_id,
			session_time, user_id, begin_at, end_at)
		SELECT
			assigned_address, bytes_in, bytes_out, client_address,
			nas_address, nas_port, packets_in, packets_out, session_id,
			session_time, user_id, created_at as begin_at, updated_at as end_at 
		FROM
			`+sessions+`
		WHERE
			updated_at < ?`),
		d,
	)
	if e != nil {
		return e
	}
	_, e = res.RowsAffected()
	if e != nil {
		return e
	}
	res, e = txn.Exec(
		config.PlaceholderFormat(`DELETE FROM `+sessions+
			` WHERE updated_at < ?`), d)
	if e != nil {
		return e
	}
	_, e = res.RowsAffected()
	if e != nil {
		return e
	}
	return txn.Commit()
}

func SessionAcct(db *sql.DB, user int64, hostname string, octetIn uint32, octetOut uint32, packetIn uint32, packetOut uint32, date time.Time) error {
	res, e := db.Exec(config.PlaceholderFormat(`INSERT INTO
			`+accounting+`
		(user_id, hostname, bytes_in, bytes_out, packets_in, packets_out, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`),
		user, hostname, octetIn, octetOut, packetIn, packetOut, date)
	if e != nil {
		return e
	}
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != 1 {
		return fmt.Errorf(
			"Affect fail for user=%s",
			user,
		)
	}
	return nil
}

func UpdateRemaining(db *sql.DB, user int64, remain uint32) error {
	if remain == 0 {
		return nil
	}

	res, e := db.Exec(config.PlaceholderFormat(`UPDATE
			`+users+`
		SET
			block_remaining = CASE WHEN block_remaining - ? < 0 THEN 0 ELSE block_remaining - ? END
		WHERE
			id = ?`), remain, remain, user)
	if e != nil {
		return e
	}
	affect, e := res.RowsAffected()
	if e != nil {
		return e
	}
	if affect != 1 {
		// Nothing changed, check if this behaviour is correct
		remain, e := checkRemain(db, user)
		if e != nil {
			return e
		}
		if !remain {
			return fmt.Errorf(
				"Affect fail for user=%s",
				user,
			)
		}
	}
	return nil
}

func checkRemain(db *sql.DB, user int64) (bool, error) {
	var remain *int64

	e := db.QueryRow(
		config.PlaceholderFormat(`SELECT
			block_remaining
		FROM
			`+users+`
		WHERE
			username = ?`),
		user,
	).Scan(&remain)
	if remain == nil || *remain == 0 {
		return true, e
	}
	return false, e
}
