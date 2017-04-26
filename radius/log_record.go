package radius

import "github.com/runner-mei/radiusd/config"

type ErrorCode struct {
	Code    int
	Message string
}

var (
	ErrBASNotFound          = ErrorCode{1, "BAS_NOT_FOUND"}
	ErrInvalidAuthRequest   = ErrorCode{2, "INVALID_AUTH_REQUEST"}
	ErrDBFail               = ErrorCode{3, "DB_FAIL"}
	ErrUserNotFound         = ErrorCode{4, "USER_NOT_FOUND"}
	ErrUserPasswordNotMatch = ErrorCode{5, "USER_PASSWORD_NOT_MATCH"}
	ErrInvalidMSCHAP        = ErrorCode{6, "INVALID_MSCHAP"}
	ErrConnectionExceed     = ErrorCode{7, "CONNECTION_EXCEED"}
	ErrInternalError        = ErrorCode{8, "INTERNAL_ERROR"}
)

type Record struct {
	Code    ErrorCode
	Address string
	Message string
	Data    map[string]interface{}
}

func (r *Record) With(k, v string) *Record {
	if r.Data == nil {
		r.Data = map[string]interface{}{k: v}
	} else {
		r.Data[k] = v
	}
	return r
}

func (r *Record) Save() {
	if WriteRecord == nil {
		DefaultWriteRecord(r)
	} else {
		WriteRecord(r)
	}
}

func LogRecord(c ErrorCode, address, message string) *Record {
	return &Record{Code: c, Address: address, Message: message}
}

var WriteRecord = DefaultWriteRecord

func DefaultWriteRecord(r *Record) {
	if r.Data == nil {
		config.Log.Printf("[%s] %s: %s", r.Code.Message, r.Address, r.Message)
	} else {
		config.Log.Printf("[%s] %s: %s - %#v", r.Code.Message, r.Address, r.Message, r.Data)
	}
}
