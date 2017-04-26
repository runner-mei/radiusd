// radius commands
package main

import (
	"bytes"
	"io"
	"net"

	"github.com/runner-mei/radiusd/config"
	"github.com/runner-mei/radiusd/model"
	"github.com/runner-mei/radiusd/queue"
	"github.com/runner-mei/radiusd/radius"
	"github.com/runner-mei/radiusd/radius/mschap"
	"github.com/runner-mei/radiusd/radius/vendor"
)

func createSession(userID int64, req *radius.Packet) model.Session {
	var nasPortID string
	if req.HasAttr(radius.NASPortID) {
		nasPortID = string(req.Attr(radius.NASPortID))
	}

	return model.Session{
		BytesIn:     radius.DecodeFour(req.Attr(radius.AcctInputOctets)),
		BytesOut:    radius.DecodeFour(req.Attr(radius.AcctOutputOctets)),
		PacketsIn:   radius.DecodeFour(req.Attr(radius.AcctInputPackets)),
		PacketsOut:  radius.DecodeFour(req.Attr(radius.AcctOutputPackets)),
		SessionID:   string(req.Attr(radius.AcctSessionID)),
		SessionTime: radius.DecodeFour(req.Attr(radius.AcctSessionTime)),
		NasPort:     nasPortID,
		User:        userID,
		NasIP:       radius.DecodeIP(req.Attr(radius.NASIPAddress)).String(),
	}
}

func auth(w io.Writer, addr string, bas interface{}, req *radius.Packet) {
	config.Log.Printf("recv auth packet")
	if err := radius.ValidateAuthRequest(req); err != "" {
		if config.Debug {
			config.Log.Printf("auth.begin e=ValidateAuthRequest: %s", err)
		}

		radius.LogRecord(radius.ErrInvalidAuthRequest, addr, err).
			With("username", string(req.Attr(radius.UserName))).Save()
		return
	}

	reply := []radius.AttrEncoder{}

	user := string(req.Attr(radius.UserName))
	limits, err := model.Auth(config.DB, user)
	if err != nil {
		if config.Debug {
			config.Log.Printf("auth.begin e=" + err.Error())
		}

		radius.LogRecord(radius.ErrDBFail, addr, err.Error()).
			With("username", user).Save()
		return
	}
	if limits.Password == "" {
		if config.Debug {
			config.Log.Printf("auth.begin e=No such user")
		}
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "No such user"))

		radius.LogRecord(radius.ErrUserNotFound, addr, radius.ErrUserNotFound.Message).
			With("username", user).Save()
		return
	}

	if req.HasAttr(radius.UserPassword) {
		pass := radius.DecryptPassword(req.Attr(radius.UserPassword), req)
		if pass != limits.Password {
			if config.Debug {
				config.Log.Println("auth.begin e=Invalid password, ", pass, limits.Password)
			}
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))

			radius.LogRecord(radius.ErrUserPasswordNotMatch, addr,
				radius.ErrUserPasswordNotMatch.Message).
				With("username", user).Save()
			return
		}
		if config.Verbose {
			config.Log.Printf("PAP login user=%s", user)
		}
	} else if req.HasAttr(radius.CHAPPassword) {
		challenge := req.Attr(radius.CHAPChallenge)
		hash := req.Attr(radius.CHAPPassword)

		// TODO: No challenge then use Request Authenticator

		if !radius.CHAPMatch(limits.Password, hash, challenge) {
			if config.Debug {
				config.Log.Printf("auth.begin e=Invalid password")
			}
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))

			radius.LogRecord(radius.ErrUserPasswordNotMatch, addr,
				radius.ErrUserPasswordNotMatch.Message).
				With("username", user).Save()
			return
		}
		if config.Verbose {
			config.Log.Printf("CHAP login user=%s", user)
		}
	} else {
		// Search for MSCHAP attrs
		attrs := make(map[vendor.AttributeType]radius.AttrEncoder)
		for _, attr := range req.Attrs {
			if radius.AttributeType(attr.Type()) == radius.VendorSpecific {
				hdr := radius.VendorSpecificHeader(attr.Bytes())
				if hdr.VendorId == vendor.Microsoft {
					attrs[vendor.AttributeType(hdr.VendorType)] = attr
				}
			}
		}

		if len(attrs) > 0 && len(attrs) != 2 {
			if config.Debug {
				config.Log.Printf("auth.begin e=MSCHAP: Missing attrs? MS-CHAP-Challenge/MS-CHAP-Response")
			}
			w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAP: Missing attrs? MS-CHAP-Challenge/MS-CHAP-Response"))

			radius.LogRecord(radius.ErrInvalidMSCHAP, addr, "missing attrs").
				With("username", user).Save()
			return
		} else if len(attrs) == 2 {
			// Collect our data
			challenge := mschap.DecodeChallenge(attrs[vendor.MSCHAPChallenge].Bytes()).Value
			if _, isV1 := attrs[vendor.MSCHAPResponse]; isV1 {
				// MSCHAPv1
				res := mschap.DecodeResponse(attrs[vendor.MSCHAPResponse].Bytes())
				if res.Flags == 0 {
					// If it is zero, the NT-Response field MUST be ignored and
					// the LM-Response field used.
					if config.Debug {
						config.Log.Printf("auth.begin e=MSCHAPv1: LM-Response not supported.")
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response not supported."))

					radius.LogRecord(radius.ErrInvalidMSCHAP, addr,
						"LM-Response not supported").
						With("username", user).Save()
					return
				}
				if bytes.Compare(res.LMResponse, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
					if config.Debug {
						config.Log.Printf("auth.begin e=MSCHAPv1: LM-Response set.")
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: LM-Response set."))

					radius.LogRecord(radius.ErrInvalidMSCHAP, addr,
						"LM-Response set").
						With("username", user).Save()
					return
				}

				// Check for correctness
				calc, e := mschap.Encryptv1(challenge, limits.Password)
				if e != nil {
					if config.Debug {
						config.Log.Printf("MSCHAPv1: Encryptv1: " + e.Error())
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv1: Server-side processing error"))

					radius.LogRecord(radius.ErrInternalError, addr,
						"LM-MSCHAPv1: Server-side processing error, "+e.Error()).
						With("username", user).Save()
					return
				}
				mppe, e := mschap.Mppev1(limits.Password)
				if e != nil {
					if config.Debug {
						config.Log.Printf("MPPEv1: Mppev1: " + e.Error())
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MPPEv1: Server-side processing error"))

					radius.LogRecord(radius.ErrInternalError, addr,
						"LM-MSCHAPv1: Server-side processing error, "+e.Error()).
						With("username", user).Save()
					return
				}

				if bytes.Compare(res.NTResponse, calc) != 0 {
					if config.Verbose {
						config.Log.Printf(
							"MSCHAPv1 user=%s mismatch expect=%x, received=%x",
							user, calc, res.NTResponse,
						)
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))

					radius.LogRecord(radius.ErrUserPasswordNotMatch, addr,
						radius.ErrUserPasswordNotMatch.Message).
						With("username", user).Save()
					return
				}
				if config.Verbose {
					config.Log.Printf("MSCHAPv1 login user=%s", user)
				}

				reply = append(reply, radius.VendorAttr{
					Type:     radius.VendorSpecific,
					VendorId: vendor.Microsoft,
					/* 1 Encryption-Allowed, 2 Encryption-Required */
					Values: []radius.VendorAttrString{
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionPolicy,
							Value: []byte{0x0, 0x0, 0x0, 0x01},
						},
						/* encryption types, allow RC4[40/128bit] */
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionTypes,
							Value: []byte{0x0, 0x0, 0x0, 0x06},
						},
						/* mppe - encryption negotation key */
						radius.VendorAttrString{
							Type:  vendor.MSCHAPMPPEKeys,
							Value: mppe,
						},
					},
				}.Encode())

			} else if _, isV2 := attrs[vendor.MSCHAP2Response]; isV2 {
				// MSCHAPv2
				res := mschap.DecodeResponse2(attrs[vendor.MSCHAP2Response].Bytes())
				if res.Flags != 0 {
					if config.Debug {
						config.Log.Printf("auth.begin e=MSCHAPv2: Flags should be set to 0")
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Flags should be set to 0"))

					radius.LogRecord(radius.ErrInternalError, addr,
						"MSCHAPv2: Flags should be set to 0").
						With("username", user).Save()
					return
				}
				enc, e := mschap.Encryptv2(challenge, res.PeerChallenge, user, limits.Password)
				if e != nil {
					if config.Debug {
						config.Log.Printf("MSCHAPv2: Encryptv2: " + e.Error())
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAPv2: Server-side processing error"))

					radius.LogRecord(radius.ErrInternalError, addr,
						"MSCHAPv2: Server-side processing error, "+e.Error()).
						With("username", user).Save()
					return
				}
				send, recv := mschap.Mmpev2(req.Secret(), limits.Password, req.Auth, res.Response)

				if bytes.Compare(res.Response, enc.ChallengeResponse) != 0 {
					if config.Verbose {
						config.Log.Printf(
							"MSCHAPv2 user=%s mismatch expect=%x, received=%x",
							user, enc.ChallengeResponse, res.Response,
						)
					}
					w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid password"))

					radius.LogRecord(radius.ErrUserPasswordNotMatch, addr,
						radius.ErrUserPasswordNotMatch.Message).
						With("username", user).Save()
					return
				}
				if config.Verbose {
					config.Log.Printf("MSCHAPv2 login user=%s", user)
				}
				// TODO: Framed-Protocol = PPP, Framed-Compression = Van-Jacobson-TCP-IP
				reply = append(reply, radius.VendorAttr{
					Type:     radius.VendorSpecific,
					VendorId: vendor.Microsoft,
					Values: []radius.VendorAttrString{
						/* 1 Encryption-Allowed, 2 Encryption-Required */
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionPolicy,
							Value: []byte{0x0, 0x0, 0x0, 0x01},
						},
						/* encryption types, allow RC4[40/128bit] */
						radius.VendorAttrString{
							Type:  vendor.MSMPPEEncryptionTypes,
							Value: []byte{0x0, 0x0, 0x0, 0x06},
						},
						/* success challenge */
						radius.VendorAttrString{
							Type:  vendor.MSCHAP2Success,
							Value: append([]byte{byte(res.Ident)}, []byte(enc.AuthenticatorResponse)...),
						},
						/* Send-Key */
						radius.VendorAttrString{
							Type:  vendor.MSMPPESendKey,
							Value: send,
						},
						/* Recv-Key */
						radius.VendorAttrString{
							Type:  vendor.MSMPPERecvKey,
							Value: recv,
						},
					},
				}.Encode())
			} else {
				if config.Debug {
					config.Log.Printf("auth.begin e=MSCHAP: Response1/2 not found")
				}
				w.Write(radius.DefaultPacket(req, radius.AccessReject, "MSCHAP: Response1/2 not found"))

				radius.LogRecord(radius.ErrInternalError, addr,
					"MSCHAP: Response1/2 not found").
					With("username", user).Save()
				return
			}
		}
	}

	conns, e := model.SessionCount(config.DB, user)
	if e != nil {
		if config.Debug {
			config.Log.Printf("auth.begin e=SessionCount: " + e.Error())
		}

		radius.LogRecord(radius.ErrDBFail, addr, e.Error()).
			With("username", user).Save()
		return
	}
	if limits.SimultaneousUse != nil && conns >= *limits.SimultaneousUse {
		if config.Debug {
			config.Log.Printf("auth.begin e=Max conns reached")
		}
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Max conns reached"))

		radius.LogRecord(radius.ErrConnectionExceed, addr, radius.ErrConnectionExceed.Message).
			With("username", user).Save()
		return
	}

	if limits.Ok {
		if limits.DedicatedIP != nil {
			reply = append(reply, radius.NewAttr(
				radius.FramedIPAddress,
				net.ParseIP(*limits.DedicatedIP).To4(),
				0,
			))
		}
		if limits.Ratelimit != nil {
			// 	MT-Rate-Limit = MikrotikRateLimit
			reply = append(reply, radius.VendorAttr{
				Type:     radius.VendorSpecific,
				VendorId: vendor.Mikrotik,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type:  vendor.MikrotikRateLimit,
					Value: []byte(*limits.Ratelimit),
				}},
			}.Encode())
		}
		if limits.DnsOne != nil {
			// MS-Primary-DNS-Server
			// MS-Secondary-DNS-Server
			reply = append(reply, radius.VendorAttr{
				Type:     radius.VendorSpecific,
				VendorId: vendor.Microsoft,
				Values: []radius.VendorAttrString{radius.VendorAttrString{
					Type:  vendor.MSPrimaryDNSServer,
					Value: net.ParseIP(*limits.DnsOne).To4(),
				}, radius.VendorAttrString{
					Type:  vendor.MSSecondaryDNSServer,
					Value: net.ParseIP(*limits.DnsTwo).To4(),
				}},
			}.Encode())
		}

		//reply = append(reply, radius.PubAttr{Type: radius.PortLimit, Value: radius.EncodeFour(limits.SimultaneousUse-conns)})
		w.Write(req.Response(radius.AccessAccept, reply))
		return
	}

	if config.Debug {
		config.Log.Printf("auth.begin e=Invalid user/pass")
	}
	w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid user/pass"))

	radius.LogRecord(radius.ErrUserPasswordNotMatch, addr,
		radius.ErrUserPasswordNotMatch.Message).
		With("username", user).Save()
}

func acctBegin(w io.Writer, addr string, bas interface{}, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("WARN: acct.begin err=" + e)
		return
	}

	sess := string(req.Attr(radius.AcctSessionID))
	nasIP := radius.DecodeIP(req.Attr(radius.NASIPAddress)).String()
	user := string(req.Attr(radius.UserName))
	if config.Verbose {
		config.Log.Printf("acct.begin sess=%s for user=%s on nasIP=%s", sess, user, nasIP)
	}
	reply := []radius.AttrEncoder{}
	userLimits, e := model.Limits(config.DB, user)
	if e != nil {
		if e == model.ErrNoRows {
			config.Log.Printf("acct.begin received invalid user=" + user)
			return
		}
		config.Log.Printf("acct.begin e=" + e.Error())
		return
	}

	clientIP := string(req.Attr(radius.CallingStationID))
	var assignedIP string
	var nasPort string

	if !req.HasAttr(radius.FramedIPAddress) {
		config.Log.Printf("WARN: acct.begin missing FramedIPAddress")
	} else {
		assignedIP = radius.DecodeIP(req.Attr(radius.FramedIPAddress)).String()
	}

	if !req.HasAttr(radius.NASPortID) {
		config.Log.Printf("WARN: acct.begin missing NASPortID")
	} else {
		nasPort = string(req.Attr(radius.NASPortID))
	}
	if e := model.SessionAdd(config.DB, sess, userLimits.ID, nasIP, nasPort, assignedIP, clientIP); e != nil {
		config.Log.Printf("acct.begin e=%s", e.Error())
		return
	}
	w.Write(req.Response(radius.AccountingResponse, reply))
}

func acctUpdate(w io.Writer, addr string, bas interface{}, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("acct.update e=" + e)
		return
	}

	user := string(req.Attr(radius.UserName))
	userID, e := model.UserID(config.DB, user)
	if e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	sess := createSession(userID, req)
	if config.Verbose {
		config.Log.Printf(
			"acct.update sess=%s for user=%v on nasIP=%s nasPort=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess.SessionID, sess.User, sess.NasIP, sess.NasPort, sess.SessionTime, sess.BytesIn, sess.BytesOut,
		)
	}
	txn, e := model.Begin()
	if e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionUpdate(txn, sess); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	queue.Queue(sess.User, sess.BytesIn, sess.BytesOut, sess.PacketsIn, sess.PacketsOut)
	if e := txn.Commit(); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Updated accounting."))
}

func acctStop(w io.Writer, addr string, bas interface{}, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("acct.stop e=" + e)
		return
	}
	user := string(req.Attr(radius.UserName))
	sess := string(req.Attr(radius.AcctSessionID))
	nasIP := radius.DecodeIP(req.Attr(radius.NASIPAddress)).String()

	sessTime := radius.DecodeFour(req.Attr(radius.AcctSessionTime))
	octIn := radius.DecodeFour(req.Attr(radius.AcctInputOctets))
	octOut := radius.DecodeFour(req.Attr(radius.AcctOutputOctets))

	packIn := radius.DecodeFour(req.Attr(radius.AcctInputPackets))
	packOut := radius.DecodeFour(req.Attr(radius.AcctOutputPackets))

	if config.Verbose {
		config.Log.Printf(
			"acct.stop sess=%s for user=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess, user, sessTime, octIn, octOut,
		)
	}

	userID, e := model.UserID(config.DB, user)
	if e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}

	sessModel := createSession(userID, req)
	txn, e := model.Begin()
	if e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionUpdate(txn, sessModel); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionLog(txn, sess, userID, nasIP); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionRemove(txn, sess, userID, nasIP); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	queue.Queue(userID, octIn, octOut, packIn, packOut)
	if e := txn.Commit(); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Finished accounting."))
}
