// radius commands
package main

import (
	"io"
	"radiusd/config"
	"radiusd/model"
	"radiusd/queue"
	"radiusd/radius"
	"net"
)

func auth(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAuthRequest(req); e != "" {
		if config.Verbose {
			config.Log.Printf("auth.begin err=" + e)
		}
		w.Write(radius.DefaultPacket(req, radius.AccessReject, e))
		return
	}

	user := string(req.Attrs[radius.UserName].Value)
	raw := req.Attrs[radius.UserPassword].Value
	pass := radius.DecryptPassword(raw, req)

	if config.Verbose {
		config.Log.Printf("auth user=%s pass=%s", user, pass)
	}
	state, e := model.Auth(user, pass)
	if e != nil {
		config.Log.Printf("auth.begin err=" + e.Error())
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Database error"))
		return
	}

	if state.Ok {
		w.Write(radius.DefaultPacket(req, radius.AccessAccept, "Ok."))
		return
	}

	conns, e := model.Conns(user)
	if e != nil {
		config.Log.Printf("auth.begin err=" + e.Error())
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Database error"))
		return
	}
	if state.SimultaneousUse > conns {
		w.Write(radius.DefaultPacket(req, radius.AccessReject, "Max conns reached"))
		return
	}

	w.Write(radius.DefaultPacket(req, radius.AccessReject, "Invalid user/pass"))
}

func acctBegin(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("WARN: acct.begin err=" + e)
		return
	}
	if _, there := req.Attrs[radius.FramedIPAddress]; !there {
		config.Log.Printf("WARN: acct.begin missing FramedIPAddress")
		return
	}

	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)
	nasIp := radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String()
	clientIp := radius.DecodeIP(req.Attrs[radius.CallingStationId].Value).String()
	assignedIp := radius.DecodeIP(req.Attrs[radius.FramedIPAddress].Value).String()

	if config.Verbose {
		config.Log.Printf("acct.begin sess=%s for user=%s on nasIP=%s", sess, user, nasIp)
	}
	reply := []radius.PubAttr{}
	limits, e := model.Limits(user)
	if e != nil {
		if e == model.ErrNoRows {
			config.Log.Printf("acct.begin received invalid user=" + user)
			return
		}
		config.Log.Printf("acct.begin e=" + e.Error())
		return
	}

	if limits.DedicatedIP != nil {
		reply = append(reply, radius.PubAttr{
			Type: radius.FramedIPAddress,
			Value: net.ParseIP(*limits.DedicatedIP).To4(),
		})
	}
	if limits.Ratelimit != nil {
		/*reply = append(reply, radius.VendorAttr{
			Type: radius.VendorSpecific,
			// TODO: Subtype?
			Value: *limits.Ratelimit,
		})*/
	}

	if e := model.SessionAdd(sess, user, nasIp, assignedIp, clientIp); e != nil {
		config.Log.Printf("acct.begin e=%s", e.Error())
		return
	}
	w.Write(req.Response(radius.AccountingResponse, reply))
}

func acctUpdate(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("acct.update e=" + e)
		return
	}

	sess := model.Session{
		BytesIn: radius.DecodeFour(req.Attrs[radius.AcctInputOctets].Value),
		BytesOut: radius.DecodeFour(req.Attrs[radius.AcctOutputOctets].Value),
		PacketsIn: radius.DecodeFour(req.Attrs[radius.AcctInputPackets].Value),
		PacketsOut: radius.DecodeFour(req.Attrs[radius.AcctOutputPackets].Value),
		SessionID: string(req.Attrs[radius.AcctSessionId].Value),
		SessionTime: radius.DecodeFour(req.Attrs[radius.AcctSessionTime].Value),
		User: string(req.Attrs[radius.UserName].Value),
		NasIP: radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String(),
	}

	if config.Verbose {
		config.Log.Printf(
			"acct.update sess=%s for user=%s on NasIP=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess.SessionID, sess.User, sess.NasIP, sess.SessionTime, sess.BytesIn, sess.BytesOut,
		)
	}
	if e := model.SessionUpdate(sess); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}

	queue.Queue(sess.User, sess.BytesIn, sess.BytesOut)
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Updated accounting."))
}

func acctStop(w io.Writer, req *radius.Packet) {
	if e := radius.ValidateAcctRequest(req); e != "" {
		config.Log.Printf("acct.stop e=" + e)
		return
	}
	user := string(req.Attrs[radius.UserName].Value)
	sess := string(req.Attrs[radius.AcctSessionId].Value)
	nasIp := radius.DecodeIP(req.Attrs[radius.NASIPAddress].Value).String()

	sessTime := radius.DecodeFour(req.Attrs[radius.AcctSessionTime].Value)
	octIn := radius.DecodeFour(req.Attrs[radius.AcctInputOctets].Value)
	octOut := radius.DecodeFour(req.Attrs[radius.AcctOutputOctets].Value)

	if config.Verbose {
		config.Log.Printf(
			"acct.stop sess=%s for user=%s sessTime=%d octetsIn=%d octetsOut=%d",
			sess, user, sessTime, octIn, octOut,
		)
	}
	if e := model.SessionLog(sess, user, nasIp); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}
	if e := model.SessionRemove(sess, user, nasIp); e != nil {
		config.Log.Printf("acct.update e=" + e.Error())
		return
	}

	queue.Queue(user, octIn, octOut)
	w.Write(radius.DefaultPacket(req, radius.AccountingResponse, "Finished accounting."))
}