package server

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// TunnelPath is the last path segment that opens a tunnel through an
// egress-proxy service: /<service>/_tunnel?host=H&port=P.
const TunnelPath = "/_tunnel"

// WebSocket close codes the tunnel uses (RFC 6455 and private range).
const (
	closeNormal      = 1000
	closeProtocol    = 1002
	closeUnsupported = 1003
	closePolicy      = 1008
	closeTooBig      = 1009
	closeError       = 1011
	closeIdle        = 4000
	closeMaxDuration = 4001
)

// errProxyRefused: the proxy is reachable but refused (credential or
// destination). Other dial errors mean it is unreachable.
var errProxyRefused = errors.New("the proxy refused the connection")

// proxyDialer dials the person's proxy. Tests replace it to reach a proxy on
// loopback, which the address check otherwise refuses.
type proxyDialer func(ctx context.Context, address string) (net.Conn, error)

// dialPublic connects to address, refusing any resolved address that is not
// public, so a proxy name cannot point the keyring at its own network.
func dialPublic(ctx context.Context, address string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(_, addr string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(addr)
			if err != nil || !policy.PublicAddr(ap.Addr()) {
				return errors.New("proxy address is not public")
			}
			return nil
		},
	}
	return d.DialContext(ctx, "tcp", address)
}

// dialThroughProxy opens a TCP connection to host:port through the proxy in
// e, authenticated with credential ("user:password").
func dialThroughProxy(ctx context.Context, dial proxyDialer, e *policy.EgressProxy, credential, host string, port int) (net.Conn, error) {
	conn, err := dial(ctx, e.Address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if e.TLS {
		name, _, _ := net.SplitHostPort(e.Address)
		tc := tls.Client(conn, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	switch e.Type {
	case policy.ProxyHTTPConnect:
		err = httpConnect(conn, credential, target)
	case policy.ProxySOCKS5:
		err = socks5Connect(conn, credential, host, port)
	default:
		err = errors.New("unknown proxy type")
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func httpConnect(conn net.Conn, credential, target string) error {
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if credential != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(credential)) + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		return err
	}
	// Read the status line and headers one byte at a time, so no tunnel
	// byte is buffered away, and never read a body: a 2xx reply to CONNECT
	// has none (RFC 9110 9.3.6), and anything after the headers is tunnel.
	tp := textproto.NewReader(bufio.NewReaderSize(oneByteReader{conn}, 16))
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}
	proto, rest, _ := strings.Cut(line, " ")
	code, _, _ := strings.Cut(rest, " ")
	status, err := strconv.Atoi(code)
	if !strings.HasPrefix(proto, "HTTP/1.") || err != nil {
		return errors.New("the proxy sent a malformed reply")
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return fmt.Errorf("%w (%d)", errProxyRefused, status)
	}
	return nil
}

type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return o.r.Read(p)
}

func socks5Connect(conn net.Conn, credential, host string, port int) error {
	user, pass, _ := strings.Cut(credential, ":")
	if len(user) > 255 || len(pass) > 255 || len(host) > 255 {
		return errors.New("socks5 field too long")
	}
	method := byte(0x00)
	if credential != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 5 || reply[1] != method {
		return fmt.Errorf("%w (method)", errProxyRefused)
	}
	if method == 0x02 {
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pass))), pass...)
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return err
		}
		if reply[1] != 0 {
			return fmt.Errorf("%w (auth)", errProxyRefused)
		}
	}
	req := []byte{5, 1, 0}
	if a, err := netip.ParseAddr(host); err == nil && a.Is4() {
		req = append(append(req, 1), a.AsSlice()...)
	} else if err == nil {
		req = append(append(req, 4), a.AsSlice()...)
	} else {
		// A name: the proxy resolves it.
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("%w (%d)", errProxyRefused, head[1])
	}
	skip := 0
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return err
		}
		skip = int(n[0])
	default:
		return errors.New("socks5 bad reply")
	}
	_, err := io.ReadFull(conn, make([]byte, skip+2))
	return err
}

// tunnelTarget reads and checks ?host=&port= against the service.
func tunnelTarget(r *http.Request, e *policy.EgressProxy) (string, int, int, string) {
	q := r.URL.Query()
	host, portText := q.Get("host"), q.Get("port")
	port, err := strconv.Atoi(portText)
	if host == "" || err != nil || port < 1 || port > 65535 || len(q) != 2 {
		return "", 0, http.StatusBadRequest, "want ?host=<name or public IP>&port=<port>"
	}
	if !policy.TunnelHost(host) {
		return "", 0, http.StatusForbidden, "destination not allowed"
	}
	allowed := false
	for _, p := range e.AllowedPorts() {
		allowed = allowed || p == port
	}
	if !allowed {
		return "", 0, http.StatusForbidden, "port not allowed"
	}
	return host, port, 0, ""
}

// isWebSocketUpgrade reports whether r asks for a WebSocket.
func isWebSocketUpgrade(r *http.Request) bool {
	return r.Method == http.MethodGet && headerHas(r.Header, "Connection", "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && r.Header.Get("Sec-WebSocket-Version") == "13" &&
		r.Header.Get("Sec-WebSocket-Key") != ""
}

func headerHas(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// tunnelStats is what one tunnel moved, for the audit and the byte limit.
type tunnelStats struct {
	up, down atomic.Int64
	close    int
}

// wsWriteTimeout bounds one frame write: a client that stops reading cannot
// hold a tunnel (and its proxy connection) open.
const (
	wsWriteTimeout = 30 * time.Second
	wsCloseTimeout = 5 * time.Second
)

// pipeTunnel accepts the WebSocket on w and copies bytes between it and
// upstream until either side ends, the idle or maximum time passes, or allow
// refuses more bytes. hijacked reports whether w was taken over (after that
// no HTTP reply can be written).
func pipeTunnel(w http.ResponseWriter, r *http.Request, upstream net.Conn, e *policy.EgressProxy, allow func(n int64) bool, st *tunnelStats) (hijacked bool, err error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return false, errors.New("connection cannot be upgraded")
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	client, brw, err := hj.Hijack()
	if err != nil {
		return false, err
	}
	defer client.Close()
	defer upstream.Close()
	_ = client.SetDeadline(time.Now().Add(wsWriteTimeout))
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"); err != nil {
		return true, err
	}
	if err := brw.Flush(); err != nil {
		return true, err
	}
	_ = client.SetDeadline(time.Time{})
	ws := &wsConn{r: brw.Reader, conn: client}
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	done := make(chan int, 2)
	// Client to upstream.
	go func() {
		for {
			op, payload, err := ws.readMessagePart()
			if err != nil {
				var pe protocolError
				if errors.As(err, &pe) {
					done <- int(pe)
				} else {
					done <- closeNormal
				}
				return
			}
			switch op {
			case opBinary, opContinuation:
				if !allow(int64(len(payload))) {
					done <- closePolicy
					return
				}
				lastActive.Store(time.Now().UnixNano())
				st.up.Add(int64(len(payload)))
				if _, err := upstream.Write(payload); err != nil {
					done <- closeError
					return
				}
			case opClose:
				done <- closeNormal
				return
			case opPing:
				if ws.writeFrame(opPong, payload) != nil {
					done <- closeNormal
					return
				}
			case opPong:
			}
		}
	}()
	// Upstream to client.
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if !allow(int64(n)) {
					done <- closePolicy
					return
				}
				lastActive.Store(time.Now().UnixNano())
				st.down.Add(int64(n))
				if werr := ws.writeFrame(opBinary, buf[:n]); werr != nil {
					done <- closeNormal
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					done <- closeNormal
				} else {
					done <- closeError
				}
				return
			}
		}
	}()
	max := time.NewTimer(e.Max())
	defer max.Stop()
	tick := time.NewTicker(min(e.Idle()/4, 5*time.Second))
	defer tick.Stop()
	var code int
wait:
	for {
		select {
		case code = <-done:
			break wait
		case <-max.C:
			code = closeMaxDuration
			break wait
		case <-tick.C:
			if time.Since(time.Unix(0, lastActive.Load())) >= e.Idle() {
				code = closeIdle
				break wait
			}
		}
	}
	st.close = code
	// Unblock both goroutines before the close frame: the upstream side
	// ends at once, and a write stuck on a client that stopped reading ends
	// at its deadline, so the close frame never waits on a held lock for long.
	upstream.Close()
	ws.closing.Store(true)
	// Applies to a write already blocked, too.
	_ = client.SetWriteDeadline(time.Now().Add(wsCloseTimeout))
	reason := map[int]string{closeNormal: "", closeProtocol: "protocol error", closeUnsupported: "binary frames only",
		closePolicy: "daily byte limit reached", closeError: "upstream connection failed", closeIdle: "idle timeout",
		closeMaxDuration: "maximum duration reached"}[code]
	_ = ws.writeFrame(opClose, binary.BigEndian.AppendUint16(nil, uint16(code)), []byte(reason)...)
	return true, nil
}

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
	maxFrame       = 1 << 20
)

// protocolError is a client frame the tunnel refuses; its value is the close
// code to send.
type protocolError int

func (p protocolError) Error() string { return "websocket protocol error " + strconv.Itoa(int(p)) }

// wsConn is the server side of RFC 6455 framing: client frames must be
// masked, server frames are not.
type wsConn struct {
	r    *bufio.Reader
	conn net.Conn
	mu   sync.Mutex
	// inMessage: a binary message was started and not finished (FIN 0).
	inMessage bool
	// closing shortens every later write to the teardown deadline.
	closing atomic.Bool
}

// readMessagePart reads one frame and checks it against RFC 6455: masked,
// no RSV bits, control frames short and unfragmented, continuations only
// inside a binary message, no text messages.
func (c *wsConn) readMessagePart() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		return 0, nil, err
	}
	fin, op := h[0]&0x80 != 0, h[0]&0x0F
	if h[0]&0x70 != 0 || h[1]&0x80 == 0 {
		return 0, nil, protocolError(closeProtocol)
	}
	n := int64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(c.r, b[:]); err != nil {
			return 0, nil, err
		}
		n = int64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(c.r, b[:]); err != nil {
			return 0, nil, err
		}
		n = int64(binary.BigEndian.Uint64(b[:]))
	}
	control := op >= 0x8
	switch {
	case n < 0 || n > maxFrame:
		return 0, nil, protocolError(closeTooBig)
	case control && (n > 125 || !fin):
		return 0, nil, protocolError(closeProtocol)
	case op == opText:
		return 0, nil, protocolError(closeUnsupported)
	case op == opBinary && c.inMessage, op == opContinuation && !c.inMessage:
		return 0, nil, protocolError(closeProtocol)
	case !control && op != opBinary && op != opContinuation:
		return 0, nil, protocolError(closeProtocol)
	case control && op != opClose && op != opPing && op != opPong:
		return 0, nil, protocolError(closeProtocol)
	}
	if !control {
		c.inMessage = !fin
	}
	var mask [4]byte
	if _, err := io.ReadFull(c.r, mask[:]); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return op, payload, nil
}

func (c *wsConn) writeFrame(op byte, payload []byte, more ...byte) error {
	payload = append(payload, more...)
	head := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		head = append(head, byte(n))
	case n <= 0xFFFF:
		head = binary.BigEndian.AppendUint16(append(head, 126), uint16(n))
	default:
		head = binary.BigEndian.AppendUint64(append(head, 127), uint64(n))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	timeout := wsWriteTimeout
	if c.closing.Load() {
		timeout = wsCloseTimeout
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := c.conn.Write(append(head, payload...)); err != nil {
		return err
	}
	return nil
}
