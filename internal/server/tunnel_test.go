package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const proxyCredential = "person:proxy-pass-123"

// echoTarget is the destination behind the proxy: it echoes bytes.
func echoTarget(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}

// fakeProxy is an HTTP CONNECT or SOCKS5 proxy that requires
// proxyCredential and connects every request to target, recording what it
// was asked for.
type fakeProxy struct {
	addr   string
	mu     sync.Mutex
	asked  []string // destinations requested
	creds  []string // credentials presented
	target string
}

func (p *fakeProxy) record(dest, cred string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, dest)
	p.creds = append(p.creds, cred)
}

func newFakeProxy(t *testing.T, kind, target string) *fakeProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	p := &fakeProxy{addr: l.Addr().String(), target: target}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go p.serve(c, kind)
		}
	}()
	return p
}

func (p *fakeProxy) serve(c net.Conn, kind string) {
	defer c.Close()
	br := bufio.NewReader(c)
	if kind == policy.ProxyHTTPConnect {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		cred := ""
		if v, ok := strings.CutPrefix(req.Header.Get("Proxy-Authorization"), "Basic "); ok {
			b, _ := base64.StdEncoding.DecodeString(v)
			cred = string(b)
		}
		p.record(req.Host, cred)
		if cred != proxyCredential {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return
		}
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	} else {
		var h [2]byte
		io.ReadFull(br, h[:])
		methods := make([]byte, h[1])
		io.ReadFull(br, methods)
		c.Write([]byte{5, 2})
		var v [2]byte
		io.ReadFull(br, v[:])
		user := make([]byte, v[1])
		io.ReadFull(br, user)
		var pl [1]byte
		io.ReadFull(br, pl[:])
		pass := make([]byte, pl[0])
		io.ReadFull(br, pass)
		cred := string(user) + ":" + string(pass)
		if cred != proxyCredential {
			p.record("", cred)
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
		var req [4]byte
		io.ReadFull(br, req[:])
		dest := ""
		switch req[3] {
		case 3:
			var n [1]byte
			io.ReadFull(br, n[:])
			name := make([]byte, n[0])
			io.ReadFull(br, name)
			dest = string(name)
		case 1:
			a := make([]byte, 4)
			io.ReadFull(br, a)
			dest = net.IP(a).String()
		}
		var port [2]byte
		io.ReadFull(br, port[:])
		p.record(net.JoinHostPort(dest, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), cred)
		c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	}
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, br) }()
	_, _ = io.Copy(c, up)
}

// lockedBuffer is an audit sink safe to read while a tunnel handler writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// tunnelHandler builds a handler with an egress-proxy service "proxy" whose
// proxy is reached on loopback (the public-address check is for real dials).
func tunnelHandler(t *testing.T, kind, proxyAddr string, access policy.Access, mutate func(*policy.EgressProxy)) (*Handler, *lockedBuffer, *httptest.Server) {
	t.Helper()
	e := &policy.EgressProxy{Type: kind, Address: "proxy.example.com:1080", Ports: []int{443}, IdleSeconds: 2}
	if mutate != nil {
		mutate(e)
	}
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{"127.0.0.1"}, AuditLog: "audit.log"},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{"api": {Key: "PROXY_CRED", Auth: policy.AuthEgressProxy, EgressProxy: e}},
			Roles:    map[string]policy.Role{"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"api": access}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &lockedBuffer{}
	h := New(cfg, map[string]string{"PROXY_CRED": proxyCredential}, audit)
	h.dialProxy = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", proxyAddr)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, audit, srv
}

// wsClient opens a tunnel and returns the raw connection after the 101, or
// the HTTP status and body of a refusal.
func wsClient(t *testing.T, srv *httptest.Server, path string, token string) (net.Conn, *bufio.Reader, int, string) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 16)
	rand.Read(key)
	req := "GET " + path + " HTTP/1.1\r\nHost: keyring\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(key) + "\r\n" + TokenHeader + ": " + token + "\r\n\r\n"
	io.WriteString(c, req)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(resp.Body)
		c.Close()
		return nil, nil, resp.StatusCode, string(b)
	}
	return c, br, 101, ""
}

func sendFrame(c net.Conn, op byte, payload []byte) {
	head := []byte{0x80 | op}
	if len(payload) < 126 {
		head = append(head, 0x80|byte(len(payload)))
	} else {
		head = binary.BigEndian.AppendUint16(append(head, 0x80|126), uint16(len(payload)))
	}
	mask := []byte{1, 2, 3, 4}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	c.Write(append(append(head, mask...), masked...))
}

func readFrame(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	var h [2]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	n := int(h[1] & 0x7F)
	if n == 126 {
		var b [2]byte
		io.ReadFull(br, b[:])
		n = int(binary.BigEndian.Uint16(b[:]))
	}
	p := make([]byte, n)
	io.ReadFull(br, p)
	return h[0] & 0x0F, p
}

func TestTunnelThroughHTTPConnectAndSOCKS5(t *testing.T) {
	for _, kind := range []string{policy.ProxyHTTPConnect, policy.ProxySOCKS5} {
		t.Run(kind, func(t *testing.T) {
			proxy := newFakeProxy(t, kind, echoTarget(t))
			_, audit, srv := tunnelHandler(t, kind, proxy.addr, allowAll, nil)
			c, br, code, body := wsClient(t, srv, "/api/_tunnel?host=mail.example.com&port=443", testToken)
			if code != 101 {
				t.Fatalf("upgrade: %d %s", code, body)
			}
			defer c.Close()
			sendFrame(c, opBinary, []byte("hello through the proxy"))
			op, got := readFrame(t, br)
			if op != opBinary || string(got) != "hello through the proxy" {
				t.Fatalf("echo: op %d %q", op, got)
			}
			sendFrame(c, opClose, binary.BigEndian.AppendUint16(nil, 1000))
			op, got = readFrame(t, br)
			if op != opClose || binary.BigEndian.Uint16(got) != closeNormal {
				t.Fatalf("close: op %d %v", op, got)
			}
			proxy.mu.Lock()
			asked, creds := proxy.asked, proxy.creds
			proxy.mu.Unlock()
			// The name goes to the proxy unresolved.
			if len(asked) != 1 || asked[0] != "mail.example.com:443" || creds[0] != proxyCredential {
				t.Fatalf("proxy got %v %v", asked, creds)
			}
			time.Sleep(50 * time.Millisecond) // audit is written as the handler returns
			log := audit.String()
			if strings.Contains(log, "proxy-pass-123") || !strings.Contains(log, `"status":101`) || !strings.Contains(log, "tunnel mail.example.com:443 closed 1000") {
				t.Fatalf("audit:\n%s", log)
			}
		})
	}
}

func TestTunnelRefusals(t *testing.T) {
	proxy := newFakeProxy(t, policy.ProxyHTTPConnect, echoTarget(t))
	_, _, srv := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, allowAll, nil)
	cases := []struct {
		path string
		want int
	}{
		{"/api/_tunnel?host=10.0.0.1&port=443", 403},
		{"/api/_tunnel?host=127.0.0.1&port=443", 403},
		{"/api/_tunnel?host=100.100.100.100&port=443", 403}, // Tailscale / CGNAT
		{"/api/_tunnel?host=169.254.169.254&port=443", 403},
		{"/api/_tunnel?host=%5B::1%5D&port=443", 403},
		{"/api/_tunnel?host=::1&port=443", 403},
		{"/api/_tunnel?host=example.com&port=22", 403},
		{"/api/_tunnel?host=example.com", 400},
		{"/api/_tunnel?host=example.com&port=443&extra=1", 400},
		{"/api/v1/x", 404}, // an egress-proxy service only tunnels
	}
	for _, c := range cases {
		if _, _, code, body := wsClient(t, srv, c.path, testToken); code != c.want {
			t.Errorf("%s: %d %s, want %d", c.path, code, body, c.want)
		}
	}
	if _, _, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", "wrong-token"); code != 401 {
		t.Errorf("bad role token: %d", code)
	}
	// Without the WebSocket upgrade.
	req, _ := http.NewRequest("GET", srv.URL+"/api/_tunnel?host=example.com&port=443", nil)
	req.Header.Set(TokenHeader, testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("plain GET: %d", resp.StatusCode)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if len(proxy.asked) != 0 {
		t.Fatalf("refused tunnels reached the proxy: %v", proxy.asked)
	}
}

func TestTunnelProxyFailures(t *testing.T) {
	// Wrong credential: the proxy refuses; 502, the credential never shown.
	proxy := newFakeProxy(t, policy.ProxySOCKS5, echoTarget(t))
	h, audit, srv := tunnelHandler(t, policy.ProxySOCKS5, proxy.addr, policy.Access{Paths: []string{"/"}, DailyRequests: 1}, nil)
	h.Swap(h.Config(), map[string]string{"PROXY_CRED": "person:wrong-pass"})
	_, _, code, body := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken)
	if code != 502 || !strings.Contains(body, "refused") || strings.Contains(body, "wrong-pass") {
		t.Fatalf("wrong credential: %d %s", code, body)
	}
	// The failed tunnel did not use the daily limit (1).
	h.Swap(h.Config(), map[string]string{"PROXY_CRED": proxyCredential})
	if c, _, code, body := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken); code != 101 {
		t.Fatalf("after fixing the credential: %d %s", code, body)
	} else {
		c.Close()
	}
	if _, _, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken); code != 429 {
		t.Fatalf("second tunnel with daily_requests 1: %d", code)
	}
	// No credential stored: 503.
	h.Swap(h.Config(), map[string]string{})
	if _, _, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken); code != 503 {
		t.Fatalf("no credential: %d", code)
	}
	if strings.Contains(audit.String(), "pass") {
		t.Fatalf("audit holds a credential:\n%s", audit)
	}

	// Proxy unreachable.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()
	_, _, srv2 := tunnelHandler(t, policy.ProxyHTTPConnect, dead, allowAll, nil)
	if _, _, code, body := wsClient(t, srv2, "/api/_tunnel?host=example.com&port=443", testToken); code != 502 || !strings.Contains(body, "unreachable") {
		t.Fatalf("dead proxy: %d %s", code, body)
	}
}

func TestTunnelLimits(t *testing.T) {
	proxy := newFakeProxy(t, policy.ProxyHTTPConnect, echoTarget(t))
	_, _, srv := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, policy.Access{Paths: []string{"/"}, DailyBytes: 20}, nil)
	c, br, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken)
	if code != 101 {
		t.Fatalf("upgrade: %d", code)
	}
	sendFrame(c, opBinary, []byte("0123456789")) // 10 up + 10 down = 20
	readFrame(t, br)
	sendFrame(c, opBinary, []byte("x"))
	op, got := readFrame(t, br)
	if op != opClose || binary.BigEndian.Uint16(got) != closePolicy {
		t.Fatalf("over the byte limit: op %d %v %q", op, got, got)
	}
	c.Close()
	if _, _, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken); code != 429 {
		t.Fatalf("new tunnel after the byte limit: %d", code)
	}

	// Idle timeout (2 s in tunnelHandler).
	_, _, srv2 := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, allowAll, nil)
	c, br, _, _ = wsClient(t, srv2, "/api/_tunnel?host=example.com&port=443", testToken)
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	op, got = readFrame(t, br)
	if op != opClose || binary.BigEndian.Uint16(got) != closeIdle {
		t.Fatalf("idle: op %d %v", op, got)
	}

	// Text frames are refused.
	c3, br3, _, _ := wsClient(t, srv2, "/api/_tunnel?host=example.com&port=443", testToken)
	defer c3.Close()
	sendFrame(c3, opText, []byte("hi"))
	op, got = readFrame(t, br3)
	if op != opClose || binary.BigEndian.Uint16(got) != closeUnsupported {
		t.Fatalf("text frame: op %d %v", op, got)
	}
}

func TestEgressProxyPolicy(t *testing.T) {
	for _, bad := range []policy.EgressProxy{
		{Type: "http", Address: "proxy.example.com:8080"},
		{Type: policy.ProxyHTTPConnect, Address: "10.0.0.1:8080"},
		{Type: policy.ProxyHTTPConnect, Address: "127.0.0.1:8080"},
		{Type: policy.ProxyHTTPConnect, Address: "100.64.1.1:8080"},
		{Type: policy.ProxyHTTPConnect, Address: "proxy.example.com"},
		{Type: policy.ProxySOCKS5, Address: "proxy.example.com:1080", TLS: true},
		{Type: policy.ProxySOCKS5, Address: "proxy.example.com:1080", Ports: []int{0}},
	} {
		c := &policy.Config{
			Rules:      policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{"127.0.0.1"}, AuditLog: "/x"},
			AccessList: policy.AccessList{Services: map[string]policy.Service{"p": {Key: "K", Auth: policy.AuthEgressProxy, EgressProxy: &bad}}},
		}
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// daily_bytes only on egress-proxy services.
	c := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{"127.0.0.1"}, AuditLog: "/x"},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{"api": {Base: "https://api.example.com", Key: "K", Auth: policy.AuthBearer}},
			Roles:    map[string]policy.Role{"r": {TokenSHA256: tokenHash("t"), Access: map[string]policy.Access{"api": {Paths: []string{"/"}, DailyBytes: 5}}}},
		},
	}
	if err := c.Validate(); err == nil {
		t.Error("daily_bytes on a bearer service accepted")
	}
}

func TestDialPublicRefusesPrivateProxy(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if c, err := dialPublic(context.Background(), l.Addr().String()); err == nil {
		c.Close()
		t.Fatal("dialPublic reached a loopback proxy")
	}
}

// TestTunnelPathOnlyOnEgressServices: on any other service /_tunnel is an
// ordinary path and is forwarded as before (existing services unchanged).
func TestTunnelPathOnlyOnEgressServices(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	if w := call(h, "GET", "/api/_tunnel?host=example.com&port=443", testToken, nil); w.Code != http.StatusOK {
		t.Fatalf("/_tunnel on a bearer service: %d", w.Code)
	}
	if r := got.last(t); r.URL.Path != "/_tunnel" {
		t.Fatalf("forwarded %q", r.URL.Path)
	}
}

func TestTunnelRefusesZonedAndEmbeddedIPv4(t *testing.T) {
	for _, host := range []string{
		"64:ff9b::a00:1%eth0", "64:ff9b::7f00:1%x", "100::1%eth0", "2001:db8::1%eth0", "::%eth0", "2001:0::1%eth0",
		"2606:4700::1%\r\nX-Injected: yes]", "2606:4700::1%eth0",
		"64:ff9b:1::a00:1", "2002:a00:1::1", "2001:0:a00:1::1", "fd00::1",
		"::7f00:1", "::a00:1", "::ffff:0:a00:1", "fe80::1", "ff02::1", "::1",
	} {
		if policy.TunnelHost(host) {
			t.Errorf("TunnelHost(%q) = true", host)
		}
	}
	for _, host := range []string{"2606:4700::1", "1.1.1.1", "mail.example.com"} {
		if !policy.TunnelHost(host) {
			t.Errorf("TunnelHost(%q) = false", host)
		}
	}
}

// TestTunnelClientThatStopsReading: a client that never reads cannot hold
// the tunnel and its proxy connection past the idle timeout plus the
// teardown deadline.
func TestTunnelClientThatStopsReading(t *testing.T) {
	// A target that sends forever.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				chunk := bytes.Repeat([]byte("x"), 64<<10)
				for {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
			}()
		}
	}()
	proxy := newFakeProxy(t, policy.ProxyHTTPConnect, l.Addr().String())
	_, audit, srv := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, allowAll, func(e *policy.EgressProxy) { e.MaxSeconds = 1 })
	c, _, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken)
	if code != 101 {
		t.Fatalf("upgrade: %d", code)
	}
	defer c.Close()
	// Never read. The handler must still finish: max 1 s + close timeout 5 s.
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(audit.String(), "closed 4001") {
		if time.Now().After(deadline) {
			t.Fatalf("tunnel still open with a client that stopped reading; audit:\n%s", audit)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestHTTPConnectReplyBodyIsTunnel: bytes after the 200 headers belong to
// the tunnel even if the proxy sends a Content-Length.
func TestHTTPConnectReplyBodyIsTunnel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		br := bufio.NewReader(b)
		_, _ = http.ReadRequest(br)
		io.WriteString(b, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfirst-tunnel-bytes")
	}()
	if err := httpConnect(a, proxyCredential, "example.com:443"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 18)
	if _, err := io.ReadFull(a, buf); err != nil || string(buf) != "first-tunnel-bytes" {
		t.Fatalf("tunnel bytes after CONNECT: %q %v", buf, err)
	}
}

func TestTunnelFramingErrors(t *testing.T) {
	proxy := newFakeProxy(t, policy.ProxyHTTPConnect, echoTarget(t))
	_, _, srv := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, allowAll, nil)
	cases := []struct {
		name string
		send func(net.Conn)
		want uint16
	}{
		{"rsv bit", func(c net.Conn) { c.Write([]byte{0xC2, 0x80, 1, 2, 3, 4}) }, closeProtocol},
		{"continuation without a message", func(c net.Conn) { sendFrame(c, opContinuation, []byte("x")) }, closeProtocol},
		{"fragmented ping", func(c net.Conn) { c.Write([]byte{0x09, 0x80, 1, 2, 3, 4}) }, closeProtocol},
		{"long ping", func(c net.Conn) { sendFrame(c, opPing, bytes.Repeat([]byte("p"), 200)) }, closeProtocol},
		{"unmasked", func(c net.Conn) { c.Write([]byte{0x82, 0x01, 'x'}) }, closeProtocol},
	}
	for _, tc := range cases {
		c, br, code, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken)
		if code != 101 {
			t.Fatalf("%s: upgrade %d", tc.name, code)
		}
		tc.send(c)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		op, got := readFrame(t, br)
		if op != opClose || binary.BigEndian.Uint16(got) != tc.want {
			t.Errorf("%s: op %d code %v", tc.name, op, got)
		}
		c.Close()
	}
}

func TestTunnelBytesSurviveRestart(t *testing.T) {
	proxy := newFakeProxy(t, policy.ProxyHTTPConnect, echoTarget(t))
	h, _, srv := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, policy.Access{Paths: []string{"/"}, DailyBytes: 20}, nil)
	c, br, _, _ := wsClient(t, srv, "/api/_tunnel?host=example.com&port=443", testToken)
	sendFrame(c, opBinary, []byte("0123456789"))
	readFrame(t, br)
	c.Close()
	time.Sleep(100 * time.Millisecond)
	day, counts := h.DailyCounts(time.Now())
	if len(counts) != 1 || counts[0].Bytes != 20 {
		t.Fatalf("exported %v", counts)
	}
	h2, _, srv2 := tunnelHandler(t, policy.ProxyHTTPConnect, proxy.addr, policy.Access{Paths: []string{"/"}, DailyBytes: 20}, nil)
	h2.RestoreDailyCounts(day, counts, time.Now())
	if _, _, code, _ := wsClient(t, srv2, "/api/_tunnel?host=example.com&port=443", testToken); code != 429 {
		t.Fatalf("after restore: %d", code)
	}
}
