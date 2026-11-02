package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/eseiker/tailrpproxy/internal/rpproxy"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const testPeer = "100.64.0.2"

type fakeDiagnosticClient struct {
	status func(context.Context) (*ipnstate.Status, error)
	ping   func(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error)
}

func (f fakeDiagnosticClient) Status(ctx context.Context) (*ipnstate.Status, error) {
	if f.status != nil {
		return f.status(ctx)
	}
	return &ipnstate.Status{BackendState: "Running", Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		{}: {TailscaleIPs: []netip.Addr{netip.MustParseAddr(testPeer), netip.MustParseAddr("fd7a:115c:a1e0::2")}, InNetworkMap: true, Online: true},
	}}, nil
}

func (f fakeDiagnosticClient) Ping(ctx context.Context, ip netip.Addr, kind tailcfg.PingType) (*ipnstate.PingResult, error) {
	if f.ping != nil {
		return f.ping(ctx, ip, kind)
	}
	return &ipnstate.PingResult{LatencySeconds: .25, Endpoint: "192.0.2.1:1234"}, nil
}

func diagnosticHTTP(handler http.Handler, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9091/diagnostics/peer?"+query, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func decodeDiagnostic(t *testing.T, w *httptest.ResponseRecorder) diagnosticResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var result diagnosticResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDiagnosticRequestValidation(t *testing.T) {
	for _, query := range []string{
		"", "peer=localhost", "peer=127.0.0.1", "peer=10.7.0.1", "peer=192.0.2.1",
		"peer=100.64.0.2:80", "peer=100.64.0.2/32", "peer=::ffff:100.64.0.2", "peer=fd7a:115c:a1e0::2%25eth0",
		"peer=%zz", "peer=100.64.0.2&peer=100.64.0.3", "peer=100.64.0.2&url=http://example.com", strings.Repeat("a", 513),
	} {
		if _, err := parseDiagnosticRequest(query); err == nil {
			t.Errorf("accepted %q", query)
		}
	}
	for name, values := range map[string][]string{
		"port":    {"", "0", "-1", "65536", "+80", "80.0", "http", "999999999999999999999"},
		"count":   {"", "0", "-1", "6", "1.5"},
		"timeout": {"", "0", "99ms", "6s", "NaN", "-1s"},
	} {
		for _, value := range values {
			if _, err := parseDiagnosticRequest("peer=" + testPeer + "&" + name + "=" + value); err == nil {
				t.Errorf("accepted %s=%q", name, value)
			}
		}
	}
	for _, query := range []string{"peer=" + testPeer, "peer=" + testPeer + "&port=1&count=1&timeout=100ms", "peer=fd7a:115c:a1e0::2&port=65535&count=5&timeout=5s"} {
		if _, err := parseDiagnosticRequest(query); err != nil {
			t.Errorf("rejected %q: %v", query, err)
		}
	}
}

func TestDiagnosticsDisabledByDefaultAndPortOnly(t *testing.T) {
	originalFlags, originalArgs := flag.CommandLine, os.Args
	t.Cleanup(func() { flag.CommandLine, os.Args = originalFlags, originalArgs })
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	os.Args = []string{"tailrpproxy"}
	for _, name := range []string{"RPPROXY_DIAGNOSTICS_PORT", "RPPROXY_TSNET_PORT", "RPPROXY_VERBOSE"} {
		t.Setenv(name, "")
	}
	configuration, err := parseFlags()
	if err != nil || configuration.diagnosticsPort != 0 {
		t.Fatalf("defaults: %+v, %v", configuration, err)
	}
	server, err := startDiagnosticServer(context.Background(), 0, nil, nil)
	if err != nil || server != nil {
		t.Fatalf("disabled server = %v, %v", server, err)
	}
	for _, value := range []string{"0.0.0.0:9091", ":9091", "localhost:9091", "-1", "65536", "+9091", "9091 "} {
		if _, err := parseDiagnosticsPort(value); err == nil {
			t.Errorf("accepted listen configuration %q", value)
		}
	}
	for _, value := range []string{"", "0", "1", "9091", "65535"} {
		if _, err := parseDiagnosticsPort(value); err != nil {
			t.Errorf("rejected port %q: %v", value, err)
		}
	}
	// The flag can override an enabled environment setting back to disabled.
	t.Setenv("RPPROXY_DIAGNOSTICS_PORT", "9091")
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	os.Args = []string{"tailrpproxy", "-diagnostics-port=0"}
	configuration, err = parseFlags()
	if err != nil || configuration.diagnosticsPort != 0 {
		t.Fatalf("disable override: %+v, %v", configuration, err)
	}
}

func TestDiagnosticRequiresCurrentPeer(t *testing.T) {
	for _, scenario := range []string{"unknown", "stale", "nil peer", "self", "stopped", "nil status", "error", "subnet"} {
		t.Run(scenario, func(t *testing.T) {
			client := fakeDiagnosticClient{status: func(ctx context.Context) (*ipnstate.Status, error) {
				st, _ := (fakeDiagnosticClient{}).Status(ctx)
				p := st.Peer[key.NodePublic{}]
				switch scenario {
				case "unknown":
					p.TailscaleIPs = nil
				case "stale":
					p.InNetworkMap = false
				case "nil peer":
					st.Peer[key.NodePublic{}] = nil
				case "self":
					st.Self = p
				case "stopped":
					st.BackendState = "Stopped"
				case "nil status":
					return nil, nil
				case "error":
					return nil, errors.New("https://secret:credential@example.com")
				case "subnet":
					p.TailscaleIPs = []netip.Addr{netip.MustParseAddr("100.64.0.3")}
				}
				return st, nil
			}, ping: func(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error) {
				t.Fatal("ping before peer validation")
				return nil, nil
			}}
			dial := func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("dial before peer validation")
				return nil, nil
			}
			w := diagnosticHTTP(newDiagnosticHandler(client, dial), "peer="+testPeer+"&port=1234")
			if w.Code != http.StatusNotFound && w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status %d", w.Code)
			}
			if strings.Contains(w.Body.String(), "credential") {
				t.Fatal("leaked status error")
			}
		})
	}
}

func TestDiagnosticPingResults(t *testing.T) {
	index := 0
	client := fakeDiagnosticClient{ping: func(_ context.Context, ip netip.Addr, kind tailcfg.PingType) (*ipnstate.PingResult, error) {
		if ip.String() != testPeer {
			t.Fatalf("target %s", ip)
		}
		index++
		switch index {
		case 1:
			return &ipnstate.PingResult{LatencySeconds: .2, DERPRegionID: 1, DERPRegionCode: "dbi"}, nil
		case 2:
			return &ipnstate.PingResult{LatencySeconds: .3, Endpoint: "192.0.2.1:1234"}, nil
		case 3:
			return &ipnstate.PingResult{LatencySeconds: .4, PeerRelay: "192.0.2.2:1234:vni:1"}, nil
		case 4:
			return nil, context.DeadlineExceeded
		case 5:
			return &ipnstate.PingResult{Err: "secret-credential"}, nil
		default:
			if kind != tailcfg.PingTSMP {
				t.Fatal("expected TSMP")
			}
			return &ipnstate.PingResult{LatencySeconds: .5, Endpoint: "ignored-for-tsmp"}, nil
		}
	}}
	w := diagnosticHTTP(newDiagnosticHandler(client, nil), "peer="+testPeer)
	r := decodeDiagnostic(t, w)
	if r.Disco.Succeeded != 3 || r.Disco.Failed != 0 || *r.Disco.MinMS != 200 || *r.Disco.AverageMS != 300 || *r.Disco.MaxMS != 400 {
		t.Fatalf("DISCO: %+v", r.Disco)
	}
	for i, path := range []string{"derp", "direct", "peer-relay"} {
		if r.Disco.Samples[i].Connection != path {
			t.Fatalf("path %d: %+v", i, r.Disco.Samples[i])
		}
	}
	if r.TSMP.Succeeded != 1 || r.TSMP.Failed != 2 || *r.TSMP.AverageMS != 500 || r.TSMP.Samples[2].Connection != "unknown" || r.TCP != nil {
		t.Fatalf("TSMP: %+v", r.TSMP)
	}
	if strings.Contains(w.Body.String(), "credential") {
		t.Fatal("leaked ping error")
	}
}

func TestDiagnosticInvalidPingResults(t *testing.T) {
	for _, result := range []*ipnstate.PingResult{nil, {Err: "no matching peer"}, {LatencySeconds: -1}, {LatencySeconds: math.NaN()}, {LatencySeconds: math.Inf(1)}, {LatencySeconds: 10}} {
		client := fakeDiagnosticClient{ping: func(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error) { return result, nil }}
		r := decodeDiagnostic(t, diagnosticHTTP(newDiagnosticHandler(client, nil), "peer="+testPeer+"&count=1"))
		if r.Disco.Failed != 1 || r.TSMP.Failed != 1 || r.Disco.AverageMS != nil || r.Disco.Samples[0].RTTMS != nil {
			t.Fatalf("invalid result: %+v", r)
		}
	}
}

func TestDiagnosticTCP(t *testing.T) {
	for _, peer := range []string{testPeer, "fd7a:115c:a1e0::2"} {
		t.Run(peer, func(t *testing.T) {
			proxy, device := net.Pipe()
			defer device.Close()
			dial := func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != net.JoinHostPort(peer, "1234") {
					t.Fatalf("dial %s %s", network, address)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("unbounded dial")
				}
				return proxy, nil
			}
			r := decodeDiagnostic(t, diagnosticHTTP(newDiagnosticHandler(fakeDiagnosticClient{}, dial), "peer="+peer+"&port=1234&count=1"))
			if r.TCP == nil || !r.TCP.Success || r.TCP.ElapsedMS < 0 {
				t.Fatalf("TCP: %+v", r.TCP)
			}
			_ = device.SetReadDeadline(time.Now().Add(time.Second))
			if n, err := device.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("expected close without payload: %d, %v", n, err)
			}
		})
	}
	for _, test := range []struct {
		err  error
		want string
	}{
		{syscall.ECONNREFUSED, "connection refused"}, {syscall.EHOSTUNREACH, "peer unreachable"},
		{&net.OpError{Err: errors.New("connection was refused")}, "connection refused"},
		{&net.OpError{Err: errors.New("network is unreachable")}, "peer unreachable"},
		{&net.OpError{Err: errors.New("no route to host")}, "peer unreachable"},
		{&net.OpError{Err: errors.New("operation timed out")}, "timeout"},
		{&net.OpError{Err: errors.New("connection was refused secret-credential")}, "TCP connection failed"},
		{context.DeadlineExceeded, "timeout"}, {errors.New("https://secret:credential@example.com"), "TCP connection failed"}, {nil, "TCP connection failed"},
	} {
		dial := func(context.Context, string, string) (net.Conn, error) { return nil, test.err }
		r := decodeDiagnostic(t, diagnosticHTTP(newDiagnosticHandler(fakeDiagnosticClient{}, dial), "peer="+testPeer+"&port=1234&count=1"))
		if r.TCP.Success || r.TCP.Error != test.want {
			t.Fatalf("TCP: %+v", r.TCP)
		}
	}
}

func TestDiagnosticTCPRevalidatesPeer(t *testing.T) {
	calls := 0
	client := fakeDiagnosticClient{status: func(ctx context.Context) (*ipnstate.Status, error) {
		st, _ := (fakeDiagnosticClient{}).Status(ctx)
		calls++
		if calls > 1 {
			st.Peer = nil
		}
		return st, nil
	}}
	dial := func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed removed peer")
		return nil, nil
	}
	r := decodeDiagnostic(t, diagnosticHTTP(newDiagnosticHandler(client, dial), "peer="+testPeer+"&port=1234&count=1"))
	if r.TCP.Success || r.TCP.Error != errDiagnosticPeer.Error() {
		t.Fatalf("TCP: %+v", r.TCP)
	}
}

func TestDiagnosticTimeoutsAndCancellation(t *testing.T) {
	for _, stage := range []string{"status", "ping", "tcp"} {
		t.Run(stage, func(t *testing.T) {
			client := fakeDiagnosticClient{}
			dial := diagnosticDial(func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED })
			switch stage {
			case "status":
				client.status = func(ctx context.Context) (*ipnstate.Status, error) { <-ctx.Done(); return nil, ctx.Err() }
			case "ping":
				client.ping = func(ctx context.Context, _ netip.Addr, _ tailcfg.PingType) (*ipnstate.PingResult, error) {
					<-ctx.Done()
					return nil, ctx.Err()
				}
			case "tcp":
				dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
			}
			start := time.Now()
			w := diagnosticHTTP(newDiagnosticHandler(client, dial), "peer="+testPeer+"&count=1&timeout=100ms&port=1234")
			if time.Since(start) > time.Second || !strings.Contains(w.Body.String(), "timeout") {
				t.Fatalf("timeout: %s", w.Body.String())
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var calls atomic.Int32
	client := fakeDiagnosticClient{ping: func(ctx context.Context, _ netip.Addr, _ tailcfg.PingType) (*ipnstate.PingResult, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	h := newDiagnosticHandler(client, func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial after cancellation")
		return nil, nil
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9091/diagnostics/peer?peer="+testPeer+"&port=1234", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(w, req) }()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("did not cancel")
	}
	r := decodeDiagnostic(t, w)
	if calls.Load() != 1 || r.Error != "canceled" || len(r.TSMP.Samples) != 0 || r.TCP != nil {
		t.Fatalf("cancellation: %+v", r)
	}
}

func TestDiagnosticHTTPGuards(t *testing.T) {
	h := newDiagnosticHandler(fakeDiagnosticClient{}, nil)
	for _, test := range []struct {
		method, host, path, origin, body string
		code                             int
	}{
		{"GET", "127.0.0.1:9091", "/diagnostics/peer", "", "", 405},
		{"POST", "evil.example:9091", "/diagnostics/peer", "", "", 403},
		{"POST", "127.0.0.1:9091", "/diagnostics/peer", "https://example.com", "", 403},
		{"POST", "127.0.0.1:9091", "/metrics", "", "", 404},
		{"POST", "127.0.0.1:9091", "/diagnostics/peer", "", "body", 400},
	} {
		req := httptest.NewRequest(test.method, "http://"+test.host+test.path+"?peer="+testPeer, strings.NewReader(test.body))
		req.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != test.code || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("HTTP guard: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestDiagnosticLoopbackListener(t *testing.T) {
	// Reserve a free port, then check the actual startup listener, including bind failures.
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(reservation.Addr().(*net.TCPAddr).Port)
	if _, err := startDiagnosticServer(context.Background(), port, fakeDiagnosticClient{}, nil); err == nil {
		t.Fatal("accepted occupied port")
	}
	_ = reservation.Close()
	server, err := startDiagnosticServer(context.Background(), port, fakeDiagnosticClient{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if !strings.HasPrefix(server.Addr, "127.0.0.1:") {
		t.Fatalf("address %s", server.Addr)
	}
	client := &http.Client{Timeout: time.Second}
	res, err := client.Post("http://"+server.Addr+"/diagnostics/peer?peer="+testPeer+"&count=1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("status %d", res.StatusCode)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ipnet, ok := address.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil || ipnet.IP.IsLoopback() {
			continue
		}
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort(ipnet.IP.String(), strings.Split(server.Addr, ":")[1]), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatal("diagnostics reachable on non-loopback interface")
		}
	}
}

func TestDiagnosticsDoNotBlockReflectorOrHealth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	client := fakeDiagnosticClient{ping: func(ctx context.Context, _ netip.Addr, _ tailcfg.PingType) (*ipnstate.PingResult, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		proxy, device := net.Pipe()
		go func() {
			defer device.Close()
			payload := make([]byte, 5)
			if _, err := io.ReadFull(device, payload); err == nil {
				_, _ = device.Write(payload)
			}
		}()
		return proxy, nil
	}
	h := newDiagnosticHandler(client, dial)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9091/diagnostics/peer?peer="+testPeer, nil).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), req) }()
	<-started
	if w := diagnosticHTTP(h, "peer="+testPeer); w.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent request: %d", w.Code)
	}
	reflector, err := rpproxy.NewTCPReflector(dial, netip.MustParsePrefix("10.7.0.1/32"), true, rpproxy.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, intercept := reflector.HandleTCPFlow(netip.MustParseAddrPort(testPeer+":12345"), netip.MustParseAddrPort("10.7.0.1:1234"))
	if !intercept || handler == nil {
		t.Fatal("reflection rejected")
	}
	proxy, phone := net.Pipe()
	go handler(proxy)
	_ = phone.SetDeadline(time.Now().Add(time.Second))
	if _, err := phone.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(phone, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("reflection %q: %v", buf, err)
	}
	phone.Close()
	reflector.Metrics().SetReady(true)
	health, err := startHealthServer("127.0.0.1:0", reflector.Metrics())
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownHealthServer(health)
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		w := httptest.NewRecorder()
		health.Handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("diagnostic did not stop")
	}
	drain, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := reflector.Shutdown(drain); err != nil {
		t.Fatal(err)
	}
	if reflector.Metrics().Snapshot().Total != 1 {
		t.Fatal("diagnostics affected reflector metrics")
	}
}
