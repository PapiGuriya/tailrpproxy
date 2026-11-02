package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/eseiker/tailrpproxy/internal/rpproxy"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

const diagnosticBudget = 65 * time.Second

type diagnosticClient interface {
	Status(context.Context) (*ipnstate.Status, error)
	Ping(context.Context, netip.Addr, tailcfg.PingType) (*ipnstate.PingResult, error)
}

type diagnosticDial func(context.Context, string, string) (net.Conn, error)

type diagnosticRequest struct {
	peer    netip.Addr
	port    uint16
	count   int
	timeout time.Duration
}

// Only a port is configurable: callers cannot widen the listening address.
func parseDiagnosticsPort(value string) (uint16, error) {
	if value == "" || value == "0" {
		return 0, nil
	}
	n, err := diagnosticNumber(value, 1, 65535)
	if err != nil {
		return 0, errors.New("diagnostics port must be 0 (disabled) or an integer from 1 through 65535")
	}
	return uint16(n), nil
}

func diagnosticNumber(value string, min, max int) (int, error) {
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid integer")
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return 0, errors.New("integer out of range")
	}
	return n, nil
}

func parseDiagnosticRequest(rawQuery string) (diagnosticRequest, error) {
	r := diagnosticRequest{count: 3, timeout: 2 * time.Second}
	if len(rawQuery) > 512 {
		return r, errors.New("query too long")
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return r, errors.New("invalid query")
	}
	for name, values := range q {
		if len(values) != 1 || !slices.Contains([]string{"peer", "port", "count", "timeout"}, name) {
			return r, errors.New("unknown or repeated parameter")
		}
	}
	r.peer, err = netip.ParseAddr(q.Get("peer"))
	if err != nil || r.peer.Zone() != "" || r.peer.Is4In6() || !rpproxy.IsTailnetAddress(r.peer) {
		return r, errors.New("peer must be a literal Tailscale IPv4 or IPv6 address without a zone")
	}
	if q.Has("port") {
		n, err := diagnosticNumber(q.Get("port"), 1, 65535)
		if err != nil {
			return r, errors.New("port must be an integer from 1 through 65535")
		}
		r.port = uint16(n)
	}
	if q.Has("count") {
		r.count, err = diagnosticNumber(q.Get("count"), 1, 5)
		if err != nil {
			return r, errors.New("count must be an integer from 1 through 5")
		}
	}
	if q.Has("timeout") {
		r.timeout, err = time.ParseDuration(q.Get("timeout"))
		if err != nil || r.timeout < 100*time.Millisecond || r.timeout > 5*time.Second {
			return r, errors.New("timeout must be between 100ms and 5s")
		}
	}
	return r, nil
}

type diagnosticPeer struct {
	IP            netip.Addr `json:"ip"`
	Online        bool       `json:"online"`
	Active        bool       `json:"active"`
	Expired       bool       `json:"expired"`
	LastSeen      *time.Time `json:"last_seen,omitempty"`
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
	DirectAddress string     `json:"direct_address,omitempty"`
	DERPRegion    string     `json:"derp_region,omitempty"`
	PeerRelay     string     `json:"peer_relay,omitempty"`
}

type diagnosticSample struct {
	Success    bool     `json:"success"`
	RTTMS      *float64 `json:"rtt_ms,omitempty"`
	Connection string   `json:"connection"`
	Endpoint   string   `json:"endpoint,omitempty"`
	DERPRegion string   `json:"derp_region,omitempty"`
	PeerRelay  string   `json:"peer_relay,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type diagnosticPings struct {
	Samples   []diagnosticSample `json:"samples"`
	Succeeded int                `json:"succeeded"`
	Failed    int                `json:"failed"`
	MinMS     *float64           `json:"min_ms,omitempty"`
	AverageMS *float64           `json:"average_ms,omitempty"`
	MaxMS     *float64           `json:"max_ms,omitempty"`
}

type diagnosticTCP struct {
	Port      uint16  `json:"port"`
	Success   bool    `json:"success"`
	ElapsedMS float64 `json:"elapsed_ms"`
	Error     string  `json:"error,omitempty"`
}

type diagnosticResponse struct {
	Peer  diagnosticPeer  `json:"peer"`
	Disco diagnosticPings `json:"disco"`
	TSMP  diagnosticPings `json:"tsmp"`
	TCP   *diagnosticTCP  `json:"tcp,omitempty"`
	Error string          `json:"error,omitempty"`
}

var errDiagnosticPeer = errors.New("peer is not in the embedded node's current network map")

func lookupDiagnosticPeer(ctx context.Context, client diagnosticClient, ip netip.Addr, timeout time.Duration) (*ipnstate.PeerStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		return nil, err
	}
	if status == nil || status.BackendState != "Running" {
		return nil, errors.New("status unavailable")
	}
	if slices.Contains(status.TailscaleIPs, ip) || (status.Self != nil && slices.Contains(status.Self.TailscaleIPs, ip)) {
		return nil, errDiagnosticPeer
	}
	for _, peer := range status.Peer {
		if peer != nil && peer.InNetworkMap && slices.Contains(peer.TailscaleIPs, ip) {
			return peer, nil
		}
	}
	return nil, errDiagnosticPeer
}

// Never return arbitrary LocalAPI/dial error strings: they can contain URLs,
// response bodies, or credentials. Keep known causes useful and bounded.
func diagnosticError(err error, fallback string) string {
	var netError net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netError) && netError.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "peer unreachable"
	case errors.Is(err, errDiagnosticPeer):
		return errDiagnosticPeer.Error()
	default:
		// gVisor's gonet wraps these literal strings in net.OpError rather
		// than syscall.Errno. Match exact known causes, never echo its text.
		var opError *net.OpError
		if errors.As(err, &opError) && opError.Err != nil {
			switch opError.Err.Error() {
			case "connection was refused":
				return "connection refused"
			case "network is unreachable", "no route to host":
				return "peer unreachable"
			case "operation timed out":
				return "timeout"
			}
		}
		return fallback
	}
}

func runDiagnosticPings(ctx context.Context, client diagnosticClient, r diagnosticRequest, kind tailcfg.PingType) diagnosticPings {
	report := diagnosticPings{Samples: make([]diagnosticSample, 0, r.count)}
	var total, minimum, maximum float64
	for i := 0; i < r.count && ctx.Err() == nil; i++ {
		probeCtx, cancel := context.WithTimeout(ctx, r.timeout)
		result, err := client.Ping(probeCtx, r.peer, kind)
		if probeCtx.Err() != nil {
			err = probeCtx.Err()
		}
		cancel()
		sample := diagnosticSample{Connection: "unknown"}
		switch {
		case err != nil:
			sample.Error = diagnosticError(err, "ping request failed")
		case result == nil:
			sample.Error = "empty ping result"
		case result.Err != "":
			// Only known literal errors are safe to expose.
			sample.Error = "ping failed"
			switch result.Err {
			case "no matching peer", "unknown peer", "local tailscaled stopped", "peer's node key has expired", "ping timeout":
				sample.Error = result.Err
			}
		case result.LatencySeconds < 0 || math.IsNaN(result.LatencySeconds) || math.IsInf(result.LatencySeconds, 0) || result.LatencySeconds > r.timeout.Seconds():
			sample.Error = "invalid ping latency"
		default:
			sample.Success = true
			rtt := result.LatencySeconds * 1000
			sample.RTTMS = &rtt
			if kind == tailcfg.PingDisco {
				switch {
				case result.PeerRelay != "":
					sample.Connection, sample.PeerRelay = "peer-relay", result.PeerRelay
				case result.Endpoint != "":
					sample.Connection, sample.Endpoint = "direct", result.Endpoint
				case result.DERPRegionID != 0:
					sample.Connection, sample.DERPRegion = "derp", result.DERPRegionCode
				}
			}
			if report.Succeeded == 0 || rtt < minimum {
				minimum = rtt
			}
			maximum = max(maximum, rtt)
			total += rtt
			report.Succeeded++
		}
		if !sample.Success {
			report.Failed++
		}
		report.Samples = append(report.Samples, sample)
	}
	if report.Succeeded > 0 {
		average := total / float64(report.Succeeded)
		report.MinMS, report.AverageMS, report.MaxMS = &minimum, &average, &maximum
	}
	return report
}

func newDiagnosticHandler(client diagnosticClient, dial diagnosticDial) http.Handler {
	// Independent of the reflector's connection limits; do not queue probes.
	busy := make(chan struct{}, 1)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fail := func(code int, message string) { diagnosticJSON(w, code, map[string]string{"error": message}) }
		if req.URL.Path != "/diagnostics/peer" {
			fail(http.StatusNotFound, "not found")
			return
		}
		// POST and literal loopback Host prevent browser-triggered probes and DNS rebinding.
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil || host != "127.0.0.1" || req.Header.Get("Origin") != "" {
			fail(http.StatusForbidden, "loopback requests without Origin required")
			return
		}
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			fail(http.StatusMethodNotAllowed, "POST required")
			return
		}
		if req.ContentLength != 0 || len(req.TransferEncoding) != 0 {
			fail(http.StatusBadRequest, "request body must be empty")
			return
		}
		r, err := parseDiagnosticRequest(req.URL.RawQuery)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		select {
		case busy <- struct{}{}:
			defer func() { <-busy }()
		default:
			fail(http.StatusTooManyRequests, "diagnostics busy; retry after the current request")
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), diagnosticBudget)
		defer cancel()
		peer, err := lookupDiagnosticPeer(ctx, client, r.peer, r.timeout)
		if err != nil {
			code := http.StatusServiceUnavailable
			if errors.Is(err, errDiagnosticPeer) {
				code = http.StatusNotFound
			}
			fail(code, diagnosticError(err, "embedded node status unavailable"))
			return
		}
		report := diagnosticResponse{Peer: diagnosticPeer{
			IP: r.peer, Online: peer.Online, Active: peer.Active, Expired: peer.Expired,
			DirectAddress: peer.CurAddr, DERPRegion: peer.Relay, PeerRelay: peer.PeerRelay,
		}}
		if !peer.LastSeen.IsZero() {
			report.Peer.LastSeen = &peer.LastSeen
		}
		if !peer.LastHandshake.IsZero() {
			report.Peer.LastHandshake = &peer.LastHandshake
		}
		report.Disco = runDiagnosticPings(ctx, client, r, tailcfg.PingDisco)
		report.TSMP = runDiagnosticPings(ctx, client, r, tailcfg.PingTSMP)
		if r.port != 0 && ctx.Err() == nil {
			report.TCP = &diagnosticTCP{Port: r.port}
			start := time.Now()
			// Revalidate membership before dialing, after potentially slow pings.
			_, err := lookupDiagnosticPeer(ctx, client, r.peer, r.timeout)
			if err == nil {
				probeCtx, cancel := context.WithTimeout(ctx, r.timeout)
				var conn net.Conn
				conn, err = dial(probeCtx, "tcp", net.JoinHostPort(r.peer.String(), strconv.Itoa(int(r.port))))
				if conn != nil {
					_ = conn.Close() // No application reads or writes.
				} else if err == nil {
					err = errors.New("empty connection")
				}
				if probeCtx.Err() != nil {
					err = probeCtx.Err()
				}
				cancel()
			}
			report.TCP.ElapsedMS = time.Since(start).Seconds() * 1000
			report.TCP.Success = err == nil
			if err != nil {
				report.TCP.Error = diagnosticError(err, "TCP connection failed")
			}
		}
		if ctx.Err() != nil {
			report.Error = diagnosticError(ctx.Err(), "diagnostics interrupted")
		}
		diagnosticJSON(w, http.StatusOK, report)
	})
}

func diagnosticJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func startDiagnosticServer(ctx context.Context, port uint16, client diagnosticClient, dial diagnosticDial) (*http.Server, error) {
	if port == 0 {
		return nil, nil
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("diagnostics listen: %w", err)
	}
	server := &http.Server{
		Addr: address, Handler: newDiagnosticHandler(client, dial),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: diagnosticBudget + 2*time.Second, IdleTimeout: 5 * time.Second,
		MaxHeaderBytes: 4096,
		BaseContext:    func(net.Listener) context.Context { return ctx },
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Print("diagnostics HTTP server stopped")
		}
	}()
	return server, nil
}
