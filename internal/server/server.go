// Package server exposes a Resolver as a DNS server on UDP and TCP.
package server

import (
	"context"
	"log/slog"
	"time"

	"github.com/miekg/dns"

	"github.com/bitcoinbrisbane/hnsdns/internal/resolver"
)

// Handler answers client queries using a Resolver.
type Handler struct {
	Resolver resolver.Resolver
	Timeout  time.Duration // per query; default 5s
	Log      *slog.Logger  // optional
	Verbose  bool          // log every query
	Route    func(name string) resolver.Path
}

// maxUDP is the largest UDP response we send (DNS flag day 2020).
const maxUDP = 1232

// ServeDNS implements dns.Handler.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true

	switch {
	case req.Opcode != dns.OpcodeQuery:
		resp.Rcode = dns.RcodeNotImplemented
		h.write(w, req, resp)
		return
	case len(req.Question) != 1:
		resp.Rcode = dns.RcodeFormatError
		h.write(w, req, resp)
		return
	}
	q := req.Question[0]

	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	m, err := h.Resolver.Resolve(ctx, q)
	if err != nil {
		resp.Rcode = dns.RcodeServerFailure
		if h.Log != nil {
			h.Log.Warn("resolve failed", "name", q.Name, "type", dns.TypeToString[q.Qtype], "err", err)
		}
	} else {
		resp.Rcode = m.Rcode
		resp.Answer = m.Answer
		resp.Ns = m.Ns
	}
	if h.Verbose && h.Log != nil {
		attrs := []any{"name", q.Name, "type", dns.TypeToString[q.Qtype],
			"rcode", dns.RcodeToString[resp.Rcode], "answers", len(resp.Answer),
			"ms", time.Since(start).Milliseconds()}
		if h.Route != nil {
			attrs = append(attrs, "path", h.Route(q.Name))
		}
		h.Log.Info("query", attrs...)
	}
	h.write(w, req, resp)
}

func (h *Handler) write(w dns.ResponseWriter, req, resp *dns.Msg) {
	size := dns.MinMsgSize
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(maxUDP, false)
		size = int(min(max(opt.UDPSize(), dns.MinMsgSize), maxUDP))
	}
	if a := w.RemoteAddr(); a != nil && a.Network() == "udp" {
		resp.Truncate(size)
	} else {
		resp.Truncate(dns.MaxMsgSize)
	}
	if err := w.WriteMsg(resp); err != nil && h.Log != nil {
		h.Log.Debug("write failed", "err", err)
	}
}

// ListenAndServe serves h on addr over both UDP and TCP until ctx is done.
// ready, if non-nil, is closed once both listeners are up.
func ListenAndServe(ctx context.Context, addr string, h dns.Handler, ready chan<- struct{}) error {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: h, UDPSize: maxUDP}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	up := make(chan struct{}, 2)
	udp.NotifyStartedFunc = func() { up <- struct{}{} }
	tcp.NotifyStartedFunc = func() { up <- struct{}{} }

	errc := make(chan error, 2)
	go func() { errc <- udp.ListenAndServe() }()
	go func() { errc <- tcp.ListenAndServe() }()

	started := 0
	for started < 2 {
		select {
		case <-up:
			started++
		case err := <-errc:
			_ = udp.Shutdown()
			_ = tcp.Shutdown()
			return err
		}
	}
	if ready != nil {
		close(ready)
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return err
	}
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	return nil
}
