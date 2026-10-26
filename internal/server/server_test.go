package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/bitcoinbrisbane/hnsdns/internal/resolver"
	"github.com/bitcoinbrisbane/hnsdns/internal/tld"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// auth starts a fake authoritative server on ip:port ("0" = any port).
func auth(t *testing.T, ip, port string, answer func(q dns.Question) *dns.Msg) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, port))
	if err != nil {
		t.Skipf("bind %s: %v", ip, err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := answer(req.Question[0])
		rcode := m.Rcode
		m.SetReply(req)
		m.Rcode = rcode
		w.WriteMsg(m)
	})
	s := &dns.Server{PacketConn: pc, Handler: h}
	go s.ActivateAndServe()
	t.Cleanup(func() { s.Shutdown() })
	return pc.LocalAddr().String()
}

// start serves h on a free loopback port and returns its address.
func start(t *testing.T, h dns.Handler) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- ListenAndServe(ctx, addr, h, ready) }()
	select {
	case <-ready:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not start")
	}
	t.Cleanup(func() { cancel(); <-errc })
	return addr
}

func query(t *testing.T, addr, network, name string, qt uint16, edns bool) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qt)
	if edns {
		m.SetEdns0(1232, false)
	}
	c := &dns.Client{Net: network, Timeout: 3 * time.Second, UDPSize: 65535}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", network, name, err)
	}
	if r.Id != m.Id {
		t.Fatal("id mismatch")
	}
	return r
}

// TestEndToEnd wires the real stack — cache, router, plain-DNS ICANN
// upstream, and the Handshake recursive path — against fake servers, then
// queries it over UDP and TCP like a stub resolver would.
func TestEndToEnd(t *testing.T) {
	icann := auth(t, "127.0.0.1", "0", func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		if q.Name == "example.com." && q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{mustRR(t, "example.com. 300 IN A 93.184.216.34")}
			return m
		}
		m.Rcode = dns.RcodeNameError
		return m
	})
	root := auth(t, "127.0.0.1", "0", func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		if dns.IsSubDomain("nb.", q.Name) {
			m.Ns = []dns.RR{mustRR(t, "nb. 3600 IN NS ns1.nb.")}
			m.Extra = []dns.RR{mustRR(t, "ns1.nb. 3600 IN A 127.0.0.2")}
			return m
		}
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{mustRR(t, ". 86400 IN SOA . . 1 1 1 1 300")}
		return m
	})
	_, port, _ := net.SplitHostPort(root)
	auth(t, "127.0.0.2", port, func(q dns.Question) *dns.Msg {
		m := new(dns.Msg)
		switch q.Name {
		case "welcome.nb.":
			m.Answer = []dns.RR{mustRR(t, "welcome.nb. 60 IN A 10.10.10.10")}
		case "big.nb.":
			for i := 0; i < 15; i++ {
				m.Answer = append(m.Answer, mustRR(t, "big.nb. 60 IN TXT \"0123456789012345678901234567890123456789\""))
			}
		default:
			m.Rcode = dns.RcodeNameError
		}
		return m
	})

	router := &resolver.Router{
		TLDs:  tld.NewSet("com"),
		ICANN: &resolver.Forwarder{Servers: []string{icann}, Timeout: time.Second},
	}
	cache := &resolver.Cache{Next: router}
	router.HNS = &resolver.Recursive{Roots: []string{root}, Lookup: cache, Port: port, Timeout: time.Second}
	addr := start(t, &Handler{Resolver: cache})

	for _, network := range []string{"udp", "tcp"} {
		r := query(t, addr, network, "example.com", dns.TypeA, true)
		if len(r.Answer) != 1 || !r.RecursionAvailable || !r.RecursionDesired {
			t.Fatalf("%s example.com: %v", network, r)
		}
		r = query(t, addr, network, "welcome.nb", dns.TypeA, false)
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.10.10.10" {
			t.Fatalf("%s welcome.nb: %v", network, r)
		}
		r = query(t, addr, network, "nothere.nb", dns.TypeA, true)
		if r.Rcode != dns.RcodeNameError {
			t.Fatalf("%s nothere.nb rcode %s", network, dns.RcodeToString[r.Rcode])
		}
	}

	// 15 TXT records (~800 bytes) don't fit in 512 bytes: UDP without EDNS gets TC=1,
	// TCP gets everything.
	r := query(t, addr, "udp", "big.nb", dns.TypeTXT, false)
	if !r.Truncated {
		t.Errorf("large UDP reply not truncated (%d answers)", len(r.Answer))
	}
	r = query(t, addr, "tcp", "big.nb", dns.TypeTXT, false)
	if r.Truncated || len(r.Answer) != 15 {
		t.Errorf("tcp: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
	// EDNS replies carry an OPT record.
	r = query(t, addr, "udp", "welcome.nb", dns.TypeA, true)
	if r.IsEdns0() == nil {
		t.Error("EDNS query answered without OPT")
	}
}

func TestServfailOnError(t *testing.T) {
	h := &Handler{Resolver: resolver.Func(func(context.Context, dns.Question) (*dns.Msg, error) {
		return nil, errors.New("upstream down")
	})}
	addr := start(t, h)
	r := query(t, addr, "udp", "x.com", dns.TypeA, false)
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s", dns.RcodeToString[r.Rcode])
	}
}

func TestRejectsNonQuery(t *testing.T) {
	addr := start(t, &Handler{Resolver: resolver.Func(func(context.Context, dns.Question) (*dns.Msg, error) {
		t.Error("resolver called for NOTIFY")
		return nil, nil
	})})
	m := new(dns.Msg)
	m.SetNotify("example.com.")
	r, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("rcode = %s", dns.RcodeToString[r.Rcode])
	}
}
