package resolver

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// authServer is a fake authoritative nameserver for tests.
type authServer struct {
	addr  string
	hits  atomic.Int32
	answr func(q dns.Question) *dns.Msg
}

// startAuth starts a UDP+TCP nameserver on ip:port ("0" picks a port).
func startAuth(t *testing.T, ip, port string, answer func(q dns.Question) *dns.Msg) *authServer {
	t.Helper()
	a := &authServer{answr: answer}
	pc, err := net.ListenPacket("udp", net.JoinHostPort(ip, port))
	if err != nil {
		t.Skipf("cannot bind %s:%s (need 127.0.0.0/8 on loopback): %v", ip, port, err)
	}
	a.addr = pc.LocalAddr().String()
	ln, err := net.Listen("tcp", a.addr)
	if err != nil {
		pc.Close()
		t.Skipf("cannot bind tcp %s: %v", a.addr, err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		a.hits.Add(1)
		m := a.answr(req.Question[0])
		if m == nil {
			m = new(dns.Msg)
			m.Rcode = dns.RcodeRefused
		}
		rcode := m.Rcode
		m.SetReply(req) // resets Rcode
		m.Rcode = rcode
		m.Authoritative = true
		if w.RemoteAddr().Network() == "udp" {
			size := dns.MinMsgSize
			if o := req.IsEdns0(); o != nil {
				size = int(o.UDPSize())
			}
			m.Truncate(size)
		}
		w.WriteMsg(m)
	})
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: ln, Handler: h}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return a
}

func (a *authServer) port() string { _, p, _ := net.SplitHostPort(a.addr); return p }

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("bad RR %q: %v", s, err)
	}
	return r
}

func msg(rcode int, answer, ns, extra []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Rcode = rcode
	m.Answer, m.Ns, m.Extra = answer, ns, extra
	return m
}

// staticResolver answers from a fixed table keyed by "name TYPE".
type staticResolver struct {
	table map[string][]dns.RR
	calls atomic.Int32
}

func (s *staticResolver) Resolve(_ context.Context, q dns.Question) (*dns.Msg, error) {
	s.calls.Add(1)
	key := strings.ToLower(q.Name) + " " + dns.TypeToString[q.Qtype]
	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	if rrs, ok := s.table[key]; ok {
		m.Answer = rrs
	} else {
		m.Rcode = dns.RcodeNameError
	}
	return m, nil
}

func question(name string, t uint16) dns.Question {
	return dns.Question{Name: dns.Fqdn(name), Qtype: t, Qclass: dns.ClassINET}
}

func answerIPs(m *dns.Msg) []string {
	var out []string
	for _, r := range m.Answer {
		if a, ok := r.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}
