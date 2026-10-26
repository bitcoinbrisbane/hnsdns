package resolver

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testNet builds a small fake Handshake namespace:
//
//	root (127.0.0.1)  "."      — authoritative root, like hnsd
//	  hns.     -> ns1.hns.          glue 127.0.0.2 (in zone)
//	  far.     -> ns.provider.com.  glue 127.0.0.2 (out of zone: HNS GLUE4 style)
//	  glueless.-> ns.provider.com.  no glue (needs Lookup)
//	  info.    TXT answered by the root itself
//	  everything else NXDOMAIN
//	tld server (127.0.0.2) answers hns., far. and refers sub.hns. with
//	  out-of-bailiwick glue that must be ignored.
//	glueless server (127.0.0.3) answers glueless.
type testNet struct {
	root, tld, gl *authServer
	lookup        *staticResolver
	r             *Recursive
}

func newTestNet(t *testing.T) *testNet {
	n := &testNet{}
	soa := func(zone string) dns.RR { return rr(t, zone+" 300 IN SOA ns. host. 1 3600 600 86400 120") }

	n.root = startAuth(t, "127.0.0.1", "0", func(q dns.Question) *dns.Msg {
		switch {
		case dns.IsSubDomain("hns.", q.Name):
			return msg(0, nil, []dns.RR{rr(t, "hns. 3600 IN NS ns1.hns.")},
				[]dns.RR{rr(t, "ns1.hns. 3600 IN A 127.0.0.2")})
		case dns.IsSubDomain("far.", q.Name):
			return msg(0, nil, []dns.RR{rr(t, "far. 3600 IN NS ns.provider.com.")},
				[]dns.RR{rr(t, "ns.provider.com. 3600 IN A 127.0.0.2")})
		case dns.IsSubDomain("glueless.", q.Name):
			return msg(0, nil, []dns.RR{rr(t, "glueless. 3600 IN NS ns.provider.com.")}, nil)
		case dns.IsSubDomain("loop.", q.Name):
			// In-zone nameserver with no glue: unresolvable by design.
			return msg(0, nil, []dns.RR{rr(t, "loop. 3600 IN NS ns.loop.")}, nil)
		case q.Name == "info." && q.Qtype == dns.TypeTXT:
			return msg(0, []dns.RR{rr(t, `info. 300 IN TXT "on chain"`)}, nil, nil)
		}
		return msg(dns.RcodeNameError, nil, []dns.RR{soa(".")}, nil)
	})
	port := n.root.port()

	n.tld = startAuth(t, "127.0.0.2", port, func(q dns.Question) *dns.Msg {
		switch q.Name {
		case "www.hns.", "www.far.":
			if q.Qtype == dns.TypeA {
				return msg(0, []dns.RR{rr(t, q.Name+" 60 IN A 10.0.0.1")}, nil, nil)
			}
			return msg(0, nil, []dns.RR{soa("hns.")}, nil)
		case "alias.hns.":
			return msg(0, []dns.RR{rr(t, "alias.hns. 60 IN CNAME target.example.com.")}, nil, nil)
		case "chain.hns.":
			return msg(0, []dns.RR{
				rr(t, "chain.hns. 60 IN CNAME www.hns."),
				rr(t, "www.hns. 60 IN A 10.0.0.1"),
			}, nil, nil)
		}
		if dns.IsSubDomain("sub.hns.", q.Name) {
			// Glue for a name outside hns. — a poisoning attempt.
			return msg(0, nil, []dns.RR{rr(t, "sub.hns. 3600 IN NS ns.evil.com.")},
				[]dns.RR{rr(t, "ns.evil.com. 3600 IN A 127.0.0.66")})
		}
		return msg(dns.RcodeNameError, nil, []dns.RR{soa("hns.")}, nil)
	})

	n.gl = startAuth(t, "127.0.0.3", port, func(q dns.Question) *dns.Msg {
		if q.Name == "www.glueless." {
			return msg(0, []dns.RR{rr(t, "www.glueless. 60 IN A 10.0.0.3")}, nil, nil)
		}
		return msg(dns.RcodeNameError, nil, []dns.RR{soa("glueless.")}, nil)
	})

	n.lookup = &staticResolver{table: map[string][]dns.RR{
		"ns.provider.com. A":    {rr(t, "ns.provider.com. 300 IN A 127.0.0.3")},
		"target.example.com. A": {rr(t, "target.example.com. 300 IN A 93.184.216.34")},
		"ns.evil.com. A":        {rr(t, "ns.evil.com. 300 IN A 127.0.0.3")},
	}}
	n.r = &Recursive{
		Roots:   []string{n.root.addr},
		Lookup:  n.lookup,
		Port:    port,
		Timeout: time.Second,
	}
	return n
}

func resolve(t *testing.T, r Resolver, name string, qt uint16) *dns.Msg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := r.Resolve(ctx, question(name, qt))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return m
}

func TestRecursiveFollowsGlue(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "www.hns", dns.TypeA)
	if got := answerIPs(m); !reflect.DeepEqual(got, []string{"10.0.0.1"}) {
		t.Fatalf("answer = %v, want [10.0.0.1]", got)
	}
	if n.lookup.calls.Load() != 0 {
		t.Errorf("Lookup used %d times; glue should have been enough", n.lookup.calls.Load())
	}
}

func TestRecursiveAcceptsOutOfZoneGlueFromRoot(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "www.far", dns.TypeA)
	if got := answerIPs(m); !reflect.DeepEqual(got, []string{"10.0.0.1"}) {
		t.Fatalf("answer = %v (root glue for ns.provider.com should be used)", got)
	}
}

func TestRecursiveGluelessUsesLookup(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "www.glueless", dns.TypeA)
	if got := answerIPs(m); !reflect.DeepEqual(got, []string{"10.0.0.3"}) {
		t.Fatalf("answer = %v, want [10.0.0.3]", got)
	}
	if n.lookup.calls.Load() != 1 {
		t.Errorf("Lookup calls = %d, want 1", n.lookup.calls.Load())
	}
}

func TestRecursiveIgnoresOutOfBailiwickGlue(t *testing.T) {
	n := newTestNet(t)
	// sub.hns is delegated to ns.evil.com with glue 127.0.0.66 (nothing
	// listens there). The resolver must ignore that glue and look the host up
	// instead; the real address (127.0.0.3) says NXDOMAIN.
	m := resolve(t, n.r, "x.sub.hns", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
	}
	if n.lookup.calls.Load() != 1 {
		t.Errorf("Lookup calls = %d, want 1 (glue should have been rejected)", n.lookup.calls.Load())
	}
}

func TestRecursiveChasesCNAMEAcrossNamespaces(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "alias.hns", dns.TypeA)
	if len(m.Answer) != 2 {
		t.Fatalf("answer = %v, want CNAME + A", m.Answer)
	}
	if _, ok := m.Answer[0].(*dns.CNAME); !ok {
		t.Errorf("first record = %v, want CNAME", m.Answer[0])
	}
	if got := answerIPs(m); !reflect.DeepEqual(got, []string{"93.184.216.34"}) {
		t.Errorf("A = %v", got)
	}
}

func TestRecursiveCompleteCNAMEChainNeedsNoLookup(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "chain.hns", dns.TypeA)
	if len(m.Answer) != 2 || n.lookup.calls.Load() != 0 {
		t.Fatalf("answer = %v, lookups = %d", m.Answer, n.lookup.calls.Load())
	}
}

func TestRecursiveRootAnswersDirectly(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "info", dns.TypeTXT)
	if len(m.Answer) != 1 {
		t.Fatalf("answer = %v", m.Answer)
	}
	if n.tld.hits.Load() != 0 {
		t.Errorf("tld server queried for a root-level answer")
	}
}

func TestRecursiveNXDOMAINAndNODATA(t *testing.T) {
	n := newTestNet(t)
	m := resolve(t, n.r, "nope", dns.TypeA)
	if m.Rcode != dns.RcodeNameError || len(m.Ns) == 0 {
		t.Fatalf("nope.: rcode=%s ns=%v, want NXDOMAIN with SOA", dns.RcodeToString[m.Rcode], m.Ns)
	}
	m = resolve(t, n.r, "www.hns", dns.TypeAAAA)
	if m.Rcode != dns.RcodeSuccess || len(m.Answer) != 0 || len(m.Ns) == 0 {
		t.Fatalf("NODATA: rcode=%s answer=%v ns=%v", dns.RcodeToString[m.Rcode], m.Answer, m.Ns)
	}
}

func TestRecursiveLoopIsBounded(t *testing.T) {
	n := newTestNet(t)
	// loop. is served by ns.loop. with no glue: finding ns.loop needs ns.loop.
	n.r.Lookup = nil // nameserver lookups recurse into the same resolver
	n.r.MaxDepth = 4
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := n.r.Resolve(ctx, question("www.loop", dns.TypeA))
	if !errors.Is(err, ErrDepth) && !errors.Is(err, ErrNoServers) {
		t.Fatalf("err = %v, want depth/no-servers error", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %s; loop should fail fast", time.Since(start))
	}
}

func TestRecursiveUnreachableRoot(t *testing.T) {
	r := &Recursive{Roots: []string{"127.0.0.1:1"}, Timeout: 200 * time.Millisecond}
	_, err := r.Resolve(context.Background(), question("x.hns", dns.TypeA))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestChase(t *testing.T) {
	rrs := []dns.RR{
		rr(t, "a.x. 60 IN CNAME b.x."),
		rr(t, "b.x. 60 IN CNAME C.x."),
		rr(t, "c.x. 60 IN A 1.1.1.1"),
	}
	name, found := chase("a.x.", dns.TypeA, rrs)
	if name != "c.x." || !found {
		t.Fatalf("chase = %q %v", name, found)
	}
	name, found = chase("a.x.", dns.TypeA, rrs[:2])
	if name != "c.x." || found {
		t.Fatalf("dangling chase = %q %v", name, found)
	}
	loop := []dns.RR{rr(t, "a.x. 60 IN CNAME b.x."), rr(t, "b.x. 60 IN CNAME a.x.")}
	if _, found := chase("a.x.", dns.TypeA, loop); found {
		t.Fatal("loop reported found")
	}
}
