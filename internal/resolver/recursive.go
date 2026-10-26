package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Recursive resolves names iteratively, starting at a root server — for
// Handshake, hnsd's authoritative root (127.0.0.1:5369 by default), which
// serves HNS names from the chain and ICANN TLDs from a built-in fallback.
//
// Nameserver host names without glue, and CNAME targets, are resolved through
// Lookup (normally the Router), so an HNS name delegated to ns1.example.com
// uses the ICANN path for the nameserver's address.
type Recursive struct {
	Roots   []string      // "ip:port" of the root server(s)
	Lookup  Resolver      // resolves NS hosts and CNAME targets; defaults to r itself
	Port    string        // port for delegated nameservers; default "53"
	IPv6    bool          // also try AAAA nameserver addresses
	Timeout time.Duration // per query attempt; default 2s

	MaxDepth     int // nested resolutions (CNAME / glueless NS); default 8
	MaxReferrals int // delegations followed per question; default 12
}

func (r *Recursive) port() string {
	if r.Port == "" {
		return "53"
	}
	return r.Port
}

func (r *Recursive) lookup() Resolver {
	if r.Lookup == nil {
		return r
	}
	return r.Lookup
}

// Resolve implements Resolver.
func (r *Recursive) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	maxDepth := r.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 8
	}
	d := depth(ctx)
	if d >= maxDepth {
		return nil, ErrDepth
	}
	ctx = withDepth(ctx, d+1)

	maxRef := r.MaxReferrals
	if maxRef <= 0 {
		maxRef = 12
	}

	q.Name = dns.CanonicalName(q.Name)
	zone := "."
	servers := r.Roots
	for i := 0; i <= maxRef; i++ {
		req := new(dns.Msg)
		req.Id = dns.Id()
		req.RecursionDesired = false
		req.Question = []dns.Question{q}
		req.SetEdns0(1232, false)

		resp, err := exchange(ctx, servers, req, r.Timeout)
		if err != nil {
			return nil, fmt.Errorf("query %s %s in zone %s: %w", q.Name, dns.TypeToString[q.Qtype], zone, err)
		}
		if resp.Rcode != dns.RcodeSuccess {
			return reply(q, resp), nil
		}
		if len(resp.Answer) > 0 {
			return r.answer(ctx, q, resp)
		}
		child, hosts := referral(resp, zone, q.Name)
		if child == "" {
			return reply(q, resp), nil // NODATA
		}
		servers = r.addrs(ctx, hosts, glue(resp, zone, hosts))
		if len(servers) == 0 {
			return nil, fmt.Errorf("delegation %s: %w", child, ErrNoServers)
		}
		zone = child
	}
	return nil, fmt.Errorf("%s: too many referrals", q.Name)
}

// answer returns resp, following a dangling CNAME chain via Lookup.
func (r *Recursive) answer(ctx context.Context, q dns.Question, resp *dns.Msg) (*dns.Msg, error) {
	out := reply(q, resp)
	if q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeANY {
		return out, nil
	}
	name, found := chase(q.Name, q.Qtype, resp.Answer)
	if found || name == q.Name {
		return out, nil
	}
	sub, err := r.lookup().Resolve(ctx, dns.Question{Name: name, Qtype: q.Qtype, Qclass: q.Qclass})
	if err != nil {
		return nil, fmt.Errorf("cname target %s: %w", name, err)
	}
	out.Answer = append(append([]dns.RR{}, out.Answer...), sub.Answer...)
	out.Ns = sub.Ns
	out.Rcode = sub.Rcode
	return out, nil
}

// chase follows CNAMEs from name through rrs. It returns the last name in
// the chain and whether a record of qtype exists for it.
func chase(name string, qtype uint16, rrs []dns.RR) (string, bool) {
	for hops := 0; hops < 16; hops++ {
		var next string
		for _, rr := range rrs {
			h := rr.Header()
			if !strings.EqualFold(h.Name, name) {
				continue
			}
			if h.Rrtype == qtype {
				return name, true
			}
			if c, ok := rr.(*dns.CNAME); ok {
				next = dns.CanonicalName(c.Target)
			}
		}
		if next == "" {
			return name, false
		}
		name = next
	}
	return name, false
}

// referral returns the delegated zone and its nameserver hosts if resp is a
// referral from zone toward qname, or "" if it is not.
func referral(resp *dns.Msg, zone, qname string) (string, []string) {
	var child string
	var hosts []string
	for _, rr := range resp.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := dns.CanonicalName(ns.Hdr.Name)
		// Must move strictly down the tree, toward qname.
		if owner == zone || !dns.IsSubDomain(zone, owner) || !dns.IsSubDomain(owner, qname) {
			continue
		}
		if child == "" {
			child = owner
		}
		if owner != child {
			continue
		}
		hosts = append(hosts, dns.CanonicalName(ns.Ns))
	}
	return child, hosts
}

// glue returns addresses from resp's additional section for the given hosts.
// Only in-bailiwick glue is trusted: the referring server must be
// authoritative for the glue name. A root server is authoritative for
// everything, which is how Handshake GLUE records for out-of-zone hosts work.
func glue(resp *dns.Msg, zone string, hosts []string) map[string][]net.IP {
	want := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		want[h] = true
	}
	out := make(map[string][]net.IP)
	for _, rr := range resp.Extra {
		name := dns.CanonicalName(rr.Header().Name)
		if !want[name] || !dns.IsSubDomain(zone, name) {
			continue
		}
		switch a := rr.(type) {
		case *dns.A:
			out[name] = append(out[name], a.A)
		case *dns.AAAA:
			out[name] = append(out[name], a.AAAA)
		}
	}
	return out
}

// addrs turns nameserver hosts into "ip:port" addresses: glue first, then up
// to three hosts resolved via Lookup until one yields an address.
func (r *Recursive) addrs(ctx context.Context, hosts []string, g map[string][]net.IP) []string {
	var v4, v6 []string
	add := func(ip net.IP) {
		hp := net.JoinHostPort(ip.String(), r.port())
		if ip.To4() != nil {
			v4 = append(v4, hp)
		} else if r.IPv6 {
			v6 = append(v6, hp)
		}
	}
	for _, h := range hosts {
		for _, ip := range g[h] {
			add(ip)
		}
	}
	if len(v4)+len(v6) > 0 {
		return append(v4, v6...)
	}
	tried := 0
	for _, h := range hosts {
		if tried == 3 || ctx.Err() != nil {
			break
		}
		tried++
		m, err := r.lookup().Resolve(ctx, dns.Question{Name: h, Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if err != nil || m.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				add(a.A)
			}
		}
		if len(v4) > 0 {
			break
		}
	}
	return append(v4, v6...)
}
