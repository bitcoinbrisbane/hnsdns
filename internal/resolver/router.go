package resolver

import (
	"context"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"

	"github.com/bitcoinbrisbane/hnsdns/internal/tld"
)

// Zone sends every name at or below Suffix to a specific resolver, e.g. a
// home router for "lan." or "home.arpa.".
type Zone struct {
	Suffix   string
	Resolver Resolver
}

// Path names which resolver handled a question.
type Path string

const (
	PathICANN Path = "icann"
	PathHNS   Path = "hns"
	PathZone  Path = "zone"
	PathLocal Path = "local"
)

// Router picks a resolver per question: local zones first, then ICANN when
// the TLD is in the IANA list, otherwise Handshake.
type Router struct {
	TLDs  *tld.Set
	ICANN Resolver
	HNS   Resolver
	Zones []Zone
}

// SortZones orders zones longest-suffix first so the most specific wins.
func (rt *Router) SortZones() {
	for i := range rt.Zones {
		rt.Zones[i].Suffix = dns.CanonicalName(rt.Zones[i].Suffix)
	}
	sort.SliceStable(rt.Zones, func(i, j int) bool {
		return dns.CountLabel(rt.Zones[i].Suffix) > dns.CountLabel(rt.Zones[j].Suffix)
	})
}

// Route reports which path a name takes, and the resolver for it (nil for
// names answered locally).
func (rt *Router) Route(name string) (Path, Resolver) {
	name = dns.CanonicalName(name)
	for _, z := range rt.Zones {
		if dns.IsSubDomain(z.Suffix, name) {
			return PathZone, z.Resolver
		}
	}
	top := topLabel(name)
	switch top {
	case "localhost", "invalid", "local", "onion":
		return PathLocal, nil
	case "":
		return PathHNS, rt.HNS // the root itself
	}
	if rt.TLDs != nil && rt.TLDs.Contains(top) {
		return PathICANN, rt.ICANN
	}
	return PathHNS, rt.HNS
}

// Resolve implements Resolver.
func (rt *Router) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	path, r := rt.Route(q.Name)
	if path == PathLocal {
		return special(q), nil
	}
	return r.Resolve(ctx, q)
}

// special answers RFC 6761 / 6762 / 7686 names without leaking them upstream.
func special(q dns.Question) *dns.Msg {
	name := dns.CanonicalName(q.Name)
	if topLabel(name) != "localhost" {
		return rcodeMsg(q, dns.RcodeNameError)
	}
	m := rcodeMsg(q, dns.RcodeSuccess)
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 3600}
	switch q.Qtype {
	case dns.TypeA:
		hdr.Rrtype = dns.TypeA
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)}}
	case dns.TypeAAAA:
		hdr.Rrtype = dns.TypeAAAA
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6loopback}}
	}
	return m
}

// topLabel returns the rightmost label of a name, lowercased ("" for root).
func topLabel(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}
