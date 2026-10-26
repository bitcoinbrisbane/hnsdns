package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"

	"github.com/bitcoinbrisbane/hnsdns/internal/tld"
)

func tagged(tag string) Resolver {
	return Func(func(_ context.Context, q dns.Question) (*dns.Msg, error) {
		m := rcodeMsg(q, 0)
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: 1, Ttl: 60}, Txt: []string{tag}}}
		return m, nil
	})
}

func handledBy(t *testing.T, r Resolver, name string) string {
	t.Helper()
	m := resolve(t, r, name, dns.TypeTXT)
	if len(m.Answer) == 0 {
		return ""
	}
	return m.Answer[0].(*dns.TXT).Txt[0]
}

func TestRouter(t *testing.T) {
	rt := &Router{
		TLDs:  tld.NewSet("com", "au", "arpa", "xn--p1ai"),
		ICANN: tagged("icann"),
		HNS:   tagged("hns"),
		Zones: []Zone{
			{Suffix: "lan", Resolver: tagged("lan")},
			{Suffix: "home.arpa", Resolver: tagged("home")},
			{Suffix: "printer.home.arpa", Resolver: tagged("printer")},
		},
	}
	rt.SortZones()
	cases := map[string]string{
		"example.com":              "icann",
		"WWW.Example.COM.":         "icann",
		"abc.net.au":               "icann",
		"xn--80ak6aa92e.xn--p1ai":  "icann",
		"1.0.168.192.in-addr.arpa": "icann",
		"welcome.nb":               "hns",
		"nb":                       "hns",
		"proofofconcept":           "hns",
		".":                        "hns",
		"nas.lan":                  "lan",
		"router.home.arpa":         "home",
		"x.printer.home.arpa":      "printer",
	}
	for name, want := range cases {
		if got := handledBy(t, rt, name); got != want {
			t.Errorf("%s -> %q, want %q", name, got, want)
		}
	}
}

func TestRouterSpecialNames(t *testing.T) {
	rt := &Router{TLDs: tld.NewSet(), ICANN: tagged("icann"), HNS: tagged("hns")}
	m := resolve(t, rt, "localhost", dns.TypeA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "127.0.0.1" {
		t.Fatalf("localhost A = %v", m.Answer)
	}
	m = resolve(t, rt, "foo.localhost", dns.TypeAAAA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.AAAA).AAAA.String() != "::1" {
		t.Fatalf("foo.localhost AAAA = %v", m.Answer)
	}
	for _, n := range []string{"printer.local", "x.onion", "a.invalid"} {
		if m := resolve(t, rt, n, dns.TypeA); m.Rcode != dns.RcodeNameError {
			t.Errorf("%s rcode = %s, want NXDOMAIN", n, dns.RcodeToString[m.Rcode])
		}
	}
}

func TestRouterWithoutTLDListSendsEverythingToHNS(t *testing.T) {
	rt := &Router{TLDs: tld.NewSet(), ICANN: tagged("icann"), HNS: tagged("hns")}
	if got := handledBy(t, rt, "example.com"); got != "hns" {
		t.Fatalf("got %q", got)
	}
}
