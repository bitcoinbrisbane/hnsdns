// Command hnsdns is a small local DNS server: ICANN names go to an upstream
// such as Cloudflare over DNS-over-HTTPS, Handshake names are resolved
// iteratively from a Handshake root server (hnsd).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/bitcoinbrisbane/hnsdns/internal/resolver"
	"github.com/bitcoinbrisbane/hnsdns/internal/server"
	"github.com/bitcoinbrisbane/hnsdns/internal/tld"
)

var version = "dev"

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hnsdns:", err)
		os.Exit(1)
	}
}

func run() error {
	var zones listFlag
	listen := flag.String("listen", "127.0.0.1:53", "address to serve DNS on (UDP and TCP)")
	upstream := flag.String("upstream", "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query",
		"ICANN upstreams, comma separated: DoH URLs (https://...) or plain DNS ip:port")
	hnsRoot := flag.String("hns-root", "127.0.0.1:5369",
		"Handshake root server(s), comma separated (hnsd -n default 127.0.0.1:5369; hsd uses 5349)")
	tldURL := flag.String("tld-url", tld.DefaultURL, "IANA TLD list URL")
	tldCache := flag.String("tld-cache", defaultCachePath(), "where to cache the TLD list (empty to disable)")
	tldRefresh := flag.Duration("tld-refresh", 24*time.Hour, "how often to refresh the TLD list")
	flag.Var(&zones, "zone", "send a zone to a plain DNS server, e.g. lan=192.168.1.1:53 (repeatable)")
	cacheSize := flag.Int("cache-size", 10000, "maximum cached answers")
	ipv6 := flag.Bool("ipv6", false, "use IPv6 addresses for Handshake nameservers")
	verbose := flag.Bool("v", false, "log every query")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("hnsdns", version)
		return nil
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	icann, err := upstreamResolver(splitList(*upstream))
	if err != nil {
		return err
	}

	tlds := tld.NewSet()
	router := &resolver.Router{TLDs: tlds, ICANN: icann}
	for _, z := range zones {
		suffix, addr, ok := strings.Cut(z, "=")
		if !ok || suffix == "" || addr == "" {
			return fmt.Errorf("bad -zone %q, want suffix=ip:port", z)
		}
		router.Zones = append(router.Zones, resolver.Zone{
			Suffix:   suffix,
			Resolver: &resolver.Forwarder{Servers: splitList(withPort(addr))},
		})
	}
	router.SortZones()

	cache := &resolver.Cache{Next: router, MaxEntries: *cacheSize}
	router.HNS = &resolver.Recursive{
		Roots:  splitList(*hnsRoot),
		Lookup: cache, // nameserver hosts and CNAME targets go back through the router
		IPv6:   *ipv6,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The TLD list is fetched through our own ICANN upstream so it works even
	// when this server is the machine's only resolver.
	loader := &tld.Loader{
		Set:       tlds,
		URL:       *tldURL,
		CachePath: *tldCache,
		Client:    &http.Client{Timeout: 30 * time.Second, Transport: dialVia(icann)},
		Logf:      func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) },
	}
	if err := loader.LoadCache(); err == nil {
		log.Info("loaded TLD list from cache", "path", *tldCache, "tlds", tlds.Len())
	} else if *tldCache != "" && !errors.Is(err, os.ErrNotExist) {
		log.Warn("ignoring TLD cache", "err", err)
	}
	if tlds.Len() == 0 {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := loader.Fetch(fctx); err != nil {
			log.Warn("no ICANN TLD list yet; every name goes via the Handshake root until it loads", "err", err)
		} else {
			log.Info("fetched TLD list", "tlds", tlds.Len())
		}
		cancel()
	}
	go loader.Run(ctx, *tldRefresh)

	h := &server.Handler{
		Resolver: cache,
		Log:      log,
		Verbose:  *verbose,
		Route:    func(n string) resolver.Path { p, _ := router.Route(n); return p },
	}
	ready := make(chan struct{})
	go func() {
		<-ready
		log.Info("hnsdns listening", "addr", *listen, "upstream", *upstream, "hns_root", *hnsRoot, "version", version)
	}()
	return server.ListenAndServe(ctx, *listen, h, ready)
}

func upstreamResolver(urls []string) (resolver.Resolver, error) {
	if len(urls) == 0 {
		return nil, errors.New("no -upstream given")
	}
	var doh, plain []string
	for _, u := range urls {
		if strings.HasPrefix(u, "https://") {
			doh = append(doh, u)
		} else {
			plain = append(plain, withPort(strings.TrimPrefix(u, "udp://")))
		}
	}
	if len(doh) > 0 && len(plain) > 0 {
		return nil, errors.New("-upstream: use either DoH URLs or plain DNS servers, not both")
	}
	if len(doh) > 0 {
		return &resolver.DoH{URLs: doh, Client: &http.Client{Timeout: 5 * time.Second}}, nil
	}
	return &resolver.Forwarder{Servers: plain}, nil
}

// dialVia returns an HTTP transport that looks up host names with r instead
// of the system resolver.
func dialVia(r resolver.Resolver) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Timeout: 10 * time.Second}
	t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) != nil {
			return d.DialContext(ctx, network, addr)
		}
		m, err := r.Resolve(ctx, dns.Question{Name: dns.Fqdn(host), Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if err != nil {
			return nil, err
		}
		var lastErr error = fmt.Errorf("no A record for %s", host)
		for _, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				c, err := d.DialContext(ctx, network, net.JoinHostPort(a.A.String(), port))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
		}
		return nil, lastErr
	}
	return t
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func withPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), "53")
}

func defaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "hnsdns", "tlds.txt")
}
