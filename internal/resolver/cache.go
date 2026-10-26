package resolver

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Cache wraps a resolver with a TTL cache (positive and negative answers)
// and collapses concurrent identical questions into one upstream query.
type Cache struct {
	Next Resolver

	MaxEntries int           // default 10,000
	MinTTL     time.Duration // floor for cached answers; default 0
	MaxTTL     time.Duration // ceiling; default 24h
	NegTTL     time.Duration // negative TTL when no SOA is present; default 60s

	now func() time.Time // for tests

	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
	flight  map[cacheKey]*call
}

type cacheKey struct {
	name   string
	qtype  uint16
	qclass uint16
}

type cacheEntry struct {
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

type call struct {
	done chan struct{}
	msg  *dns.Msg
	err  error
}

func (c *Cache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Len returns the number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Resolve implements Resolver.
func (c *Cache) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	key := cacheKey{strings.ToLower(dns.Fqdn(q.Name)), q.Qtype, q.Qclass}
	now := c.clock()

	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[cacheKey]*cacheEntry)
		c.flight = make(map[cacheKey]*call)
	}
	if e, ok := c.entries[key]; ok {
		if now.Before(e.expires) {
			m := aged(e.msg, uint32(now.Sub(e.stored)/time.Second))
			c.mu.Unlock()
			m.Question = []dns.Question{q}
			return m, nil
		}
		delete(c.entries, key)
	}
	if f, ok := c.flight[key]; ok {
		c.mu.Unlock()
		if onPath(ctx, key) {
			// This question is waiting on itself (e.g. a nameserver whose
			// address can only be found by asking that nameserver).
			return nil, ErrDepth
		}
		select {
		case <-f.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if f.err != nil {
			return nil, f.err
		}
		m := f.msg.Copy()
		m.Question = []dns.Question{q}
		return m, nil
	}
	f := &call{done: make(chan struct{})}
	c.flight[key] = f
	c.mu.Unlock()

	f.msg, f.err = c.Next.Resolve(withPath(ctx, key), q)

	c.mu.Lock()
	delete(c.flight, key)
	if f.err == nil {
		if ttl, ok := c.ttl(f.msg); ok {
			c.store(key, f.msg.Copy(), now, ttl)
		}
	}
	c.mu.Unlock()
	close(f.done)

	if f.err != nil {
		return nil, f.err
	}
	return f.msg.Copy(), nil
}

// ttl decides how long m may be cached; ok is false for uncacheable answers.
func (c *Cache) ttl(m *dns.Msg) (time.Duration, bool) {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return 0, false
	}
	maxTTL := c.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 24 * time.Hour
	}
	var t time.Duration
	switch {
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
		t = minTTL(m.Answer)
	default: // NXDOMAIN or NODATA: RFC 2308, min(SOA TTL, SOA MINIMUM)
		t = c.NegTTL
		if t <= 0 {
			t = 60 * time.Second
		}
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				t = time.Duration(min(soa.Hdr.Ttl, soa.Minttl)) * time.Second
				break
			}
		}
	}
	t = max(t, c.MinTTL)
	t = min(t, maxTTL)
	return t, t > 0
}

func (c *Cache) store(key cacheKey, m *dns.Msg, now time.Time, ttl time.Duration) {
	limit := c.MaxEntries
	if limit <= 0 {
		limit = 10000
	}
	if len(c.entries) >= limit {
		c.evict(now, limit)
	}
	c.entries[key] = &cacheEntry{msg: m, stored: now, expires: now.Add(ttl)}
}

// evict drops expired entries, then arbitrary ones, until under 90% of limit.
func (c *Cache) evict(now time.Time, limit int) {
	for k, e := range c.entries {
		if !now.Before(e.expires) {
			delete(c.entries, k)
		}
	}
	target := limit * 9 / 10
	for k := range c.entries {
		if len(c.entries) <= target {
			break
		}
		delete(c.entries, k)
	}
}

type pathKey struct{}

// pathNode records the chain of questions a resolution is nested inside.
type pathNode struct {
	key    cacheKey
	parent *pathNode
}

func withPath(ctx context.Context, k cacheKey) context.Context {
	parent, _ := ctx.Value(pathKey{}).(*pathNode)
	return context.WithValue(ctx, pathKey{}, &pathNode{key: k, parent: parent})
}

func onPath(ctx context.Context, k cacheKey) bool {
	for n, _ := ctx.Value(pathKey{}).(*pathNode); n != nil; n = n.parent {
		if n.key == k {
			return true
		}
	}
	return false
}

func minTTL(rrs []dns.RR) time.Duration {
	lo := uint32(1<<32 - 1)
	for _, rr := range rrs {
		lo = min(lo, rr.Header().Ttl)
	}
	return time.Duration(lo) * time.Second
}

// aged returns a copy of m with every TTL reduced by elapsed seconds.
func aged(m *dns.Msg, elapsed uint32) *dns.Msg {
	out := m.Copy()
	for _, sec := range [][]dns.RR{out.Answer, out.Ns} {
		for _, rr := range sec {
			h := rr.Header()
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 0
			}
		}
	}
	return out
}
