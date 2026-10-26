package resolver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestCache(next Resolver) (*Cache, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return &Cache{Next: next, now: clk.now}, clk
}

func TestCacheHitAgesTTL(t *testing.T) {
	up := &staticResolver{table: map[string][]dns.RR{
		"a.test. A": {rr(t, "a.test. 100 IN A 1.2.3.4")},
	}}
	c, clk := newTestCache(up)
	resolve(t, c, "a.test", dns.TypeA)
	clk.t = clk.t.Add(40 * time.Second)
	m := resolve(t, c, "A.TEST", dns.TypeA) // case-insensitive key
	if up.calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls.Load())
	}
	if ttl := m.Answer[0].Header().Ttl; ttl != 60 {
		t.Errorf("aged TTL = %d, want 60", ttl)
	}
	if m.Question[0].Name != "A.TEST." {
		t.Errorf("question not echoed: %v", m.Question)
	}
	clk.t = clk.t.Add(61 * time.Second)
	resolve(t, c, "a.test", dns.TypeA)
	if up.calls.Load() != 2 {
		t.Fatalf("expired entry served; calls = %d", up.calls.Load())
	}
}

func TestCacheDoesNotShareMutableMessages(t *testing.T) {
	up := &staticResolver{table: map[string][]dns.RR{
		"a.test. A": {rr(t, "a.test. 100 IN A 1.2.3.4")},
	}}
	c, _ := newTestCache(up)
	m := resolve(t, c, "a.test", dns.TypeA)
	m.Answer[0].Header().Ttl = 1
	m2 := resolve(t, c, "a.test", dns.TypeA)
	if m2.Answer[0].Header().Ttl != 100 {
		t.Fatalf("cache entry mutated by caller: ttl=%d", m2.Answer[0].Header().Ttl)
	}
}

func TestCacheNegativeUsesSOAMinimum(t *testing.T) {
	calls := 0
	next := Func(func(_ context.Context, q dns.Question) (*dns.Msg, error) {
		calls++
		m := rcodeMsg(q, dns.RcodeNameError)
		m.Ns = []dns.RR{rr(t, "test. 900 IN SOA ns. h. 1 1 1 1 30")}
		return m, nil
	})
	c, clk := newTestCache(next)
	resolve(t, c, "gone.test", dns.TypeA)
	clk.t = clk.t.Add(29 * time.Second)
	resolve(t, c, "gone.test", dns.TypeA)
	if calls != 1 {
		t.Fatalf("calls = %d within SOA minimum", calls)
	}
	clk.t = clk.t.Add(2 * time.Second)
	resolve(t, c, "gone.test", dns.TypeA)
	if calls != 2 {
		t.Fatalf("calls = %d after SOA minimum", calls)
	}
}

func TestCacheSkipsServfailAndErrors(t *testing.T) {
	calls := 0
	fail := true
	next := Func(func(_ context.Context, q dns.Question) (*dns.Msg, error) {
		calls++
		if fail {
			return nil, errors.New("boom")
		}
		return rcodeMsg(q, dns.RcodeServerFailure), nil
	})
	c, _ := newTestCache(next)
	if _, err := c.Resolve(context.Background(), question("x.test", dns.TypeA)); err == nil {
		t.Fatal("error swallowed")
	}
	fail = false
	resolve(t, c, "x.test", dns.TypeA)
	resolve(t, c, "x.test", dns.TypeA)
	if calls != 3 || c.Len() != 0 {
		t.Fatalf("calls=%d len=%d; failures must not be cached", calls, c.Len())
	}
}

func TestCacheCollapsesConcurrentQueries(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	next := Func(func(_ context.Context, q dns.Question) (*dns.Msg, error) {
		calls.Add(1)
		<-release
		m := rcodeMsg(q, 0)
		m.Answer = []dns.RR{rr(t, "slow.test. 60 IN A 1.1.1.1")}
		return m, nil
	})
	c := &Cache{Next: next}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := c.Resolve(context.Background(), question("slow.test", dns.TypeA))
			if err != nil || len(m.Answer) != 1 {
				t.Errorf("m=%v err=%v", m, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls.Load())
	}
}

func TestCacheDetectsSelfWait(t *testing.T) {
	// A resolver that, while answering q, asks the cache for q again.
	var c *Cache
	next := Func(func(ctx context.Context, q dns.Question) (*dns.Msg, error) {
		return c.Resolve(ctx, q)
	})
	c = &Cache{Next: next}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := c.Resolve(ctx, question("self.test", dns.TypeA))
	if !errors.Is(err, ErrDepth) {
		t.Fatalf("err = %v, want ErrDepth (not a timeout)", err)
	}
}

func TestCacheEvicts(t *testing.T) {
	next := Func(func(_ context.Context, q dns.Question) (*dns.Msg, error) {
		m := rcodeMsg(q, 0)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: 1, Ttl: 60}}}
		return m, nil
	})
	c := &Cache{Next: next, MaxEntries: 10}
	for i := 0; i < 50; i++ {
		resolve(t, c, string(rune('a'+i%26))+string(rune('a'+i/26))+".test", dns.TypeA)
	}
	if n := c.Len(); n > 10 {
		t.Fatalf("len = %d, want <= 10", n)
	}
}

func TestCacheThroughRecursiveLoop(t *testing.T) {
	// Real wiring: cache -> router -> recursive, whose Lookup is the cache.
	n := newTestNet(t)
	router := &Router{HNS: n.r}
	c := &Cache{Next: router}
	n.r.Lookup = c
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := c.Resolve(ctx, question("www.loop", dns.TypeA))
	if err == nil {
		t.Fatal("expected failure for unresolvable delegation")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took %s: self-dependent nameserver should fail fast, not time out", time.Since(start))
	}
	// And a normal name still works through the same wiring.
	if got := answerIPs(resolve(t, c, "www.hns", dns.TypeA)); len(got) != 1 {
		t.Fatalf("www.hns = %v", got)
	}
}
