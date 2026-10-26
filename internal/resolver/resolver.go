// Package resolver contains the pieces that answer a DNS question: an ICANN
// upstream (DoH or plain DNS), an iterative resolver rooted at a Handshake
// root server, a router that chooses between them, and a cache.
package resolver

import (
	"context"
	"errors"

	"github.com/miekg/dns"
)

// Resolver answers a single question. The returned message carries Rcode,
// Answer and Ns; callers should not rely on Extra. Implementations must be
// safe for concurrent use.
type Resolver interface {
	Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error)
}

// Func adapts a function to the Resolver interface.
type Func func(ctx context.Context, q dns.Question) (*dns.Msg, error)

// Resolve calls f.
func (f Func) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	return f(ctx, q)
}

var (
	// ErrDepth is returned when resolution recurses too deeply, usually a
	// CNAME or glueless-delegation loop.
	ErrDepth = errors.New("resolver: maximum recursion depth exceeded")
	// ErrNoServers is returned when a delegation has no reachable servers.
	ErrNoServers = errors.New("resolver: no usable nameservers")
)

// reply builds an answer-only message from an upstream response, dropping
// header flags, glue and EDNS options that belong to the upstream hop.
func reply(q dns.Question, from *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	m.Rcode = from.Rcode
	m.Answer = from.Answer
	m.Ns = from.Ns
	return m
}

// rcodeMsg is a message with only an rcode and the question.
func rcodeMsg(q dns.Question, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	m.Rcode = rcode
	return m
}

type depthKey struct{}

// depth returns how many nested resolutions the context has passed through.
func depth(ctx context.Context) int {
	d, _ := ctx.Value(depthKey{}).(int)
	return d
}

func withDepth(ctx context.Context, d int) context.Context {
	return context.WithValue(ctx, depthKey{}, d)
}
