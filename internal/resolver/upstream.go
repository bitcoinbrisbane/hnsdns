package resolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DoH forwards questions to one or more DNS-over-HTTPS endpoints (RFC 8484),
// trying them in order until one answers.
//
// Use IP-literal URLs (https://1.1.1.1/dns-query) when this server is the
// machine's own resolver; a hostname URL would need DNS to find the upstream.
type DoH struct {
	URLs   []string
	Client *http.Client
}

const dohMediaType = "application/dns-message"

// Resolve implements Resolver.
func (d *DoH) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.Id = 0 // RFC 8484 §4.1: use 0 for cache friendliness
	req.RecursionDesired = true
	req.Question = []dns.Question{q}
	req.SetEdns0(4096, false)
	wire, err := req.Pack()
	if err != nil {
		return nil, err
	}
	client := d.Client
	if client == nil {
		client = http.DefaultClient
	}
	var errs []error
	for _, u := range d.URLs {
		m, err := d.post(ctx, client, u, wire)
		if err == nil && m.Rcode != dns.RcodeServerFailure {
			return reply(q, m), nil
		}
		if err == nil {
			err = fmt.Errorf("%s: SERVFAIL", u)
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func (d *DoH) post(ctx context.Context, c *http.Client, url string, wire []byte) (*dns.Msg, error) {
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", dohMediaType)
	hreq.Header.Set("Accept", dohMediaType)
	resp, err := c.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, dohMediaType) {
		return nil, fmt.Errorf("%s: unexpected content-type %q", url, ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	return m, nil
}

// Forwarder sends questions to plain DNS servers ("ip:port") with recursion
// desired, retrying over TCP when a UDP answer is truncated.
type Forwarder struct {
	Servers []string
	Timeout time.Duration // per attempt; default 2s
}

// Resolve implements Resolver.
func (f *Forwarder) Resolve(ctx context.Context, q dns.Question) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{q}
	req.SetEdns0(1232, false)
	m, err := exchange(ctx, f.Servers, req, f.Timeout)
	if err != nil {
		return nil, err
	}
	return reply(q, m), nil
}

// exchange sends req to each server in turn and returns the first usable
// response. SERVFAIL and REFUSED move on to the next server; if every server
// says so, the last such response is returned.
func exchange(ctx context.Context, servers []string, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if len(servers) == 0 {
		return nil, ErrNoServers
	}
	var last *dns.Msg
	var errs []error
	for _, s := range servers {
		if ctx.Err() != nil {
			break
		}
		m, err := exchangeOne(ctx, s, req, timeout)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if m.Id != req.Id {
			errs = append(errs, fmt.Errorf("%s: mismatched id", s))
			continue
		}
		if m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused {
			last = m
			continue
		}
		return m, nil
	}
	if last != nil {
		return last, nil
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func exchangeOne(ctx context.Context, server string, req *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 1232}
	m, _, err := c.ExchangeContext(ctx, req, server)
	if err != nil {
		return nil, err
	}
	if !m.Truncated {
		return m, nil
	}
	c.Net = "tcp"
	m, _, err = c.ExchangeContext(ctx, req, server)
	return m, err
}
