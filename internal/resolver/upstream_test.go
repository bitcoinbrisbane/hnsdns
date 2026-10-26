package resolver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func dohServer(t *testing.T, answer func(q dns.Question) *dns.Msg) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != dohMediaType {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Id != 0 || !req.RecursionDesired {
			http.Error(w, "want id 0 and RD", http.StatusBadRequest)
			return
		}
		m := answer(req.Question[0])
		rcode := m.Rcode
		m.SetReply(req)
		m.Rcode = rcode
		out, _ := m.Pack()
		w.Header().Set("Content-Type", dohMediaType)
		w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDoH(t *testing.T) {
	srv := dohServer(t, func(q dns.Question) *dns.Msg {
		return msg(0, []dns.RR{rr(t, q.Name+" 300 IN A 104.16.0.1")}, nil, nil)
	})
	d := &DoH{URLs: []string{srv.URL + "/dns-query"}, Client: srv.Client()}
	m := resolve(t, d, "example.com", dns.TypeA)
	if got := answerIPs(m); len(got) != 1 || got[0] != "104.16.0.1" {
		t.Fatalf("answer = %v", got)
	}
	for _, r := range m.Extra {
		if _, ok := r.(*dns.OPT); ok {
			t.Error("upstream OPT leaked into reply")
		}
	}
}

func TestDoHFailsOverAndKeepsNXDOMAIN(t *testing.T) {
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer bad.Close()
	good := dohServer(t, func(q dns.Question) *dns.Msg { return msg(dns.RcodeNameError, nil, nil, nil) })
	client := good.Client() // trusts httptest's shared CA
	d := &DoH{URLs: []string{bad.URL, good.URL}, Client: client}
	m := resolve(t, d, "missing.com", dns.TypeA)
	if m.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s", dns.RcodeToString[m.Rcode])
	}
}

func TestDoHAllFail(t *testing.T) {
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>captive portal</html>"))
	}))
	defer bad.Close()
	d := &DoH{URLs: []string{bad.URL}, Client: bad.Client()}
	_, err := d.Resolve(context.Background(), question("a.com", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "content-type") {
		t.Fatalf("err = %v", err)
	}
}

func TestForwarderTCPFallbackOnTruncation(t *testing.T) {
	big := make([]dns.RR, 0, 100)
	for i := 0; i < 100; i++ {
		big = append(big, rr(t, "big.lan. 60 IN TXT \"padding padding padding padding padding\""))
	}
	s := startAuth(t, "127.0.0.1", "0", func(q dns.Question) *dns.Msg {
		return msg(0, big, nil, nil)
	})
	// miekg's server truncates UDP replies that exceed the client's size and
	// sets TC, so the forwarder must retry over TCP to get all 100.
	f := &Forwarder{Servers: []string{s.addr}, Timeout: time.Second}
	m := resolve(t, f, "big.lan", dns.TypeTXT)
	if len(m.Answer) != 100 {
		t.Fatalf("got %d records, want 100 via TCP", len(m.Answer))
	}
}
