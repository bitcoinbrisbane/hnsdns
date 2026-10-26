// Package tld keeps the set of top-level domains that exist in ICANN's root
// zone. Anything in the set is resolved through the ICANN upstream; anything
// else is treated as a Handshake name.
//
// The list comes from IANA (tlds-alpha-by-domain.txt), is cached on disk so a
// restart works offline, and is refreshed periodically.
package tld

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultURL is IANA's canonical list of root-zone TLDs.
const DefaultURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

// minEntries guards against replacing a good list with a truncated or bogus
// download. The real list has ~1,400 entries.
const minEntries = 500

// Set is a concurrency-safe set of lowercase TLD labels (A-label form).
type Set struct {
	mu      sync.RWMutex
	labels  map[string]struct{}
	updated time.Time
}

// NewSet returns a set containing labels.
func NewSet(labels ...string) *Set {
	s := &Set{labels: make(map[string]struct{}, len(labels))}
	for _, l := range labels {
		s.labels[strings.ToLower(l)] = struct{}{}
	}
	return s
}

// Contains reports whether label (e.g. "com", "xn--p1ai") is an ICANN TLD.
func (s *Set) Contains(label string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.labels[strings.ToLower(label)]
	return ok
}

// Len returns the number of TLDs in the set.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.labels)
}

// Updated returns when the set was last replaced.
func (s *Set) Updated() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.updated
}

func (s *Set) replace(labels map[string]struct{}, at time.Time) {
	s.mu.Lock()
	s.labels = labels
	s.updated = at
	s.mu.Unlock()
}

// Parse reads IANA's list format: one TLD per line, '#' comments.
func Parse(r io.Reader) (map[string]struct{}, error) {
	out := make(map[string]struct{}, 1600)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label := strings.ToLower(line)
		if !validLabel(label) {
			return nil, fmt.Errorf("tld: malformed line %q", line)
		}
		out[label] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// validLabel reports whether s is a letters-digits-hyphen label, the form
// every root-zone TLD takes (IDNs appear as xn-- A-labels).
func validLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Loader populates a Set from a disk cache and from IANA.
type Loader struct {
	Set       *Set
	URL       string       // defaults to DefaultURL
	CachePath string       // optional; empty disables the disk cache
	Client    *http.Client // defaults to http.DefaultClient
	Logf      func(format string, args ...any)
}

func (l *Loader) logf(format string, args ...any) {
	if l.Logf != nil {
		l.Logf(format, args...)
	}
}

// LoadCache fills the set from the on-disk cache, if present.
func (l *Loader) LoadCache() error {
	if l.CachePath == "" {
		return errors.New("tld: no cache path")
	}
	f, err := os.Open(l.CachePath)
	if err != nil {
		return err
	}
	defer f.Close()
	labels, err := Parse(f)
	if err != nil {
		return err
	}
	if len(labels) < minEntries {
		return fmt.Errorf("tld: cache has only %d entries", len(labels))
	}
	st, _ := f.Stat()
	at := time.Now()
	if st != nil {
		at = st.ModTime()
	}
	l.Set.replace(labels, at)
	return nil
}

// Fetch downloads the list, replaces the set and rewrites the cache.
func (l *Loader) Fetch(ctx context.Context) error {
	url := l.URL
	if url == "" {
		url = DefaultURL
	}
	client := l.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tld: GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	labels, err := Parse(strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	if len(labels) < minEntries {
		return fmt.Errorf("tld: download has only %d entries", len(labels))
	}
	l.Set.replace(labels, time.Now())
	if l.CachePath != "" {
		if err := writeAtomic(l.CachePath, body); err != nil {
			l.logf("tld: writing cache %s: %v", l.CachePath, err)
		}
	}
	return nil
}

// Run refreshes the list every interval until ctx is done. Failed fetches are
// retried with backoff, capped at interval.
func (l *Loader) Run(ctx context.Context, interval time.Duration) {
	wait := time.Duration(0)
	if !l.Set.Updated().IsZero() {
		wait = time.Until(l.Set.Updated().Add(interval))
		if wait < 0 {
			wait = 0
		}
	}
	backoff := 30 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		fctx, cancel := context.WithTimeout(ctx, time.Minute)
		err := l.Fetch(fctx)
		cancel()
		if err != nil {
			l.logf("tld: refresh failed: %v (retrying in %s)", err, backoff)
			wait = backoff
			backoff = min(backoff*2, interval)
			continue
		}
		l.logf("tld: loaded %d ICANN TLDs", l.Set.Len())
		backoff = 30 * time.Second
		wait = interval
	}
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tlds-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
