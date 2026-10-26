package tld

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ianaList(n int) string {
	var b strings.Builder
	b.WriteString("# Version 2026102600, Last Updated Mon Oct 26 07:07:01 2026 UTC\n")
	b.WriteString("COM\nAU\nXN--P1AI\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "T%04d\n", i)
	}
	return b.String()
}

func TestParse(t *testing.T) {
	got, err := Parse(strings.NewReader("# comment\nCOM\n\n  NET  \nXN--P1AI\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"com", "net", "xn--p1ai"} {
		if _, ok := got[l]; !ok {
			t.Errorf("missing %q", l)
		}
	}
	if _, err := Parse(strings.NewReader("<html><body>error</body></html>\n")); err == nil {
		t.Error("HTML accepted as a TLD list")
	}
}

func TestSetContains(t *testing.T) {
	s := NewSet("com", "AU")
	if !s.Contains("COM") || !s.Contains("au") || s.Contains("nb") {
		t.Fatal("Contains is wrong")
	}
}

func TestFetchWritesCacheAndReloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(ianaList(800)))
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "sub", "tlds.txt")

	l := &Loader{Set: NewSet(), URL: srv.URL, CachePath: cache}
	if err := l.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !l.Set.Contains("com") || l.Set.Len() != 803 {
		t.Fatalf("len = %d", l.Set.Len())
	}

	l2 := &Loader{Set: NewSet(), CachePath: cache}
	if err := l2.LoadCache(); err != nil {
		t.Fatal(err)
	}
	if !l2.Set.Contains("xn--p1ai") || l2.Set.Updated().IsZero() {
		t.Fatal("cache reload incomplete")
	}
}

func TestFetchRejectsShortOrFailedDownloads(t *testing.T) {
	status := http.StatusOK
	body := ianaList(10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	cache := filepath.Join(t.TempDir(), "tlds.txt")
	l := &Loader{Set: NewSet("keep"), URL: srv.URL, CachePath: cache}

	if err := l.Fetch(context.Background()); err == nil {
		t.Fatal("short list accepted")
	}
	status, body = http.StatusInternalServerError, ianaList(800)
	if err := l.Fetch(context.Background()); err == nil {
		t.Fatal("500 accepted")
	}
	if !l.Set.Contains("keep") {
		t.Fatal("good set replaced by bad download")
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("bad download written to cache")
	}
}
