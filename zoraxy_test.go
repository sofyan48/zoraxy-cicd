package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type managementMock struct {
	t           *testing.T
	rules       []proxyRule
	logins      int
	mutations   int
	failure     string
	ignoreWrite bool
	paths       []string
}

func (m *managementMock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.paths = append(m.paths, r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/login.html" {
		http.SetCookie(w, &http.Cookie{Name: "zoraxy_csrf", Value: "csrf-cookie", Path: "/"})
		w.Write([]byte(`<html><meta content='csrf&amp;token' name='zoraxy.csrf.Token'></html>`))
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("X-CSRF-Token") != "csrf&token" {
			m.t.Error("missing rendered CSRF token")
		}
		cookie, err := r.Cookie("zoraxy_csrf")
		if err != nil || cookie.Value != "csrf-cookie" {
			m.t.Error("missing CSRF cookie")
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			m.t.Error("wrong request encoding")
		}
		r.ParseForm()
	}
	if r.URL.Path == "/api/auth/login" {
		m.logins++
		if r.Form.Get("username") != "admin" || r.Form.Get("password") != "secret&password" {
			m.t.Error("incorrect login credentials")
		}
		http.SetCookie(w, &http.Cookie{Name: "Zoraxy", Value: "session", Path: "/"})
		w.Write([]byte(`"OK"`))
		return
	}
	cookie, err := r.Cookie("Zoraxy")
	if err != nil || cookie.Value != "session" {
		m.t.Error("missing management session")
	}
	if r.URL.Path == "/api/proxy/list" {
		if r.Method != http.MethodGet || r.URL.Query().Get("type") != "host" {
			m.t.Error("incorrect list request")
		}
		if m.rules == nil {
			w.Write([]byte(`[]`))
		} else {
			json.NewEncoder(w).Encode(m.rules)
		}
		return
	}
	if r.Method != http.MethodPost {
		m.t.Error("mutation must use POST")
	}
	m.mutations++
	if m.failure != "" {
		w.Write([]byte(m.failure))
		return
	}
	if !m.ignoreWrite {
		switch r.URL.Path {
		case "/api/proxy/add":
			if r.Form.Get("type") != "host" || r.Form.Get("tags") != ownershipTag || r.Form.Get("tlsval") != "false" {
				m.t.Error("incorrect creation parameters")
			}
			m.rules = append(m.rules, proxyRule{
				RootOrMatchingDomain: r.Form.Get("rootname"), Tags: []string{r.Form.Get("tags")},
				ActiveOrigins: []proxyOrigin{{OriginIpOrDomain: r.Form.Get("ep"), RequireTLS: r.Form.Get("tls") == "true"}},
			})
		case "/api/proxy/upstream/update":
			if r.Form.Get("active") != "true" || r.Form.Get("ep") != "app.example.com" || r.Form.Get("origin") != "old.internal:80" {
				m.t.Error("incorrect upstream update selector")
			}
			var payload map[string]json.RawMessage
			json.Unmarshal([]byte(r.Form.Get("payload")), &payload)
			if len(payload) != 2 {
				m.t.Error("update should preserve all other upstream settings")
			}
			json.Unmarshal([]byte(r.Form.Get("payload")), &m.rules[0].ActiveOrigins[0])
		case "/api/proxy/del":
			if r.Form.Get("ep") != "app.example.com" {
				m.t.Error("incorrect delete selector")
			}
			m.rules = nil
		default:
			m.t.Errorf("unexpected API path %s", r.URL.Path)
		}
	}
	w.Write([]byte(`"OK"`))
}

func newTestClient(t *testing.T, m *managementMock) *ZoraxyClient {
	t.Helper()
	m.t = t
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	c, err := NewZoraxyClient(s.URL, "admin", "secret&password")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ownedRule() proxyRule {
	return proxyRule{RootOrMatchingDomain: "app.example.com", Tags: []string{ownershipTag}, ActiveOrigins: []proxyOrigin{{OriginIpOrDomain: "old.internal:80"}}}
}

func TestApplyCreateUpdateUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rules  []proxyRule
		action string
	}{
		{"create", nil, "created"},
		{"update", []proxyRule{ownedRule()}, "updated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &managementMock{rules: tc.rules}
			c := newTestClient(t, m)
			d := Deployment{Hostname: "app.example.com", Upstream: "https://new.internal:8443"}
			result, err := c.Apply(context.Background(), d)
			if err != nil || result.Action != tc.action || result.Hostname != d.Hostname || result.Upstream != d.Upstream {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			result, err = c.Apply(context.Background(), d)
			if err != nil || result.Action != "unchanged" || m.logins != 2 || m.mutations != 1 {
				t.Fatalf("result=%+v error=%v logins=%d mutations=%d", result, err, m.logins, m.mutations)
			}
		})
	}
}

func TestRejectUnsafeRules(t *testing.T) {
	for _, name := range []string{"unowned", "multiple-active", "inactive", "disabled"} {
		for _, operation := range []string{"apply", "delete"} {
			t.Run(name+"/"+operation, func(t *testing.T) {
				rule := ownedRule()
				switch name {
				case "unowned":
					rule.Tags = []string{"other-owner"}
				case "multiple-active":
					rule.ActiveOrigins = append(rule.ActiveOrigins, proxyOrigin{OriginIpOrDomain: "another:80"})
				case "inactive":
					rule.InactiveOrigins = []proxyOrigin{{OriginIpOrDomain: "another:80"}}
				case "disabled":
					rule.Disabled = true
				}
				m := &managementMock{rules: []proxyRule{rule}}
				c := newTestClient(t, m)
				var err error
				if operation == "apply" {
					_, err = c.Apply(context.Background(), Deployment{"app.example.com", "http://new:80"})
				} else {
					_, err = c.Delete(context.Background(), "app.example.com")
				}
				if err == nil || m.mutations != 0 {
					t.Fatalf("error=%v mutations=%d", err, m.mutations)
				}
			})
		}
	}
}

func TestDeleteAndMissing(t *testing.T) {
	m := &managementMock{rules: []proxyRule{ownedRule()}}
	c := newTestClient(t, m)
	for _, action := range []string{"deleted", "unchanged"} {
		r, err := c.Delete(context.Background(), "app.example.com")
		if err != nil || r.Action != action || r.Upstream != "" {
			t.Fatalf("result=%+v error=%v", r, err)
		}
	}
	if m.mutations != 1 || m.logins != 2 {
		t.Fatalf("mutations=%d logins=%d", m.mutations, m.logins)
	}
}

func TestMutationFailures(t *testing.T) {
	for _, body := range []string{`{"error":"secret&password"}`, `{"ok":true}`, ` `, `"NOT OK"`} {
		t.Run(body, func(t *testing.T) {
			m := &managementMock{failure: body}
			c := newTestClient(t, m)
			_, err := c.Apply(context.Background(), Deployment{"app.example.com", "http://new:80"})
			if err == nil || strings.Contains(err.Error(), "secret&password") {
				t.Fatalf("unsafe or missing error: %v", err)
			}
		})
	}
}

func TestReadBackFailure(t *testing.T) {
	for _, operation := range []string{"create", "update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			m := &managementMock{ignoreWrite: true}
			if operation != "create" {
				m.rules = []proxyRule{ownedRule()}
			}
			c := newTestClient(t, m)
			var err error
			if operation == "delete" {
				_, err = c.Delete(context.Background(), "app.example.com")
			} else {
				_, err = c.Apply(context.Background(), Deployment{"app.example.com", "http://new:80"})
			}
			if err == nil || !strings.Contains(err.Error(), "verification") {
				t.Fatalf("expected verification error, got %v", err)
			}
		})
	}
}

func TestResponseSafety(t *testing.T) {
	for _, mode := range []string{"redirect", "oversized", "list-error", "list-null", "login-error", "missing-token"} {
		t.Run(mode, func(t *testing.T) {
			m := &managementMock{t: t}
			foreignCalls := 0
			foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignCalls++ }))
			defer foreign.Close()
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case mode == "redirect":
					http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
				case mode == "oversized":
					w.Write([]byte(strings.Repeat("x", maxResponseBody+1)))
				case mode == "missing-token":
					w.Write([]byte(`<html></html>`))
				case mode == "login-error" && r.URL.Path == "/api/auth/login":
					w.Write([]byte(`{"error":"secret&password"}`))
				case mode == "list-error" && r.URL.Path == "/api/proxy/list":
					w.Write([]byte(`{"error":"secret&password"}`))
				case mode == "list-null" && r.URL.Path == "/api/proxy/list":
					w.Write([]byte(`null`))
				default:
					m.ServeHTTP(w, r)
				}
			}))
			defer s.Close()
			c, err := NewZoraxyClient(s.URL, "admin", "secret&password")
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Delete(context.Background(), "app.example.com")
			if err == nil || strings.Contains(err.Error(), "secret&password") || foreignCalls != 0 || m.mutations != 0 {
				t.Fatalf("error=%v foreign calls=%d mutations=%d", err, foreignCalls, m.mutations)
			}
		})
	}
}

func TestSerializedOperations(t *testing.T) {
	m := &managementMock{}
	c := newTestClient(t, m)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Delete(context.Background(), "missing.example.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if m.logins != 4 {
		t.Fatalf("got %d logins", m.logins)
	}
}

func TestConstructorAndCancellation(t *testing.T) {
	for _, base := range []string{"", "ftp://example.com", "http://user:secret@example.com", "http://example.com/path", "http://example.com?q=secret", "http://example.com/#fragment"} {
		if _, err := NewZoraxyClient(base, "admin", "password"); err == nil {
			t.Errorf("accepted %q", base)
		}
	}
	m := &managementMock{}
	c := newTestClient(t, m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Delete(ctx, "app.example.com"); err != context.Canceled {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if len(m.paths) != 0 {
		t.Fatal("canceled operation made a request")
	}
}
