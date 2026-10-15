package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeBackend struct {
	calls int
	last  Deployment
}

func (b *fakeBackend) Apply(_ context.Context, d Deployment) (Result, error) {
	b.calls++
	b.last = d
	return Result{Action: "created", Hostname: d.Hostname, Upstream: d.Upstream}, nil
}
func (b *fakeBackend) Delete(_ context.Context, s string) (Result, error) {
	b.calls++
	return Result{Action: "deleted", Hostname: s}, nil
}

func TestCaptureForwarding(t *testing.T) {
	for _, tt := range []struct {
		name, capture, uri, token string
		status                    int
	}{
		{"zoraxy trimmed prefix", strings.TrimSuffix(apiPrefix, "/"), apiPrefix + "health", "secret", 200},
		{"trailing slash prefix", apiPrefix, apiPrefix + "health?check=1", "secret", 200},
		{"missing token", strings.TrimSuffix(apiPrefix, "/"), apiPrefix + "health", "", 401},
		{"wrong capture", "/other", apiPrefix + "health", "secret", 404},
		{"missing capture", "", apiPrefix + "health", "secret", 404},
		{"outside namespace", strings.TrimSuffix(apiPrefix, "/"), "/api/proxy/add", "secret", 404},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := &application{token: sha256.Sum256([]byte("secret"))}
			req := httptest.NewRequest("GET", "/capture/health", nil)
			req.Header.Set("X-Zoraxy-Capture", tt.capture)
			req.Header.Set("X-Zoraxy-Uri", tt.uri)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rec := httptest.NewRecorder()
			a.serveCapture(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tt.status, rec.Body.String())
			}
		})
	}
}

func TestApplication(t *testing.T) {
	b := &fakeBackend{}
	a := &application{client: b, domains: []string{"example.com"}}
	a.token = sha256.Sum256([]byte("test-token-123456789012345678901234"))
	tests := []struct {
		name, method, token, body string
		status                    int
		calls                     int
	}{
		{"create", "PUT", "test-token-123456789012345678901234", `{"hostname":"App.Example.com","upstream":"https://backend.internal:8443"}`, 201, 1},
		{"delete", "DELETE", "test-token-123456789012345678901234", `{"hostname":"app.example.com"}`, 200, 2},
		{"bad token", "PUT", "wrong", `{"hostname":"app.example.com","upstream":"http://backend.internal:80"}`, 401, 2},
		{"outside domain", "PUT", "test-token-123456789012345678901234", `{"hostname":"app.example.com.evil.test","upstream":"http://backend.internal:80"}`, 403, 2},
		{"no port", "PUT", "test-token-123456789012345678901234", `{"hostname":"app.example.com","upstream":"http://backend.internal"}`, 400, 2},
		{"unknown field", "PUT", "test-token-123456789012345678901234", `{"hostname":"app.example.com","upstream":"http://backend.internal:80","tlsval":true}`, 400, 2},
		{"bad method", "POST", "test-token-123456789012345678901234", `{}`, 405, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, apiPrefix+"proxies", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer "+tt.token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			a.ServeHTTP(rec, req)
			if rec.Code != tt.status || b.calls != tt.calls {
				t.Fatalf("status=%d calls=%d body=%s", rec.Code, b.calls, rec.Body.String())
			}
			if tt.name == "create" && b.last.Hostname != "app.example.com" {
				t.Fatal("hostname not normalized")
			}
		})
	}
}

func TestSecurityPayload(t *testing.T) {
	for _, tt := range []struct {
		method, body string
		status       int
	}{
		{"PUT", `{"hostname":"app.example.com","upstream":"http://backend:8080","access_rule":"private","exploit_prevention":false}`, 201},
		{"PUT", `{"hostname":"app.example.com","upstream":"http://backend:8080","access_rule":""}`, 400},
		{"PUT", `{"hostname":"app.example.com","upstream":"http://backend:8080","access_rule":" private "}`, 400},
		{"PUT", `{"hostname":"app.example.com","upstream":"http://backend:8080","exploit_prevention":"true"}`, 400},
		{"DELETE", `{"hostname":"app.example.com","access_rule":"private"}`, 400},
		{"DELETE", `{"hostname":"app.example.com","exploit_prevention":false}`, 400},
	} {
		b := &fakeBackend{}
		a := &application{client: b, domains: []string{"example.com"}, token: sha256.Sum256([]byte("secret"))}
		r := httptest.NewRequest(tt.method, apiPrefix+"proxies", strings.NewReader(tt.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer secret")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Fatalf("%s: status=%d want=%d", tt.body, w.Code, tt.status)
		}
		if tt.status == 201 {
			if b.last.AccessRule == nil || *b.last.AccessRule != "private" || b.last.ExploitPrevention == nil || *b.last.ExploitPrevention {
				t.Fatalf("options lost: %+v", b.last)
			}
		} else if b.calls != 0 {
			t.Fatal("invalid request reached backend")
		}
	}
}

func TestWildcardDomains(t *testing.T) {
	b := &fakeBackend{}
	a := &application{client: b, domains: []string{"*"}, token: sha256.Sum256([]byte("test-token"))}
	for _, tt := range []struct {
		host, token string
		status      int
	}{
		{"app.example.com", "test-token", 201},
		{"other.example.org", "test-token", 201},
		{"*.example.com", "test-token", 400},
		{"127.0.0.1", "test-token", 400},
		{"app.example.net", "wrong-token", 401},
	} {
		t.Run(tt.host+tt.token, func(t *testing.T) {
			req := httptest.NewRequest("PUT", apiPrefix+"proxies", strings.NewReader(`{"hostname":"`+tt.host+`","upstream":"http://backend:8080"}`))
			req.Header.Set("Authorization", "Bearer "+tt.token)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			a.ServeHTTP(rec, req)
			if rec.Code != tt.status {
				t.Fatalf("status=%d, want %d", rec.Code, tt.status)
			}
		})
	}
	if b.calls != 2 {
		t.Fatalf("backend calls=%d, want 2", b.calls)
	}
	if (&application{}).allowed("app.example.com") {
		t.Fatal("empty allowlist must deny access")
	}
}

func TestIntrospect(t *testing.T) {
	b, err := json.Marshal(introspect())
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Type                 int    `json:"type"`
		StaticCaptureIngress string `json:"static_capture_ingress"`
		StaticCapturePaths   []struct {
			CapturePath string `json:"capture_path"`
		} `json:"static_capture_paths"`
	}
	if err = json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Type != 0 || spec.StaticCaptureIngress != "/capture" || len(spec.StaticCapturePaths) != 1 || spec.StaticCapturePaths[0].CapturePath != apiPrefix {
		t.Fatalf("bad introspect: %s", b)
	}
}
