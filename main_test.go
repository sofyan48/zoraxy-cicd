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
