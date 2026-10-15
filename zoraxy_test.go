package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type managementMock struct {
	t              *testing.T
	rules          []proxyRule
	logins         int
	mutations      int
	failure        string
	ignoreWrite    bool
	paths          []string
	detail         map[string]json.RawMessage
	accessResponse string
	ignorePath     string
	forms          []url.Values
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
	if r.URL.Path == "/api/access/list" {
		if m.accessResponse != "" {
			w.Write([]byte(m.accessResponse))
		} else {
			w.Write([]byte(`[{"ID":"default","Name":"Default"},{"ID":"private","Name":"Private"}]`))
		}
		return
	}
	if r.URL.Path == "/api/proxy/detail" {
		if r.Method != http.MethodPost || r.Form.Get("type") != "host" || r.Form.Get("epname") != "app.example.com" {
			m.t.Error("incorrect detail request")
		}
		if m.detail == nil {
			m.detail = realisticDetail(m.rules[0])
		}
		json.NewEncoder(w).Encode(m.detail)
		return
	}
	if r.Method != http.MethodPost {
		m.t.Error("mutation must use POST")
	}
	m.mutations++
	m.forms = append(m.forms, r.Form)
	if m.failure != "" {
		w.Write([]byte(m.failure))
		return
	}
	if !m.ignoreWrite && r.URL.Path != m.ignorePath {
		switch r.URL.Path {
		case "/api/proxy/add":
			if r.Form.Get("type") != "host" || r.Form.Get("tags") != ownershipTag || r.Form.Get("tlsval") != "false" {
				m.t.Error("incorrect creation parameters")
			}
			m.rules = append(m.rules, proxyRule{
				RootOrMatchingDomain: r.Form.Get("rootname"), Tags: []string{r.Form.Get("tags")},
				ActiveOrigins:    []proxyOrigin{{OriginIpOrDomain: r.Form.Get("ep"), RequireTLS: r.Form.Get("tls") == "true"}},
				AccessFilterUUID: r.Form.Get("access"), BlockCommonExploits: r.Form.Get("blockCommonExploits") == "true",
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
		case "/api/access/attach":
			if r.Form.Get("host") != "app.example.com" || r.Form.Get("id") == "" {
				m.t.Error("incorrect access attachment")
			}
			m.rules[0].AccessFilterUUID = r.Form.Get("id")
		case "/api/proxy/edit":
			if r.Form.Get("rootname") != "app.example.com" {
				m.t.Error("incorrect edit selector")
			}
			// Model the destructive handler rather than merging only supplied values.
			for key, param := range editBoolFields {
				setDetail(m.detail, key, r.Form.Get(param) == "true")
			}
			for key, param := range editIntFields {
				value, _ := strconv.ParseInt(r.Form.Get(param), 10, 64)
				setDetail(m.detail, key, value)
			}
			setDetail(m.detail, "UptimeMonitorURI", r.Form.Get("utmURI"))
			setDetail(m.detail, "Tags", strings.Split(r.Form.Get("tags"), ","))
			var auth map[string]json.RawMessage
			json.Unmarshal(m.detail["AuthenticationProvider"], &auth)
			method, _ := strconv.Atoi(r.Form.Get("authprovider"))
			setDetail(auth, "AuthMethod", method)
			setDetail(m.detail, "AuthenticationProvider", auth)
			if r.Form.Get("captcha") == "true" {
				provider, _ := strconv.Atoi(r.Form.Get("captchaProvider"))
				duration, _ := strconv.Atoi(r.Form.Get("captchaSessionDuration"))
				score, _ := strconv.ParseFloat(r.Form.Get("captchaRecaptchaScore"), 64)
				paths := []string{}
				if text := r.Form.Get("captchaPathPrefixes"); text != "" {
					paths = strings.Split(text, "\n")
				}
				setDetail(m.detail, "CaptchaConfig", map[string]any{"Provider": provider, "SiteKey": r.Form.Get("captchaSiteKey"), "SecretKey": r.Form.Get("captchaSecretKey"), "SessionDuration": duration, "RecaptchaVersion": r.Form.Get("captchaRecaptchaVersion"), "RecaptchaScore": score, "ProtectedPathPrefixes": paths, "ExceptionRules": nil})
			} else {
				setDetail(m.detail, "CaptchaConfig", nil)
			}
			m.rules[0].BlockCommonExploits = r.Form.Get("blockCommonExploits") == "true"
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
	return proxyRule{RootOrMatchingDomain: "app.example.com", Tags: []string{ownershipTag, "production"}, ActiveOrigins: []proxyOrigin{{OriginIpOrDomain: "old.internal:80"}}}
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
					_, err = c.Apply(context.Background(), Deployment{Hostname: "app.example.com", Upstream: "http://new:80"})
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
			_, err := c.Apply(context.Background(), Deployment{Hostname: "app.example.com", Upstream: "http://new:80"})
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
				_, err = c.Apply(context.Background(), Deployment{Hostname: "app.example.com", Upstream: "http://new:80"})
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

func setDetail(fields map[string]json.RawMessage, key string, value any) {
	fields[key], _ = json.Marshal(value)
}

func realisticDetail(rule proxyRule) map[string]json.RawMessage {
	raw, _ := json.Marshal(rule)
	fields := map[string]json.RawMessage{}
	json.Unmarshal(raw, &fields)
	for key := range editBoolFields {
		if _, ok := fields[key]; !ok {
			setDetail(fields, key, true)
		}
	}
	for key := range editIntFields {
		setDetail(fields, key, 5)
	}
	setDetail(fields, "UptimeMonitorURI", "/healthz")
	setDetail(fields, "AuthenticationProvider", map[string]any{"AuthMethod": 2, "BasicAuthCredentials": []any{map[string]any{"Username": "alice", "PasswordHash": "hash"}}, "ForwardAuthURL": "https://auth.internal/verify", "BasicAuthExceptionRules": []any{map[string]any{"PathPrefix": "/public"}}, "BasicAuthGroupIDs": []string{"staff"}})
	setDetail(fields, "Tags", rule.Tags)
	setDetail(fields, "HeaderRewriteRules", map[string]any{"HSTSMaxAge": 31536000, "RequestHostOverwrite": "internal"})
	setDetail(fields, "TlsOptions", map[string]any{"MinTLSVersion": 771})
	setDetail(fields, "CaptchaConfig", map[string]any{"Provider": 1, "SiteKey": "site", "SecretKey": "secret&captcha", "SessionDuration": 7200, "RecaptchaVersion": "v3", "RecaptchaScore": 0.7, "ProtectedPathPrefixes": []string{"/admin", "/private"}, "ExceptionRules": nil})
	return fields
}

func TestDeploymentSettings(t *testing.T) {
	for _, create := range []bool{false, true} {
		for _, enable := range []bool{false, true} {
			t.Run(strconv.FormatBool(create)+"/"+strconv.FormatBool(enable), func(t *testing.T) {
				rule := ownedRule()
				rule.AccessFilterUUID = "default"
				rule.BlockCommonExploits = !enable
				m := &managementMock{}
				if !create {
					m.rules = []proxyRule{rule}
				}
				c := newTestClient(t, m)
				access := "private"
				d := Deployment{Hostname: rule.RootOrMatchingDomain, Upstream: "http://old.internal:80", AccessRule: &access, ExploitPrevention: &enable}
				result, err := c.Apply(context.Background(), d)
				want := "updated"
				if create {
					want = "created"
				}
				if err != nil || result.Action != want {
					t.Fatalf("result=%+v error=%v", result, err)
				}
				if m.rules[0].AccessFilterUUID != access || m.rules[0].BlockCommonExploits != enable {
					t.Fatal("settings not applied")
				}
				writes := m.mutations
				result, err = c.Apply(context.Background(), d)
				if err != nil || result.Action != "unchanged" || writes != m.mutations {
					t.Fatalf("not idempotent: %+v %v", result, err)
				}
			})
		}
	}
}

func TestSettingsOmissionAndDefaults(t *testing.T) {
	rule := ownedRule()
	rule.AccessFilterUUID = "private"
	rule.BlockCommonExploits = true
	m := &managementMock{rules: []proxyRule{rule}}
	c := newTestClient(t, m)
	if _, err := c.Apply(context.Background(), Deployment{Hostname: rule.RootOrMatchingDomain, Upstream: "http://new:80"}); err != nil {
		t.Fatal(err)
	}
	if m.rules[0].AccessFilterUUID != "private" || !m.rules[0].BlockCommonExploits || m.mutations != 1 {
		t.Fatal("omission changed settings")
	}
	m = &managementMock{}
	c = newTestClient(t, m)
	if _, err := c.Apply(context.Background(), Deployment{Hostname: rule.RootOrMatchingDomain, Upstream: "http://new:80"}); err != nil {
		t.Fatal(err)
	}
	if m.rules[0].AccessFilterUUID != "default" || m.rules[0].BlockCommonExploits {
		t.Fatal("incorrect create defaults")
	}
	var d Deployment
	if err := json.Unmarshal([]byte(`{"hostname":"app.example.com","upstream":"http://new:80","exploit_prevention":false}`), &d); err != nil || d.ExploitPrevention == nil || *d.ExploitPrevention || d.AccessRule != nil {
		t.Fatal("optional JSON semantics")
	}
}

func TestAccessPreflight(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `{}`, `{"error":"secret&password"}`, `[{"Name":"private"}]`, `[{"ID":"private"},{"ID":"private"}]`, `[{"ID":42}]`, `broken`} {
		for _, create := range []bool{false, true} {
			t.Run(body+strconv.FormatBool(create), func(t *testing.T) {
				m := &managementMock{accessResponse: body}
				if !create {
					m.rules = []proxyRule{ownedRule()}
				}
				c := newTestClient(t, m)
				access := "private"
				enable := true
				_, err := c.Apply(context.Background(), Deployment{Hostname: "app.example.com", Upstream: "http://new:80", AccessRule: &access, ExploitPrevention: &enable})
				if err == nil || m.mutations != 0 || strings.Contains(err.Error(), "secret&password") {
					t.Fatalf("error=%v mutations=%d", err, m.mutations)
				}
			})
		}
	}
	for _, id := range []string{"", " private", "unknown"} {
		m := &managementMock{}
		c := newTestClient(t, m)
		if _, err := c.Apply(context.Background(), Deployment{Hostname: "app.example.com", Upstream: "http://new:80", AccessRule: &id}); err == nil || m.mutations != 0 {
			t.Fatalf("accepted %q: %v", id, err)
		}
	}
}

func TestExploitEditFailsSafe(t *testing.T) {
	for _, mode := range []string{"missing", "null", "wrong-type", "unknown", "auth", "tags", "captcha-exception", "captcha-unknown", "captcha-path", "dormant-captcha", "negative-rate"} {
		t.Run(mode, func(t *testing.T) {
			rule := ownedRule()
			detail := realisticDetail(rule)
			switch mode {
			case "missing":
				delete(detail, "DisableLogging")
			case "null":
				setDetail(detail, "ForceHTTP11", nil)
			case "wrong-type":
				setDetail(detail, "RateLimit", "bad")
			case "unknown":
				setDetail(detail, "FutureSecuritySetting", true)
			case "auth":
				setDetail(detail, "AuthenticationProvider", map[string]any{"AuthMethod": 99})
			case "tags":
				setDetail(detail, "Tags", []string{ownershipTag, "a,b"})
			case "negative-rate":
				setDetail(detail, "RateLimit", -1)
			case "dormant-captcha":
				setDetail(detail, "RequireCaptcha", false)
			default:
				var config map[string]json.RawMessage
				json.Unmarshal(detail["CaptchaConfig"], &config)
				if mode == "captcha-exception" {
					setDetail(config, "ExceptionRules", []any{map[string]any{"RuleType": 0, "PathPrefix": "/health"}})
				}
				if mode == "captcha-unknown" {
					setDetail(config, "FutureOption", true)
				}
				if mode == "captcha-path" {
					setDetail(config, "ProtectedPathPrefixes", []string{"/a;b"})
				}
				setDetail(detail, "CaptchaConfig", config)
			}
			m := &managementMock{rules: []proxyRule{rule}, detail: detail}
			c := newTestClient(t, m)
			enable := true
			access := "private"
			_, err := c.Apply(context.Background(), Deployment{Hostname: rule.RootOrMatchingDomain, Upstream: "http://new:80", AccessRule: &access, ExploitPrevention: &enable})
			if err == nil || m.mutations != 0 {
				t.Fatalf("error=%v mutations=%d", err, m.mutations)
			}
		})
	}
}

func TestDetailFailuresAndPreservationVerification(t *testing.T) {
	for _, mode := range []string{"error", "null", "mismatch", "preservation", "readback-error"} {
		t.Run(mode, func(t *testing.T) {
			rule := ownedRule()
			m := &managementMock{t: t, rules: []proxyRule{rule}, detail: realisticDetail(rule)}
			details := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/proxy/detail" {
					details++
					if mode == "error" || (mode == "readback-error" && details == 2) {
						w.Write([]byte(`{"error":"secret&password"}`))
						return
					}
					if mode == "null" {
						w.Write([]byte(`null`))
						return
					}
					if mode == "mismatch" {
						setDetail(m.detail, "AccessFilterUUID", "other")
					}
					if mode == "preservation" && details == 2 {
						setDetail(m.detail, "HeaderRewriteRules", map[string]any{"HSTSMaxAge": 0})
					}
				}
				m.ServeHTTP(w, r)
			}))
			defer s.Close()
			c, err := NewZoraxyClient(s.URL, "admin", "secret&password")
			if err != nil {
				t.Fatal(err)
			}
			enabled := true
			_, err = c.Apply(context.Background(), Deployment{Hostname: rule.RootOrMatchingDomain, Upstream: "http://old.internal:80", ExploitPrevention: &enabled})
			if err == nil || strings.Contains(err.Error(), "secret&password") {
				t.Fatalf("unsafe or missing error: %v", err)
			}
			if mode != "preservation" && mode != "readback-error" && m.mutations != 0 {
				t.Fatal("preflight failure mutated proxy")
			}
		})
	}
}

func TestExploitPreservesSettings(t *testing.T) {
	for method := 0; method <= 4; method++ {
		t.Run(strconv.Itoa(method), func(t *testing.T) {
			rule := ownedRule()
			detail := realisticDetail(rule)
			var auth map[string]json.RawMessage
			json.Unmarshal(detail["AuthenticationProvider"], &auth)
			setDetail(auth, "AuthMethod", method)
			setDetail(detail, "AuthenticationProvider", auth)
			m := &managementMock{rules: []proxyRule{rule}, detail: detail}
			c := newTestClient(t, m)
			enabled := true
			_, err := c.Apply(context.Background(), Deployment{Hostname: rule.RootOrMatchingDomain, Upstream: "http://old.internal:80", ExploitPrevention: &enabled})
			if err != nil {
				t.Fatal(err)
			}
			form := m.forms[0]
			for key, value := range map[string]string{
				"rootname": "app.example.com", "ss": "true", "bpgtls": "true", "enableConnectSupport": "true", "enableUpgradeForwarding": "true",
				"dutm": "true", "dAutoFallback": "true", "utmURI": "/healthz", "authprovider": strconv.Itoa(method), "rate": "true", "ratenum": "5",
				"captcha": "true", "captchaProvider": "1", "captchaSiteKey": "site", "captchaSecretKey": "secret&captcha", "captchaSessionDuration": "7200", "captchaRecaptchaVersion": "v3", "captchaRecaptchaScore": "0.7", "captchaPathPrefixes": "/admin\n/private",
				"dChunkedEnc": "true", "forceHTTP11": "true", "disableWebSocket": "true", "websocketTimeout": "5", "enableTimeoutRefreshOnActivity": "true",
				"dLogging": "true", "dStatisticCollection": "true", "blockCommonExploits": "true", "blockAICrawlers": "true", "mitigationAction": "5", "tags": ownershipTag + ",production",
			} {
				if form.Get(key) != value {
					t.Errorf("%s=%q want %q", key, form.Get(key), value)
				}
			}
			if form.Has("cred") || form.Has("payload") {
				t.Fatal("must not rewrite credentials or upstream")
			}
		})
	}
}

func TestSettingsReadbackFailure(t *testing.T) {
	for _, path := range []string{"/api/access/attach", "/api/proxy/edit"} {
		t.Run(path, func(t *testing.T) {
			m := &managementMock{rules: []proxyRule{ownedRule()}, ignorePath: path}
			c := newTestClient(t, m)
			access := "private"
			enable := true
			d := Deployment{Hostname: "app.example.com", Upstream: "http://old.internal:80"}
			if path == "/api/access/attach" {
				d.AccessRule = &access
			} else {
				d.ExploitPrevention = &enable
			}
			if _, err := c.Apply(context.Background(), d); err == nil || !strings.Contains(err.Error(), "verification") {
				t.Fatalf("expected verification failure: %v", err)
			}
		})
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
