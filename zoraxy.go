package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ownershipTag = "zoraxy-integrator"
const maxResponseBody = 1 << 20

type Deployment struct {
	Hostname string `json:"hostname"`
	Upstream string `json:"upstream"`
}

type Result struct {
	Action   string `json:"action"`
	Hostname string `json:"hostname"`
	Upstream string `json:"upstream,omitempty"`
}

type ZoraxyClient struct {
	mu       sync.Mutex
	base     string
	username string
	password string
	http     *http.Client
	token    string
}

type proxyOrigin struct {
	OriginIpOrDomain string
	RequireTLS       bool
}

type proxyRule struct {
	RootOrMatchingDomain string
	MatchingDomainAlias  []string
	Tags                 []string
	Disabled             bool
	ActiveOrigins        []proxyOrigin
	InactiveOrigins      []proxyOrigin
}

// NewZoraxyClient accepts a management origin, without a path or URL credentials.
func NewZoraxyClient(baseURL, username, password string) (*ZoraxyClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid Zoraxy management origin")
	}
	if username == "" || password == "" {
		return nil, errors.New("Zoraxy management credentials are required")
	}
	return &ZoraxyClient{
		base: strings.TrimSuffix(u.String(), "/"), username: username, password: password,
		http: &http.Client{
			Timeout: 15 * time.Second,
			// Redirects are never API success, even when they stay on the same origin.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *ZoraxyClient) Apply(ctx context.Context, d Deployment) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	u, err := url.Parse(d.Upstream)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Result{}, errors.New("invalid upstream URL")
	}
	want := proxyOrigin{OriginIpOrDomain: u.Host, RequireTLS: u.Scheme == "https"}
	if err := c.login(ctx); err != nil {
		return Result{}, err
	}
	rule, err := c.findRule(ctx, d.Hostname)
	if err != nil {
		return Result{}, err
	}
	action := "created"
	if rule != nil {
		if err := manageable(rule); err != nil {
			return Result{}, err
		}
		if rule.ActiveOrigins[0] == want {
			return Result{Action: "unchanged", Hostname: d.Hostname, Upstream: d.Upstream}, nil
		}
		action = "updated"
		payload, _ := json.Marshal(want)
		err = c.mutate(ctx, "/api/proxy/upstream/update", url.Values{
			"ep": {d.Hostname}, "origin": {rule.ActiveOrigins[0].OriginIpOrDomain},
			"active": {"true"}, "payload": {string(payload)},
		})
	} else {
		err = c.mutate(ctx, "/api/proxy/add", url.Values{
			"type": {"host"}, "rootname": {d.Hostname}, "ep": {want.OriginIpOrDomain},
			"tls": {strconv.FormatBool(want.RequireTLS)}, "tlsval": {"false"},
			"tags": {ownershipTag}, "access": {"default"},
		})
	}
	if err != nil {
		return Result{}, err
	}
	verified, err := c.findRule(ctx, d.Hostname)
	if err != nil {
		return Result{}, err
	}
	if verified == nil || manageable(verified) != nil || verified.ActiveOrigins[0] != want {
		return Result{}, errors.New("proxy mutation read-back verification failed")
	}
	return Result{Action: action, Hostname: d.Hostname, Upstream: d.Upstream}, nil
}

func (c *ZoraxyClient) Delete(ctx context.Context, hostname string) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := c.login(ctx); err != nil {
		return Result{}, err
	}
	rule, err := c.findRule(ctx, hostname)
	if err != nil {
		return Result{}, err
	}
	if rule == nil {
		return Result{Action: "unchanged", Hostname: hostname}, nil
	}
	if err := manageable(rule); err != nil {
		return Result{}, err
	}
	if err := c.mutate(ctx, "/api/proxy/del", url.Values{"ep": {hostname}}); err != nil {
		return Result{}, err
	}
	verified, err := c.findRule(ctx, hostname)
	if err != nil {
		return Result{}, err
	}
	if verified != nil {
		return Result{}, errors.New("proxy deletion read-back verification failed")
	}
	return Result{Action: "deleted", Hostname: hostname}, nil
}

func manageable(rule *proxyRule) error {
	owned := false
	for _, tag := range rule.Tags {
		owned = owned || tag == ownershipTag
	}
	if !owned {
		return errors.New("refusing to modify an unowned proxy rule")
	}
	if rule.Disabled || len(rule.ActiveOrigins) != 1 || len(rule.InactiveOrigins) != 0 {
		return errors.New("managed proxy rule must be enabled with exactly one active and no inactive origins")
	}
	return nil
}

func (c *ZoraxyClient) login(ctx context.Context) error {
	// Each operation starts with a fresh session and CSRF cookie pair.
	jar, _ := cookiejar.New(nil)
	c.http.Jar = jar
	c.token = ""
	body, err := c.request(ctx, http.MethodGet, "/login.html", nil)
	if err != nil {
		return err
	}
	c.token = csrfToken(string(body))
	if c.token == "" {
		return errors.New("management login page has no CSRF token")
	}
	return c.mutate(ctx, "/api/auth/login", url.Values{
		"username": {c.username}, "password": {c.password}, "rmbme": {"false"},
	})
}

var metaPattern = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
var attrPattern = regexp.MustCompile(`(?is)([a-zA-Z][a-zA-Z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

func csrfToken(page string) string {
	for _, tag := range metaPattern.FindAllString(page, -1) {
		attrs := make(map[string]string)
		for _, match := range attrPattern.FindAllStringSubmatch(tag, -1) {
			attrs[strings.ToLower(match[1])] = html.UnescapeString(match[2] + match[3])
		}
		if attrs["name"] == "zoraxy.csrf.Token" {
			return attrs["content"]
		}
	}
	return ""
}

func (c *ZoraxyClient) findRule(ctx context.Context, hostname string) (*proxyRule, error) {
	body, err := c.request(ctx, http.MethodGet, "/api/proxy/list?type=host", nil)
	if err != nil {
		return nil, err
	}
	if err := checkAPIError(body); err != nil {
		return nil, err
	}
	var rules []proxyRule
	if json.Unmarshal(body, &rules) != nil || len(strings.TrimSpace(string(body))) == 0 || strings.TrimSpace(string(body))[0] != '[' {
		return nil, errors.New("invalid proxy list response")
	}
	var found *proxyRule
	for i := range rules {
		if rules[i].RootOrMatchingDomain == "" {
			return nil, errors.New("invalid proxy rule in list response")
		}
		for _, alias := range rules[i].MatchingDomainAlias {
			if strings.EqualFold(alias, hostname) {
				return nil, errors.New("hostname is already an alias of another proxy rule")
			}
		}
		if strings.EqualFold(rules[i].RootOrMatchingDomain, hostname) {
			if found != nil {
				return nil, errors.New("ambiguous proxy rule in list response")
			}
			found = &rules[i]
		}
	}
	return found, nil
}

func checkAPIError(body []byte) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) == nil {
		if _, exists := fields["error"]; exists {
			// Upstream error messages may echo secrets or user-controlled content.
			return errors.New("Zoraxy API reported an error")
		}
	}
	return nil
}

func (c *ZoraxyClient) mutate(ctx context.Context, path string, form url.Values) error {
	body, err := c.request(ctx, http.MethodPost, path, form)
	if err != nil {
		return err
	}
	if err := checkAPIError(body); err != nil {
		return err
	}
	var result string
	if json.Unmarshal(body, &result) != nil || result != "OK" {
		return errors.New("invalid Zoraxy mutation acknowledgement")
	}
	return nil
}

func (c *ZoraxyClient) request(ctx context.Context, method, path string, form url.Values) ([]byte, error) {
	var reader io.Reader
	if form != nil {
		reader = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, errors.New("could not construct management request")
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", c.token)
		req.Header.Set("Referer", c.base+"/login.html")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("management request failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("management request returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, errors.New("could not read management response")
	}
	if len(body) > maxResponseBody {
		return nil, errors.New("management response exceeds size limit")
	}
	return body, nil
}
