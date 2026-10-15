package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const apiPrefix = "/_zoraxy-integrator/v1/"

func introspect() map[string]any {
	return map[string]any{
		"id": "com.github.sofyan48.zoraxy-integrator", "name": "CI/CD Integrator",
		"author": "sofyan48", "author_contact": "https://github.com/sofyan48/zoraxy-integrator",
		"description": "Token-authenticated CI/CD provisioning of managed HTTP proxy rules",
		"url":         "https://github.com/sofyan48/zoraxy-integrator", "type": 0,
		"version_major": 0, "version_minor": 1, "version_patch": 0,
		"static_capture_paths":   []map[string]string{{"capture_path": apiPrefix}},
		"static_capture_ingress": "/capture", "ui_path": "/ui",
	}
}

type backend interface {
	Apply(context.Context, Deployment) (Result, error)
	Delete(context.Context, string) (Result, error)
}

type application struct {
	client  backend
	token   [32]byte
	domains []string
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func normalizeHostname(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) > 253 || !strings.Contains(value, ".") {
		return "", errors.New("hostname must be a fully qualified DNS name")
	}
	for _, label := range strings.Split(value, ".") {
		if !hostnamePattern.MatchString(label) {
			return "", errors.New("invalid hostname")
		}
	}
	if net.ParseIP(value) != nil {
		return "", errors.New("IP hostnames are not supported")
	}
	return value, nil
}

func (a *application) allowed(host string) bool {
	for _, domain := range a.domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func validateUpstream(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return errors.New("upstream must be http(s)://host:port without credentials, path, query or fragment")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || host == "" {
		return errors.New("upstream requires an explicit host and port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("invalid upstream port")
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(strings.ToLower(host), ".") {
			if !hostnamePattern.MatchString(label) {
				return errors.New("invalid upstream hostname")
			}
		}
	}
	return nil
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	digest := sha256.Sum256([]byte(supplied))
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(digest[:], a.token[:]) != 1 {
		w.Header().Set("WWW-Authenticate", "Bearer")
		respond(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	if r.URL.Path == apiPrefix+"health" && r.Method == http.MethodGet {
		respond(w, 200, map[string]string{"status": "ok"})
		return
	}
	if r.URL.Path != apiPrefix+"proxies" {
		respond(w, 404, map[string]string{"error": "not found"})
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "PUT, DELETE")
		respond(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		respond(w, 415, map[string]string{"error": "Content-Type must be application/json"})
		return
	}
	var d Deployment
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		respond(w, 400, map[string]string{"error": "invalid JSON payload"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		respond(w, 400, map[string]string{"error": "expected one JSON object"})
		return
	}
	host, err := normalizeHostname(d.Hostname)
	if err != nil {
		respond(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if !a.allowed(host) {
		respond(w, 403, map[string]string{"error": "hostname outside allowed domains"})
		return
	}
	d.Hostname = host
	if r.Method == http.MethodPut {
		if err = validateUpstream(d.Upstream); err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
	} else if d.Upstream != "" {
		respond(w, 400, map[string]string{"error": "DELETE accepts hostname only"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	var result Result
	if r.Method == http.MethodPut {
		result, err = a.client.Apply(ctx, d)
	} else {
		result, err = a.client.Delete(ctx, host)
	}
	if err != nil {
		log.Printf("operation failed for %s: %v", host, err)
		respond(w, 502, map[string]string{"error": "Zoraxy operation failed; check integrator logs and current rule state before retrying"})
		return
	}
	log.Printf("proxy %s: %s", result.Action, host)
	status := 200
	if result.Action == "created" {
		status = 201
	}
	respond(w, status, result)
}

func run() error {
	intro := flag.Bool("introspect", false, "print Zoraxy plugin metadata")
	configure := flag.String("configure", "", "Zoraxy runtime JSON")
	listen := flag.String("listen", "127.0.0.1:9080", "standalone listener")
	configFile := flag.String("config", "integrator.json", "configuration file")
	flag.Parse()
	if *intro {
		return json.NewEncoder(os.Stdout).Encode(introspect())
	}
	// Zoraxy inherits environment variables; a local JSON file is also supported.
	var cfg struct {
		BaseURL  string   `json:"zoraxy_url"`
		Username string   `json:"zoraxy_username"`
		Password string   `json:"zoraxy_password"`
		Token    string   `json:"token"`
		Domains  []string `json:"allowed_domains"`
	}
	if data, err := os.ReadFile(*configFile); err == nil {
		if err = json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("invalid config file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, pair := range []struct {
		key    string
		target *string
	}{{"ZORAXY_URL", &cfg.BaseURL}, {"ZORAXY_USERNAME", &cfg.Username}, {"ZORAXY_PASSWORD", &cfg.Password}, {"INTEGRATOR_TOKEN", &cfg.Token}} {
		if value, ok := os.LookupEnv(pair.key); ok {
			*pair.target = value
		}
	}
	if domains, ok := os.LookupEnv("INTEGRATOR_ALLOWED_DOMAINS"); ok {
		cfg.Domains = strings.Split(domains, ",")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://127.0.0.1:8000"
	}
	if len(cfg.Token) < 32 {
		return errors.New("INTEGRATOR_TOKEN / token must contain at least 32 characters")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return errors.New("Zoraxy username and password are required")
	}
	if len(cfg.Domains) == 0 {
		return errors.New("allowed_domains must not be empty")
	}
	for i, d := range cfg.Domains {
		host, err := normalizeHostname(d)
		if err != nil {
			return fmt.Errorf("invalid allowed domain: %w", err)
		}
		cfg.Domains[i] = host
	}
	if *configure != "" {
		var spec struct {
			Port int `json:"port"`
		}
		if err := json.Unmarshal([]byte(*configure), &spec); err != nil {
			return err
		}
		if spec.Port < 1 || spec.Port > 65535 {
			return errors.New("invalid plugin port")
		}
		*listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(spec.Port))
	}
	client, err := NewZoraxyClient(cfg.BaseURL, cfg.Username, cfg.Password)
	if err != nil {
		return err
	}
	app := &application{client: client, token: sha256.Sum256([]byte(cfg.Token)), domains: cfg.Domains}
	mux := http.NewServeMux()
	mux.Handle(apiPrefix, app)
	mux.HandleFunc("/capture/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Zoraxy-Capture") != apiPrefix {
			http.NotFound(w, r)
			return
		}
		original, err := url.ParseRequestURI(r.Header.Get("X-Zoraxy-Uri"))
		if err != nil || !strings.HasPrefix(original.Path, apiPrefix) {
			http.NotFound(w, r)
			return
		}
		r.URL.Path = original.Path
		r.URL.RawQuery = original.RawQuery
		app.ServeHTTP(w, r)
	})
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "CI/CD Integrator 0.1.0\nAPI: PUT /_zoraxy-integrator/v1/proxies\nConfiguration: integrator.json or environment variables. See README.\n")
	})
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("integrator listening on %s", *listen)
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
