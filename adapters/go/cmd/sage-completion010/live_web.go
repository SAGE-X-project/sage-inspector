package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sage-x-project/sage/pkg/agent/crypto/jcs"
	"github.com/sage-x-project/sage/pkg/agent/registry010"
)

// This bounded adapter trusts a configured local service's mTLS inspection
// endpoint for committed history and checks it against a new public TLS read.
// It is test wiring, not a general-purpose web Registry resolver.
type liveWebAgent struct {
	Public string `json:"public"`
	Admin  string `json:"admin"`
}

type liveWebConfig struct {
	Origin        string                  `json:"origin"`
	AdminHost     string                  `json:"admin_host"`
	RootDER       string                  `json:"root_der"`
	InspectorCert string                  `json:"inspector_cert"`
	InspectorKey  string                  `json:"inspector_key"`
	Agents        map[string]liveWebAgent `json:"agents"`
}

type liveWebSource struct {
	origin    string
	adminHost string
	rootDER   []byte
	roots     *x509.CertPool
	client    tls.Certificate
	agents    map[string]struct{ public, admin netip.AddrPort }
	start     time.Time
}

func openLiveWebSource(path string) (*liveWebSource, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("live Registry configuration must be absolute")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("invalid live Registry configuration")
	}
	var cfg liveWebConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF ||
		cfg.Origin != "https://agent.example" || cfg.AdminHost != "admin.example.com" ||
		len(cfg.Agents) != 2 {
		return nil, errors.New("invalid live Registry configuration")
	}
	rootDER, err := base64.RawURLEncoding.Strict().DecodeString(cfg.RootDER)
	if err != nil || base64.RawURLEncoding.EncodeToString(rootDER) != cfg.RootDER {
		return nil, errors.New("invalid live Registry root")
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil || !root.IsCA {
		return nil, errors.New("invalid live Registry root")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if !filepath.IsAbs(cfg.InspectorCert) || !filepath.IsAbs(cfg.InspectorKey) {
		return nil, errors.New("invalid inspector certificate paths")
	}
	client, err := tls.LoadX509KeyPair(cfg.InspectorCert, cfg.InspectorKey)
	if err != nil {
		return nil, err
	}
	source := &liveWebSource{origin: cfg.Origin, adminHost: cfg.AdminHost,
		rootDER: rootDER, roots: roots, client: client,
		agents: map[string]struct{ public, admin netip.AddrPort }{}, start: time.Now()}
	for _, did := range []string{completionAlice, completionBob} {
		agent, ok := cfg.Agents[did]
		public, a := netip.ParseAddrPort(agent.Public)
		admin, b := netip.ParseAddrPort(agent.Admin)
		if !ok || a != nil || b != nil || !public.Addr().IsLoopback() || !admin.Addr().IsLoopback() {
			return nil, errors.New("invalid live Registry destinations")
		}
		source.agents[did] = struct{ public, admin netip.AddrPort }{public, admin}
	}
	return source, nil
}

func (s *liveWebSource) Now() (registry010.Stamp, error) {
	return registry010.Stamp{MonoMS: time.Since(s.start).Milliseconds(), Unix: time.Now().Unix()}, nil
}

type liveInspection struct {
	Registry   string                                    `json:"registry"`
	DID        string                                    `json:"did"`
	Version    string                                    `json:"version"`
	Grants     []registry010.WebRegistryOperatorGrant010 `json:"grants"`
	History    []registry010.WebRegistryHistoryEntry010  `json:"history"`
	Tombstoned bool                                      `json:"tombstoned"`
}

func (s *liveWebSource) inspect(ctx context.Context, destination netip.AddrPort) (liveInspection, error) {
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		MaxResponseHeaderBytes: 16384, ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{RootCAs: s.roots, Certificates: []tls.Certificate{s.client},
			ServerName: s.adminHost, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", destination.String())
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+s.adminHost+"/admin/registry/inspection", nil)
	if err != nil {
		return liveInspection{}, err
	}
	request.Close = true
	response, err := client.Do(request)
	if err != nil {
		return liveInspection{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 ||
		response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Content-Encoding") != "" || response.ContentLength < 1 ||
		response.ContentLength > 1048576 {
		return liveInspection{}, errors.New("invalid authenticated inspection response")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil || len(raw) != int(response.ContentLength) {
		return liveInspection{}, errors.New("incomplete authenticated inspection")
	}
	var state liveInspection
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF ||
		len(state.History) == 0 || len(state.History) > 256 {
		return liveInspection{}, errors.New("invalid authenticated inspection")
	}
	return state, nil
}

func (s *liveWebSource) Read(ctx context.Context, did string) (registry010.Snapshot, error) {
	destination, ok := s.agents[did]
	if !ok || ctx == nil || ctx.Err() != nil {
		return registry010.Snapshot{}, registry010.ErrUnreachable
	}
	var public []byte
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		startUnix := time.Now().Unix()
		public, err = registry010.FetchWebRegistryRecord010(ctx, did, []string{s.origin},
			destination.public, []netip.AddrPort{destination.public}, s.rootDER, startUnix)
		if err == nil || time.Now().Unix() == startUnix {
			break
		}
	}
	if err != nil {
		return registry010.Snapshot{}, err
	}
	inspection, err := s.inspect(ctx, destination.admin)
	if err != nil {
		return registry010.Snapshot{}, registry010.ErrUnreachable
	}
	if inspection.Registry != s.origin || inspection.DID != did ||
		registry010.CheckWebRegistryHistoryContinuity010(inspection.History, public, did, time.Now().Unix()) != nil {
		return registry010.Snapshot{}, registry010.ErrStale
	}
	var envelope struct {
		Record struct {
			ID      string `json:"id"`
			Version string `json:"version"`
			State   string `json:"state"`
			Keys    []struct {
				Name    string `json:"name"`
				Alg     string `json:"alg"`
				Key     string `json:"key"`
				State   string `json:"state"`
				Expires *int64 `json:"expires"`
			} `json:"keys"`
		} `json:"record"`
	}
	if json.Unmarshal(public, &envelope) != nil || envelope.Record.ID != did ||
		inspection.Version != envelope.Record.Version ||
		inspection.Tombstoned != (envelope.Record.State == "deactivated") ||
		len(inspection.History) != mustVersion010(envelope.Record.Version) {
		return registry010.Snapshot{}, registry010.ErrStale
	}
	keys := make([]registry010.Key, 0, len(envelope.Record.Keys))
	for _, key := range envelope.Record.Keys {
		material, err := base64.RawURLEncoding.Strict().DecodeString(key.Key)
		if err != nil || base64.RawURLEncoding.EncodeToString(material) != key.Key {
			return registry010.Snapshot{}, registry010.ErrRejected
		}
		keys = append(keys, registry010.Key{Name: key.Name, Alg: key.Alg,
			Material: hex.EncodeToString(material), State: key.State, Expires: key.Expires})
	}
	var rawEnvelope struct {
		Record json.RawMessage `json:"record"`
	}
	if json.Unmarshal(public, &rawEnvelope) != nil {
		return registry010.Snapshot{}, registry010.ErrRejected
	}
	canonicalRecord, err := jcs.Canonicalize(rawEnvelope.Record)
	if err != nil {
		return registry010.Snapshot{}, registry010.ErrRejected
	}
	digest := sha256.Sum256(canonicalRecord)
	stamp, err := s.Now()
	if err != nil || ctx.Err() != nil {
		return registry010.Snapshot{}, registry010.ErrUnreachable
	}
	return registry010.Snapshot{Source: s.origin, Registry: completionRegistry,
		Network: "local", DID: did, Version: envelope.Record.Version,
		State: envelope.Record.State, Digest: hex.EncodeToString(digest[:]),
		Ready: true, Validated: true, Finalized: true, AcquiredMS: stamp.MonoMS,
		Keys: keys}, nil
}

func mustVersion010(value string) int {
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || strings.HasPrefix(value, "0") {
		return -1
	}
	return int(parsed)
}
