package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Resinat/Resin/internal/testutil"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// SingboxBuilder constructor / teardown
// ---------------------------------------------------------------------------

func TestNewSingboxBuilder(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("SingboxBuilder.Close() error: %v", err)
	}
}

func TestNewSingboxBuilder_ConfiguresSecureDNSChain(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	defaultTransport := b.dnsTransportManager.Default()
	if defaultTransport == nil {
		t.Fatal("expected default DNS transport")
	}
	if defaultTransport.Tag() != secureDNSFailoverTransportTag {
		t.Fatalf("default DNS transport: got %q, want %q", defaultTransport.Tag(), secureDNSFailoverTransportTag)
	}

	for _, tag := range []string{
		localDNSTransportTag,
		secureDNSDoHPubTransportTag,
		secureDNSAliDoHTransportTag,
		secureDNSAliDoTTransportTag,
		secureDNSFailoverTransportTag,
	} {
		transport, ok := b.dnsTransportManager.Transport(tag)
		if !ok || transport == nil {
			t.Fatalf("expected DNS transport %q to be registered", tag)
		}
	}

	dohPub, _ := b.dnsTransportManager.Transport(secureDNSDoHPubTransportTag)
	if got := dohPub.Dependencies(); len(got) != 1 || got[0] != localDNSTransportTag {
		t.Fatalf("DoH pub dependencies: got %v, want [%s]", got, localDNSTransportTag)
	}

	aliDoH, _ := b.dnsTransportManager.Transport(secureDNSAliDoHTransportTag)
	if got := aliDoH.Dependencies(); len(got) != 1 || got[0] != localDNSTransportTag {
		t.Fatalf("AliDNS DoH dependencies: got %v, want [%s]", got, localDNSTransportTag)
	}

	failover, _ := b.dnsTransportManager.Transport(secureDNSFailoverTransportTag)
	wantFailoverDeps := []string{
		secureDNSDoHPubTransportTag,
		secureDNSAliDoHTransportTag,
		secureDNSAliDoTTransportTag,
		localDNSTransportTag,
	}
	if got := failover.Dependencies(); !equalStrings(got, wantFailoverDeps) {
		t.Fatalf("secure DNS dependencies: got %v, want %v", got, wantFailoverDeps)
	}
}

func TestSecureDNSTransportSpecs(t *testing.T) {
	specs := secureDNSTransportSpecs()
	if len(specs) != 5 {
		t.Fatalf("secureDNSTransportSpecs length: got %d, want 5", len(specs))
	}

	specByTag := make(map[string]secureDNSTransportSpec, len(specs))
	for _, spec := range specs {
		specByTag[spec.tag] = spec
	}

	dohPubSpec, ok := specByTag[secureDNSDoHPubTransportTag]
	if !ok {
		t.Fatalf("missing spec for %q", secureDNSDoHPubTransportTag)
	}
	dohPubOptions, ok := dohPubSpec.options.(*option.RemoteHTTPSDNSServerOptions)
	if !ok {
		t.Fatalf("DoH pub options type: got %T", dohPubSpec.options)
	}
	if dohPubOptions.Path != secureDNSQueryPath {
		t.Fatalf("DoH pub path: got %q, want %q", dohPubOptions.Path, secureDNSQueryPath)
	}
	if dohPubOptions.DomainResolver == nil || dohPubOptions.DomainResolver.Server != localDNSTransportTag {
		t.Fatalf("DoH pub bootstrap resolver: got %+v, want %q", dohPubOptions.DomainResolver, localDNSTransportTag)
	}

	aliDoTSpec, ok := specByTag[secureDNSAliDoTTransportTag]
	if !ok {
		t.Fatalf("missing spec for %q", secureDNSAliDoTTransportTag)
	}
	aliDoTOptions, ok := aliDoTSpec.options.(*option.RemoteTLSDNSServerOptions)
	if !ok {
		t.Fatalf("AliDNS DoT options type: got %T", aliDoTSpec.options)
	}
	if aliDoTOptions.Server != secureDNSAliDoTServerAddress {
		t.Fatalf("AliDNS DoT server: got %q, want %q", aliDoTOptions.Server, secureDNSAliDoTServerAddress)
	}
	if aliDoTOptions.TLS == nil || aliDoTOptions.TLS.ServerName != secureDNSAliDoTTLSServerName {
		t.Fatalf("AliDNS DoT TLS server_name: got %+v, want %q", aliDoTOptions.TLS, secureDNSAliDoTTLSServerName)
	}

	failoverSpec, ok := specByTag[secureDNSFailoverTransportTag]
	if !ok {
		t.Fatalf("missing spec for %q", secureDNSFailoverTransportTag)
	}
	failoverOptions, ok := failoverSpec.options.(*secureDNSFailoverOptions)
	if !ok {
		t.Fatalf("secure DNS failover options type: got %T", failoverSpec.options)
	}
	wantUpstreams := []string{
		secureDNSDoHPubTransportTag,
		secureDNSAliDoHTransportTag,
		secureDNSAliDoTTransportTag,
		localDNSTransportTag,
	}
	if !equalStrings(failoverOptions.Upstreams, wantUpstreams) {
		t.Fatalf("secure DNS upstreams: got %v, want %v", failoverOptions.Upstreams, wantUpstreams)
	}
}

func TestSecureDNSFailoverTransport_FirstSuccessSkipsFallbacks(t *testing.T) {
	first := newStaticDNSTransport("first", successDNSResponse("first.example."))
	second := newStaticDNSTransport("second", successDNSResponse("second.example."))
	manager := &stubDNSTransportManager{
		transports: map[string]adapter.DNSTransport{
			"first":  first,
			"second": second,
		},
	}
	transport := &secureDNSFailoverTransport{
		manager:      manager,
		tag:          secureDNSFailoverTransportTag,
		upstreamTags: []string{"first", "second"},
	}

	resp, err := transport.Exchange(context.Background(), dnsQuestion("example.com."))
	if err != nil {
		t.Fatalf("Exchange() error: %v", err)
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected DNS answer")
	}
	if first.calls.Load() != 1 {
		t.Fatalf("first transport calls: got %d, want 1", first.calls.Load())
	}
	if second.calls.Load() != 0 {
		t.Fatalf("second transport calls: got %d, want 0", second.calls.Load())
	}
}

func TestSecureDNSFailoverTransport_RcodeFailureFallsBack(t *testing.T) {
	manager := &stubDNSTransportManager{
		transports: map[string]adapter.DNSTransport{
			secureDNSDoHPubTransportTag: newStaticDNSTransport(secureDNSDoHPubTransportTag, rcodeDNSResponse(mDNS.RcodeServerFailure)),
			localDNSTransportTag:        newStaticDNSTransport(localDNSTransportTag, successDNSResponse("local.example.")),
		},
	}
	transport := &secureDNSFailoverTransport{
		manager:      manager,
		tag:          secureDNSFailoverTransportTag,
		upstreamTags: []string{secureDNSDoHPubTransportTag, localDNSTransportTag},
	}

	resp, err := transport.Exchange(context.Background(), dnsQuestion("example.com."))
	if err != nil {
		t.Fatalf("Exchange() error: %v", err)
	}
	if resp == nil || resp.Rcode != mDNS.RcodeSuccess {
		t.Fatalf("response rcode: got %+v, want success", resp)
	}
	first, _ := manager.Transport(secureDNSDoHPubTransportTag)
	second, _ := manager.Transport(localDNSTransportTag)
	if first.(*staticDNSTransport).calls.Load() != 1 {
		t.Fatalf("first transport calls: got %d, want 1", first.(*staticDNSTransport).calls.Load())
	}
	if second.(*staticDNSTransport).calls.Load() != 1 {
		t.Fatalf("local transport calls: got %d, want 1", second.(*staticDNSTransport).calls.Load())
	}
}

func TestSecureDNSFailoverTransport_NameErrorFallsBack(t *testing.T) {
	manager := &stubDNSTransportManager{
		transports: map[string]adapter.DNSTransport{
			secureDNSDoHPubTransportTag: newStaticDNSTransport(secureDNSDoHPubTransportTag, rcodeDNSResponse(mDNS.RcodeNameError)),
			localDNSTransportTag:        newStaticDNSTransport(localDNSTransportTag, successDNSResponse("local.example.")),
		},
	}
	transport := &secureDNSFailoverTransport{
		manager:      manager,
		tag:          secureDNSFailoverTransportTag,
		upstreamTags: []string{secureDNSDoHPubTransportTag, localDNSTransportTag},
	}

	resp, err := transport.Exchange(context.Background(), dnsQuestion("example.com."))
	if err != nil {
		t.Fatalf("Exchange() error: %v", err)
	}
	if resp == nil || resp.Rcode != mDNS.RcodeSuccess {
		t.Fatalf("response rcode: got %+v, want success", resp)
	}
	first, _ := manager.Transport(secureDNSDoHPubTransportTag)
	second, _ := manager.Transport(localDNSTransportTag)
	if first.(*staticDNSTransport).calls.Load() != 1 {
		t.Fatalf("first transport calls: got %d, want 1", first.(*staticDNSTransport).calls.Load())
	}
	if second.(*staticDNSTransport).calls.Load() != 1 {
		t.Fatalf("local transport calls: got %d, want 1", second.(*staticDNSTransport).calls.Load())
	}
}

func TestSecureDNSFailoverTransport_AllUpstreamsFail(t *testing.T) {
	manager := &stubDNSTransportManager{
		transports: map[string]adapter.DNSTransport{
			secureDNSDoHPubTransportTag: newErrorDNSTransport(secureDNSDoHPubTransportTag, errors.New("doh.pub down")),
			secureDNSAliDoHTransportTag: newErrorDNSTransport(secureDNSAliDoHTransportTag, errors.New("alidns doh down")),
			secureDNSAliDoTTransportTag: newErrorDNSTransport(secureDNSAliDoTTransportTag, errors.New("alidns dot down")),
			localDNSTransportTag:        newErrorDNSTransport(localDNSTransportTag, errors.New("local down")),
		},
	}
	transport := &secureDNSFailoverTransport{
		manager:      manager,
		tag:          secureDNSFailoverTransportTag,
		upstreamTags: []string{secureDNSDoHPubTransportTag, secureDNSAliDoHTransportTag, secureDNSAliDoTTransportTag, localDNSTransportTag},
	}

	_, err := transport.Exchange(context.Background(), dnsQuestion("example.com."))
	if err == nil {
		t.Fatal("expected error when all upstreams fail")
	}
	for _, part := range []string{
		secureDNSDoHPubTransportTag,
		secureDNSAliDoHTransportTag,
		secureDNSAliDoTTransportTag,
		localDNSTransportTag,
	} {
		if !strings.Contains(err.Error(), part) {
			t.Fatalf("error %q does not contain %q", err, part)
		}
	}
}

// ---------------------------------------------------------------------------
// Build: parse and create real outbound
// ---------------------------------------------------------------------------

func TestSingboxBuilder_ParseShadowsocks(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	raw := json.RawMessage(`{
		"type": "shadowsocks",
		"tag":  "test-ss",
		"server": "127.0.0.1",
		"server_port": 8388,
		"method": "aes-256-gcm",
		"password": "test-password"
	}`)
	ob, err := b.Build(raw)
	if err != nil {
		t.Fatalf("Build(shadowsocks) error: %v", err)
	}

	// Should implement io.Closer (sing-box outbounds do)
	closer, ok := ob.(io.Closer)
	if !ok {
		t.Fatal("expected outbound to implement io.Closer")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("outbound Close() error: %v", err)
	}
}

func TestSingboxBuilder_ParseExtendedProtocols(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	cases := []struct {
		name               string
		raw                json.RawMessage
		missingFeatureHint string
	}{
		{
			name: "socks",
			raw: json.RawMessage(`{
				"type":"socks",
				"tag":"test-socks",
				"server":"127.0.0.1",
				"server_port":1080,
				"version":"5",
				"username":"user",
				"password":"pass"
			}`),
		},
		{
			name: "http",
			raw: json.RawMessage(`{
				"type":"http",
				"tag":"test-http",
				"server":"127.0.0.1",
				"server_port":8080,
				"username":"user",
				"password":"pass"
			}`),
		},
		{
			name: "wireguard",
			raw: json.RawMessage(`{
				"type":"wireguard",
				"tag":"test-wg",
				"server":"127.0.0.1",
				"server_port":2480,
				"local_address":["172.16.0.2/32","fd01::1/128"],
				"private_key":"eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
				"peer_public_key":"Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo="
			}`),
			missingFeatureHint: "WireGuard is not included in this build",
		},
		{
			name: "hysteria",
			raw: json.RawMessage(`{
				"type":"hysteria",
				"tag":"test-hysteria",
				"server":"127.0.0.1",
				"server_port":443,
				"auth_str":"password",
				"up_mbps":30,
				"down_mbps":200,
				"tls":{"enabled":true,"insecure":true,"server_name":"example.com"}
			}`),
			missingFeatureHint: "QUIC is not included in this build",
		},
		{
			name: "tuic",
			raw: json.RawMessage(`{
				"type":"tuic",
				"tag":"test-tuic",
				"server":"127.0.0.1",
				"server_port":443,
				"uuid":"00000000-0000-0000-0000-000000000001",
				"password":"password",
				"tls":{"enabled":true,"insecure":true,"server_name":"example.com"}
			}`),
			missingFeatureHint: "QUIC is not included in this build",
		},
		{
			name: "anytls",
			raw: json.RawMessage(`{
				"type":"anytls",
				"tag":"test-anytls",
				"server":"127.0.0.1",
				"server_port":443,
				"password":"password",
				"tls":{"enabled":true,"insecure":true,"server_name":"example.com"}
			}`),
		},
		{
			name: "ssh",
			raw: json.RawMessage(`{
				"type":"ssh",
				"tag":"test-ssh",
				"server":"127.0.0.1",
				"server_port":22,
				"user":"root",
				"password":"password"
			}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ob, err := b.Build(tc.raw)
			if err != nil {
				if tc.missingFeatureHint != "" && strings.Contains(err.Error(), tc.missingFeatureHint) {
					t.Skipf("skipping %s: %v", tc.name, err)
					return
				}
				t.Fatalf("Build(%s) error: %v", tc.name, err)
			}
			if ob == nil {
				t.Fatalf("Build(%s) returned nil outbound", tc.name)
			}
			if closer, ok := ob.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Fatalf("Build(%s) outbound Close() error: %v", tc.name, err)
				}
			}
		})
	}
}

func TestSingboxBuilder_ParseDomainServerProtocols(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	cases := []struct {
		name               string
		raw                json.RawMessage
		missingFeatureHint string
	}{
		{
			name: "socks-domain",
			raw: json.RawMessage(`{
				"type":"socks",
				"tag":"test-socks-domain",
				"server":"proxy.example.com",
				"server_port":1080,
				"version":"5"
			}`),
		},
		{
			name: "anytls-domain",
			raw: json.RawMessage(`{
				"type":"anytls",
				"tag":"test-anytls-domain",
				"server":"edge.example.com",
				"server_port":443,
				"password":"password",
				"tls":{"enabled":true,"insecure":true,"server_name":"edge.example.com"}
			}`),
		},
		{
			name: "wireguard-domain",
			raw: json.RawMessage(`{
				"type":"wireguard",
				"tag":"test-wg-domain",
				"server":"wg.example.com",
				"server_port":2480,
				"local_address":["172.16.0.2/32","fd01::1/128"],
				"private_key":"eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
				"peer_public_key":"Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo="
			}`),
			missingFeatureHint: "WireGuard is not included in this build",
		},
		{
			name: "ssh-domain",
			raw: json.RawMessage(`{
				"type":"ssh",
				"tag":"test-ssh-domain",
				"server":"ssh.example.com",
				"server_port":22,
				"user":"root",
				"password":"password"
			}`),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ob, err := b.Build(tc.raw)
			if err != nil {
				if tc.missingFeatureHint != "" && strings.Contains(err.Error(), tc.missingFeatureHint) {
					t.Skipf("skipping %s: %v", tc.name, err)
					return
				}
				t.Fatalf("Build(%s) error: %v", tc.name, err)
			}
			if ob == nil {
				t.Fatalf("Build(%s) returned nil outbound", tc.name)
			}
			if closer, ok := ob.(io.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Fatalf("Build(%s) outbound Close() error: %v", tc.name, err)
				}
			}
		})
	}
}

func TestSingboxBuilder_UnknownType(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	raw := json.RawMessage(`{"type": "totally-fake-protocol-xyz", "tag": "x"}`)
	_, err = b.Build(raw)
	if err == nil {
		t.Fatal("expected error for unknown outbound type, got nil")
	}
}

func TestSingboxBuilder_InvalidJSON(t *testing.T) {
	b, err := NewSingboxBuilder()
	if err != nil {
		t.Fatalf("NewSingboxBuilder() error: %v", err)
	}
	defer b.Close()

	raw := json.RawMessage(`{invalid`)
	_, err = b.Build(raw)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestStubOutboundBuilder_Build(t *testing.T) {
	ob, err := (&testutil.StubOutboundBuilder{}).Build(nil)
	if err != nil {
		t.Fatalf("StubOutboundBuilder.Build() error: %v", err)
	}
	if ob == nil {
		t.Fatal("expected non-nil outbound")
	}
	if ob.Type() != "stub" {
		t.Fatalf("unexpected outbound type: %s", ob.Type())
	}
}

type staticDNSTransport struct {
	tag      string
	response *mDNS.Msg
	err      error
	calls    atomic.Int32
}

func newStaticDNSTransport(tag string, response *mDNS.Msg) *staticDNSTransport {
	return &staticDNSTransport{tag: tag, response: response}
}

func newErrorDNSTransport(tag string, err error) *staticDNSTransport {
	return &staticDNSTransport{tag: tag, err: err}
}

func (t *staticDNSTransport) Type() string {
	return "stub"
}

func (t *staticDNSTransport) Tag() string {
	return t.tag
}

func (t *staticDNSTransport) Dependencies() []string {
	return nil
}

func (t *staticDNSTransport) Start(stage adapter.StartStage) error {
	return nil
}

func (t *staticDNSTransport) Close() error {
	return nil
}

func (t *staticDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	t.calls.Add(1)
	if t.err != nil {
		return nil, t.err
	}
	return t.response.Copy(), nil
}

type stubDNSTransportManager struct {
	transports map[string]adapter.DNSTransport
}

func (m *stubDNSTransportManager) Start(stage adapter.StartStage) error {
	return nil
}

func (m *stubDNSTransportManager) Close() error {
	return nil
}

func (m *stubDNSTransportManager) Transports() []adapter.DNSTransport {
	list := make([]adapter.DNSTransport, 0, len(m.transports))
	for _, transport := range m.transports {
		list = append(list, transport)
	}
	return list
}

func (m *stubDNSTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, ok := m.transports[tag]
	return transport, ok
}

func (m *stubDNSTransportManager) Default() adapter.DNSTransport {
	return nil
}

func (m *stubDNSTransportManager) FakeIP() adapter.FakeIPTransport {
	return nil
}

func (m *stubDNSTransportManager) Remove(tag string) error {
	delete(m.transports, tag)
	return nil
}

func (m *stubDNSTransportManager) Create(ctx context.Context, logger log.ContextLogger, tag string, outboundType string, options any) error {
	return errors.New("not implemented")
}

func successDNSResponse(answerName string) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Response: true,
		},
		Answer: []mDNS.RR{
			&mDNS.A{
				Hdr: mDNS.RR_Header{
					Name:   answerName,
					Rrtype: mDNS.TypeA,
					Class:  mDNS.ClassINET,
					Ttl:    60,
				},
				A: net.IPv4(1, 1, 1, 1),
			},
		},
	}
}

func rcodeDNSResponse(rcode int) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Response: true,
			Rcode:    rcode,
		},
	}
}

func dnsQuestion(name string) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			RecursionDesired: true,
		},
		Question: []mDNS.Question{{
			Name:   name,
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		}},
	}
}

func equalStrings(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// CAS loser close
// ---------------------------------------------------------------------------

// closableBuilder builds closable outbounds that track Close() calls.
type closableBuilder struct {
	mu    sync.Mutex
	built []*trackCloser
}

type trackCloser struct {
	closed atomic.Bool
}

func (c *trackCloser) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *trackCloser) Type() string {
	return "track-closer"
}

func (c *trackCloser) Tag() string {
	return "track-closer"
}

func (c *trackCloser) Network() []string {
	return []string{"tcp", "udp"}
}

func (c *trackCloser) Dependencies() []string {
	return nil
}

func (c *trackCloser) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("track-closer: dial not supported")
}

func (c *trackCloser) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("track-closer: listen packet not supported")
}

func (b *closableBuilder) Build(_ json.RawMessage) (adapter.Outbound, error) {
	tc := &trackCloser{}
	b.mu.Lock()
	b.built = append(b.built, tc)
	b.mu.Unlock()
	return tc, nil
}

func TestEnsureNodeOutbound_CASLoserClose(t *testing.T) {
	entry := newTestEntry(`{"type":"test"}`)
	pool := &mockPool{}
	pool.addEntry(entry)

	cb := &closableBuilder{}
	mgr := NewOutboundManager(pool, cb)

	// Run many concurrent EnsureNodeOutbound calls. Only the CAS winner's
	// outbound survives; all losers must be closed.
	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			mgr.EnsureNodeOutbound(entry.Hash)
		}()
	}
	wg.Wait()

	if entry.Outbound.Load() == nil {
		t.Fatal("expected outbound to be set")
	}

	cb.mu.Lock()
	total := len(cb.built)
	closedCount := 0
	for _, tc := range cb.built {
		if tc.closed.Load() {
			closedCount++
		}
	}
	cb.mu.Unlock()

	// With N concurrent goroutines, some pass the fast-path nil check before
	// the winner's CAS succeeds. Those losers must all be closed.
	if total > 1 && closedCount != total-1 {
		t.Errorf("expected %d closed outbounds, got %d (total built: %d)", total-1, closedCount, total)
	}
}

// ---------------------------------------------------------------------------
// Remove close
// ---------------------------------------------------------------------------

func TestRemoveNodeOutbound_Closes(t *testing.T) {
	tc := &trackCloser{}
	entry := newTestEntry(`{"type":"test"}`)
	var wrapped adapter.Outbound = tc
	entry.Outbound.Store(&wrapped)

	pool := &mockPool{}
	mgr := NewOutboundManager(pool, &testutil.StubOutboundBuilder{})

	mgr.RemoveNodeOutbound(entry)

	if !tc.closed.Load() {
		t.Fatal("expected outbound to be closed after RemoveNodeOutbound")
	}
	if entry.Outbound.Load() != nil {
		t.Fatal("expected outbound to be nil after RemoveNodeOutbound")
	}
}
