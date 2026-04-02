package outbound

import (
	"context"
	"errors"
	"fmt"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

const (
	localDNSTransportTag = "local"

	secureDNSDoHPubTransportTag    = "resin-doh-pub"
	secureDNSAliDoHTransportTag    = "resin-doh-alidns"
	secureDNSAliDoTTransportTag    = "resin-dot-alidns"
	secureDNSFailoverTransportTag  = "resin-secure-dns"
	secureDNSFailoverTransportType = "resin-sequential-failover"
	secureDNSAliDoTServerAddress   = "223.5.5.5"
	secureDNSAliDoTTLSServerName   = "dns.alidns.com"
	secureDNSDoHPubServerAddress   = "doh.pub"
	secureDNSAliDoHServerAddress   = "dns.alidns.com"
	secureDNSQueryPath             = "/dns-query"
)

type secureDNSTransportSpec struct {
	tag           string
	transportType string
	options       any
}

type secureDNSFailoverOptions struct {
	Upstreams []string `json:"upstreams,omitempty"`
}

type secureDNSFailoverTransport struct {
	manager      adapter.DNSTransportManager
	tag          string
	upstreamTags []string
}

func registerSecureDNSTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[secureDNSFailoverOptions](registry, secureDNSFailoverTransportType, newSecureDNSFailoverTransport)
}

func secureDNSTransportSpecs() []secureDNSTransportSpec {
	return []secureDNSTransportSpec{
		{
			tag:           localDNSTransportTag,
			transportType: C.DNSTypeLocal,
			options:       &option.LocalDNSServerOptions{},
		},
		{
			tag:           secureDNSDoHPubTransportTag,
			transportType: C.DNSTypeHTTPS,
			options: &option.RemoteHTTPSDNSServerOptions{
				RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
					RemoteDNSServerOptions: option.RemoteDNSServerOptions{
						LocalDNSServerOptions: option.LocalDNSServerOptions{
							DialerOptions: option.DialerOptions{
								DomainResolver: &option.DomainResolveOptions{
									Server: localDNSTransportTag,
								},
							},
						},
						DNSServerAddressOptions: option.DNSServerAddressOptions{
							Server: secureDNSDoHPubServerAddress,
						},
					},
				},
				Path: secureDNSQueryPath,
			},
		},
		{
			tag:           secureDNSAliDoHTransportTag,
			transportType: C.DNSTypeHTTPS,
			options: &option.RemoteHTTPSDNSServerOptions{
				RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
					RemoteDNSServerOptions: option.RemoteDNSServerOptions{
						LocalDNSServerOptions: option.LocalDNSServerOptions{
							DialerOptions: option.DialerOptions{
								DomainResolver: &option.DomainResolveOptions{
									Server: localDNSTransportTag,
								},
							},
						},
						DNSServerAddressOptions: option.DNSServerAddressOptions{
							Server: secureDNSAliDoHServerAddress,
						},
					},
				},
				Path: secureDNSQueryPath,
			},
		},
		{
			tag:           secureDNSAliDoTTransportTag,
			transportType: C.DNSTypeTLS,
			options: &option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: option.RemoteDNSServerOptions{
					DNSServerAddressOptions: option.DNSServerAddressOptions{
						Server: secureDNSAliDoTServerAddress,
					},
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{
						ServerName: secureDNSAliDoTTLSServerName,
					},
				},
			},
		},
		{
			tag:           secureDNSFailoverTransportTag,
			transportType: secureDNSFailoverTransportType,
			options: &secureDNSFailoverOptions{
				Upstreams: []string{
					secureDNSDoHPubTransportTag,
					secureDNSAliDoHTransportTag,
					secureDNSAliDoTTransportTag,
					localDNSTransportTag,
				},
			},
		},
	}
}

func newSecureDNSFailoverTransport(
	ctx context.Context,
	_ log.ContextLogger,
	tag string,
	options secureDNSFailoverOptions,
) (adapter.DNSTransport, error) {
	manager := service.FromContext[adapter.DNSTransportManager](ctx)
	if manager == nil {
		return nil, fmt.Errorf("secure dns transport: missing DNS transport manager")
	}
	if len(options.Upstreams) == 0 {
		return nil, fmt.Errorf("secure dns transport: no upstreams configured")
	}
	return &secureDNSFailoverTransport{
		manager:      manager,
		tag:          tag,
		upstreamTags: append([]string(nil), options.Upstreams...),
	}, nil
}

func (t *secureDNSFailoverTransport) Type() string {
	return secureDNSFailoverTransportType
}

func (t *secureDNSFailoverTransport) Tag() string {
	return t.tag
}

func (t *secureDNSFailoverTransport) Dependencies() []string {
	return append([]string(nil), t.upstreamTags...)
}

func (t *secureDNSFailoverTransport) Start(stage adapter.StartStage) error {
	return nil
}

func (t *secureDNSFailoverTransport) Close() error {
	return nil
}

func (t *secureDNSFailoverTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(t.upstreamTags) == 0 {
		return nil, fmt.Errorf("secure dns transport: no upstreams configured")
	}

	queryName := "<empty query>"
	if len(message.Question) > 0 {
		queryName = message.Question[0].Name
	}

	var attemptErrs []error
	for _, upstreamTag := range t.upstreamTags {
		upstream, ok := t.manager.Transport(upstreamTag)
		if !ok || upstream == nil {
			attemptErrs = append(attemptErrs, fmt.Errorf("%s: transport not found", upstreamTag))
			continue
		}

		response, err := upstream.Exchange(ctx, message.Copy())
		if err == nil && shouldAcceptSecureDNSResponse(response) {
			return response, nil
		}
		if err == nil {
			if response == nil {
				err = errors.New("empty response")
			} else {
				err = dns.RcodeError(response.Rcode)
			}
		}
		attemptErrs = append(attemptErrs, fmt.Errorf("%s: %w", upstreamTag, err))
	}

	return nil, fmt.Errorf("secure DNS exchange failed for %s: %w", queryName, errors.Join(attemptErrs...))
}

func shouldAcceptSecureDNSResponse(response *mDNS.Msg) bool {
	if response == nil {
		return false
	}
	return response.Rcode == mDNS.RcodeSuccess
}
