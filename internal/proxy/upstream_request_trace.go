package proxy

import (
	"net/http/httptrace"
	"sync/atomic"
)

// upstreamRequestTrace captures request-progress milestones reported by
// net/http transport so request-log egress bytes can be committed only when
// the request has actually been written to upstream.
type upstreamRequestTrace struct {
	gotConn      atomic.Bool
	wroteRequest atomic.Bool
}

func newUpstreamRequestTrace() *upstreamRequestTrace {
	return &upstreamRequestTrace{}
}

func (t *upstreamRequestTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			t.gotConn.Store(true)
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			// Only mark as written when transport reports write success.
			// WroteRequest can also fire with Err!=nil for failed write attempts.
			if info.Err == nil {
				t.wroteRequest.Store(true)
			}
		},
	}
}

func (t *upstreamRequestTrace) shouldCommitEgress() bool {
	return t.gotConn.Load() && t.wroteRequest.Load()
}
