package llmclient

import (
	"net/http"
	"strings"
)

type Session struct {
	ConversationID string
}

type Option func(*Session)

func NewSession(opts ...Option) Session {
	s := Session{}
	for _, opt := range opts {
		if opt != nil {
			opt(&s)
		}
	}
	s.ConversationID = strings.TrimSpace(s.ConversationID)
	return s
}

func WithConversationID(id string) Option {
	cid := strings.TrimSpace(id)
	return func(s *Session) {
		s.ConversationID = cid
	}
}

func (s Session) WrapRoundTripper(base http.RoundTripper) http.RoundTripper {
	return conversationHeaderRoundTripper{
		Base:           base,
		ConversationID: strings.TrimSpace(s.ConversationID),
	}
}

type conversationHeaderRoundTripper struct {
	Base           http.RoundTripper
	ConversationID string
}

func (rt conversationHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := rt.Base
	if base == nil {
		base = http.DefaultTransport
	}
	out := req.Clone(req.Context())
	out.Header = req.Header.Clone()
	if cid := strings.TrimSpace(rt.ConversationID); cid != "" {
		out.Header.Set("X-Conversation-ID", cid)
	}
	return base.RoundTrip(out)
}
