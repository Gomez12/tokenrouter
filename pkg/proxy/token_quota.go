package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lkarlslund/tokenrouter/pkg/config"
)

var (
	errQuotaExceeded     = errors.New("quota exceeded")
	errOwnerTokenMissing = errors.New("owner token missing")
)

type quotaMetricView struct {
	Limit        int64
	Remaining    int64
	ResetAt      string
	ResetSeconds int64
}

type keyQuotaView struct {
	Requests *quotaMetricView
	Tokens   *quotaMetricView
}

func (q keyQuotaView) HasAny() bool {
	return q.Requests != nil || q.Tokens != nil
}

func (q keyQuotaView) JSONValue() map[string]any {
	out := map[string]any{}
	if q.Requests != nil {
		out["requests"] = quotaMetricJSONValue(q.Requests)
	}
	if q.Tokens != nil {
		out["tokens"] = quotaMetricJSONValue(q.Tokens)
	}
	return out
}

func quotaMetricJSONValue(m *quotaMetricView) map[string]any {
	if m == nil {
		return nil
	}
	out := map[string]any{
		"limit":     m.Limit,
		"remaining": m.Remaining,
	}
	if strings.TrimSpace(m.ResetAt) != "" {
		out["reset_at"] = strings.TrimSpace(m.ResetAt)
	}
	if m.ResetSeconds > 0 {
		out["reset_seconds"] = m.ResetSeconds
	}
	return out
}

func (s *Server) reserveRequestQuota(identity tokenAuthIdentity) (keyQuotaView, bool, error) {
	if s == nil || s.store == nil || strings.TrimSpace(identity.Token.ID) == "" {
		return keyQuotaView{}, false, nil
	}
	snap := s.store.Snapshot()
	ownerSnap, err := resolveOwnerTokenFromSnapshot(snap.IncomingTokens, identity)
	if err != nil {
		return keyQuotaView{}, false, err
	}
	if ownerSnap.Quota == nil || (ownerSnap.Quota.Requests == nil && ownerSnap.Quota.Tokens == nil) {
		return keyQuotaView{}, false, nil
	}
	now := nowUTC()
	view := keyQuotaView{}
	metered := false
	err = s.store.Update(func(c *config.ServerConfig) error {
		owner, err := resolveOwnerTokenForMutation(c, identity)
		if err != nil {
			return err
		}
		if owner.Quota == nil || (owner.Quota.Requests == nil && owner.Quota.Tokens == nil) {
			return nil
		}
		metered = true
		if owner.Quota.Requests != nil {
			refreshQuotaWindow(owner.Quota.Requests, now)
			if owner.Quota.Requests.Used >= owner.Quota.Requests.Limit {
				view = keyQuotaViewFromQuota(owner.Quota, now)
				return errQuotaExceeded
			}
			owner.Quota.Requests.Used++
		}
		if owner.Quota.Tokens != nil {
			refreshQuotaWindow(owner.Quota.Tokens, now)
		}
		view = keyQuotaViewFromQuota(owner.Quota, now)
		return nil
	})
	if err != nil {
		if errors.Is(err, errQuotaExceeded) || errors.Is(err, errOwnerTokenMissing) {
			return view, metered, err
		}
		return keyQuotaView{}, metered, err
	}
	return view, metered, nil
}

func (s *Server) applyTokenUsageQuota(identity tokenAuthIdentity, usedTokens int64) (keyQuotaView, bool, error) {
	if s == nil || s.store == nil || strings.TrimSpace(identity.Token.ID) == "" {
		return keyQuotaView{}, false, nil
	}
	snap := s.store.Snapshot()
	ownerSnap, err := resolveOwnerTokenFromSnapshot(snap.IncomingTokens, identity)
	if err != nil {
		return keyQuotaView{}, false, err
	}
	if ownerSnap.Quota == nil || (ownerSnap.Quota.Requests == nil && ownerSnap.Quota.Tokens == nil) {
		return keyQuotaView{}, false, nil
	}
	if usedTokens < 0 {
		usedTokens = 0
	}
	now := nowUTC()
	view := keyQuotaView{}
	metered := false
	err = s.store.Update(func(c *config.ServerConfig) error {
		owner, err := resolveOwnerTokenForMutation(c, identity)
		if err != nil {
			return err
		}
		if owner.Quota == nil || (owner.Quota.Requests == nil && owner.Quota.Tokens == nil) {
			return nil
		}
		metered = true
		if owner.Quota.Requests != nil {
			refreshQuotaWindow(owner.Quota.Requests, now)
		}
		if owner.Quota.Tokens != nil {
			refreshQuotaWindow(owner.Quota.Tokens, now)
			owner.Quota.Tokens.Used += usedTokens
			if owner.Quota.Tokens.Used > owner.Quota.Tokens.Limit {
				owner.Quota.Tokens.Used = owner.Quota.Tokens.Limit
			}
		}
		view = keyQuotaViewFromQuota(owner.Quota, now)
		return nil
	})
	if err != nil {
		if errors.Is(err, errOwnerTokenMissing) {
			return view, metered, err
		}
		return keyQuotaView{}, metered, err
	}
	return view, metered, nil
}

func resolveOwnerTokenForMutation(c *config.ServerConfig, identity tokenAuthIdentity) (*config.IncomingAPIToken, error) {
	if c == nil {
		return nil, errOwnerTokenMissing
	}
	token := findTokenByIdentity(c.IncomingTokens, identity)
	if token == nil {
		return nil, errOwnerTokenMissing
	}
	parentID := strings.TrimSpace(token.ParentID)
	if parentID == "" {
		return token, nil
	}
	owner := findTokenByID(c.IncomingTokens, parentID)
	if owner == nil {
		return nil, errOwnerTokenMissing
	}
	return owner, nil
}

func resolveOwnerTokenFromSnapshot(tokens []config.IncomingAPIToken, identity tokenAuthIdentity) (config.IncomingAPIToken, error) {
	token := findTokenByIdentityValue(tokens, identity)
	if token == nil {
		return config.IncomingAPIToken{}, errOwnerTokenMissing
	}
	parentID := strings.TrimSpace(token.ParentID)
	if parentID == "" {
		return *token, nil
	}
	owner := findTokenByIDValue(tokens, parentID)
	if owner == nil {
		return config.IncomingAPIToken{}, errOwnerTokenMissing
	}
	return *owner, nil
}

func findTokenByIdentity(tokens []config.IncomingAPIToken, identity tokenAuthIdentity) *config.IncomingAPIToken {
	id := strings.TrimSpace(identity.Token.ID)
	if id != "" {
		for i := range tokens {
			if strings.TrimSpace(tokens[i].ID) == id {
				return &tokens[i]
			}
		}
	}
	key := strings.TrimSpace(identity.Token.Key)
	if key != "" {
		for i := range tokens {
			if strings.TrimSpace(tokens[i].Key) == key {
				return &tokens[i]
			}
		}
	}
	return nil
}

func findTokenByID(tokens []config.IncomingAPIToken, id string) *config.IncomingAPIToken {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range tokens {
		if strings.TrimSpace(tokens[i].ID) == id {
			return &tokens[i]
		}
	}
	return nil
}

func findTokenByIdentityValue(tokens []config.IncomingAPIToken, identity tokenAuthIdentity) *config.IncomingAPIToken {
	id := strings.TrimSpace(identity.Token.ID)
	if id != "" {
		for i := range tokens {
			if strings.TrimSpace(tokens[i].ID) == id {
				return &tokens[i]
			}
		}
	}
	key := strings.TrimSpace(identity.Token.Key)
	if key != "" {
		for i := range tokens {
			if strings.TrimSpace(tokens[i].Key) == key {
				return &tokens[i]
			}
		}
	}
	return nil
}

func findTokenByIDValue(tokens []config.IncomingAPIToken, id string) *config.IncomingAPIToken {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	for i := range tokens {
		if strings.TrimSpace(tokens[i].ID) == id {
			return &tokens[i]
		}
	}
	return nil
}

func refreshQuotaWindow(b *config.TokenQuotaBudget, now time.Time) bool {
	if b == nil || b.IntervalSeconds <= 0 {
		return false
	}
	interval := time.Duration(b.IntervalSeconds) * time.Second
	if interval <= 0 {
		return false
	}
	startRaw := strings.TrimSpace(b.WindowStartedAt)
	if startRaw == "" {
		b.WindowStartedAt = now.UTC().Format(time.RFC3339)
		b.Used = 0
		return true
	}
	start, err := time.Parse(time.RFC3339, startRaw)
	if err != nil {
		b.WindowStartedAt = now.UTC().Format(time.RFC3339)
		b.Used = 0
		return true
	}
	resetAt := start.Add(interval)
	if now.Before(resetAt) {
		return false
	}
	steps := int64(now.Sub(start) / interval)
	if steps < 1 {
		steps = 1
	}
	newStart := start.Add(time.Duration(steps) * interval).UTC()
	if newStart.After(now) {
		newStart = now.UTC()
	}
	b.WindowStartedAt = newStart.Format(time.RFC3339)
	b.Used = 0
	return true
}

func keyQuotaViewFromQuota(q *config.TokenQuota, now time.Time) keyQuotaView {
	if q == nil {
		return keyQuotaView{}
	}
	return keyQuotaView{
		Requests: quotaMetricViewFromBudget(q.Requests, now),
		Tokens:   quotaMetricViewFromBudget(q.Tokens, now),
	}
}

func quotaMetricViewFromBudget(b *config.TokenQuotaBudget, now time.Time) *quotaMetricView {
	if b == nil || b.Limit <= 0 {
		return nil
	}
	remaining := b.Limit - b.Used
	if remaining < 0 {
		remaining = 0
	}
	if remaining > b.Limit {
		remaining = b.Limit
	}
	out := &quotaMetricView{
		Limit:     b.Limit,
		Remaining: remaining,
	}
	if b.IntervalSeconds > 0 {
		resetAt := quotaBudgetResetAt(b, now)
		if !resetAt.IsZero() {
			out.ResetAt = resetAt.UTC().Format(time.RFC3339)
			sec := int64(math.Ceil(time.Until(resetAt).Seconds()))
			if sec < 0 {
				sec = 0
			}
			out.ResetSeconds = sec
		}
	}
	return out
}

func quotaBudgetResetAt(b *config.TokenQuotaBudget, now time.Time) time.Time {
	if b == nil || b.IntervalSeconds <= 0 {
		return time.Time{}
	}
	interval := time.Duration(b.IntervalSeconds) * time.Second
	if interval <= 0 {
		return time.Time{}
	}
	startRaw := strings.TrimSpace(b.WindowStartedAt)
	if startRaw == "" {
		return now.Add(interval).UTC()
	}
	start, err := time.Parse(time.RFC3339, startRaw)
	if err != nil {
		return now.Add(interval).UTC()
	}
	resetAt := start.Add(interval)
	if now.Before(resetAt) {
		return resetAt
	}
	steps := int64(now.Sub(start) / interval)
	if steps < 0 {
		steps = 0
	}
	return start.Add(time.Duration(steps+1) * interval)
}

func applyQuotaHeaders(h http.Header, q keyQuotaView) {
	if len(h) == 0 || !q.HasAny() {
		return
	}
	applyQuotaHeadersPrefix(h, "x-ratelimit-", q)
	applyQuotaHeadersPrefix(h, "ratelimit-", q)
}

func applyQuotaHeadersPrefix(h http.Header, prefix string, q keyQuotaView) {
	if q.Requests != nil {
		h.Set(prefix+"limit", strconv.FormatInt(q.Requests.Limit, 10))
		h.Set(prefix+"remaining", strconv.FormatInt(q.Requests.Remaining, 10))
		h.Set(prefix+"limit-requests", strconv.FormatInt(q.Requests.Limit, 10))
		h.Set(prefix+"remaining-requests", strconv.FormatInt(q.Requests.Remaining, 10))
		if q.Requests.ResetSeconds > 0 {
			h.Set(prefix+"reset", strconv.FormatInt(q.Requests.ResetSeconds, 10))
			h.Set(prefix+"reset-requests", strconv.FormatInt(q.Requests.ResetSeconds, 10))
		} else {
			h.Del(prefix + "reset")
			h.Del(prefix + "reset-requests")
		}
	}
	if q.Tokens != nil {
		h.Set(prefix+"limit-tokens", strconv.FormatInt(q.Tokens.Limit, 10))
		h.Set(prefix+"remaining-tokens", strconv.FormatInt(q.Tokens.Remaining, 10))
		if q.Tokens.ResetSeconds > 0 {
			h.Set(prefix+"reset-tokens", strconv.FormatInt(q.Tokens.ResetSeconds, 10))
		} else {
			h.Del(prefix + "reset-tokens")
		}
	}
}

func injectQuotaIntoJSONBody(body []byte, q keyQuotaView) []byte {
	if !q.HasAny() {
		return body
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	payload["quota"] = q.JSONValue()
	b, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return b
}

func writeQuotaExceededResponse(w http.ResponseWriter, q keyQuotaView) {
	applyQuotaHeaders(w.Header(), q)
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error": map[string]any{
			"message": "quota exceeded",
			"type":    "insufficient_quota",
			"code":    "insufficient_quota",
		},
		"quota": q.JSONValue(),
	})
}

func wrapQuotaInternalErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("quota: %w", err)
}
