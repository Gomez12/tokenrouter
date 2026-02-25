package conversations

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreChainsByPreviousResponseID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conversations.json")
	s := NewStore(path, Settings{Enabled: true, MaxItems: 1000, MaxAgeDays: 30})
	now := time.Now().UTC()

	r1, ok := s.Add(CaptureInput{
		Timestamp:  now,
		Endpoint:   "responses",
		Provider:   "openai",
		Model:      "gpt-5",
		StatusCode: 200,
		ProtocolIDs: ProtocolIDs{
			ResponseID: "resp_1",
		},
	})
	if !ok {
		t.Fatal("expected first add to succeed")
	}
	r2, ok := s.Add(CaptureInput{
		Timestamp:  now.Add(10 * time.Second),
		Endpoint:   "responses",
		Provider:   "openai",
		Model:      "gpt-5",
		StatusCode: 200,
		ProtocolIDs: ProtocolIDs{
			RequestPreviousResponse: "resp_1",
		},
	})
	if !ok {
		t.Fatal("expected second add to succeed")
	}
	if r1.ConversationKey != r2.ConversationKey {
		t.Fatalf("expected same conversation key, got %q vs %q", r1.ConversationKey, r2.ConversationKey)
	}
}

func TestStoreHeuristicSplitAfterGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conversations.json")
	s := NewStore(path, Settings{Enabled: true, MaxItems: 1000, MaxAgeDays: 30})
	now := time.Now().UTC()

	r1, ok := s.Add(CaptureInput{
		Timestamp:  now,
		Endpoint:   "chat.completions",
		Provider:   "openai",
		Model:      "gpt-5",
		RemoteIP:   "127.0.0.1",
		APIKeyName: "dev",
		StatusCode: 200,
	})
	if !ok {
		t.Fatal("expected first add to succeed")
	}
	r2, ok := s.Add(CaptureInput{
		Timestamp:  now.Add(11 * time.Minute),
		Endpoint:   "chat.completions",
		Provider:   "openai",
		Model:      "gpt-5",
		RemoteIP:   "127.0.0.1",
		APIKeyName: "dev",
		StatusCode: 200,
	})
	if !ok {
		t.Fatal("expected second add to succeed")
	}
	if r1.ConversationKey == r2.ConversationKey {
		t.Fatalf("expected heuristic split after gap, key=%q", r1.ConversationKey)
	}
}

func TestStoreDeleteConversation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conversations.json")
	s := NewStore(path, Settings{Enabled: true, MaxItems: 1000, MaxAgeDays: 30})
	now := time.Now().UTC()

	r1, ok := s.Add(CaptureInput{
		Timestamp:  now,
		Endpoint:   "chat.completions",
		Provider:   "openai",
		Model:      "gpt-5",
		StatusCode: 200,
	})
	if !ok {
		t.Fatal("expected first add to succeed")
	}
	_, ok = s.Add(CaptureInput{
		Timestamp:  now.Add(2 * time.Second),
		Endpoint:   "chat.completions",
		Provider:   "openai",
		Model:      "gpt-5",
		StatusCode: 200,
		ProtocolIDs: ProtocolIDs{
			RequestConversationID: strings.TrimPrefix(r1.ConversationKey, "cid:"),
		},
	})
	if !ok {
		t.Fatal("expected second add to succeed")
	}

	if got := s.DeleteConversation(r1.ConversationKey); got < 1 {
		t.Fatalf("expected at least one removed row, got %d", got)
	}
	if conv := s.Conversation(r1.ConversationKey); len(conv) != 0 {
		t.Fatalf("expected conversation to be deleted, got %d records", len(conv))
	}
}
