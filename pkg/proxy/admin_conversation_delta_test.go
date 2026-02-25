package proxy

import (
	"testing"

	"github.com/lkarlslund/tokenrouter/pkg/conversations"
)

func TestExtractConversationDelta(t *testing.T) {
	t.Run("first message", func(t *testing.T) {
		got := extractConversationDelta("hello", "")
		if got != "hello" {
			t.Fatalf("expected full message, got %q", got)
		}
	})

	t.Run("prefix append", func(t *testing.T) {
		prev := "user: hi\nassistant: hello"
		cur := prev + "\nuser: how are you?"
		got := extractConversationDelta(cur, prev)
		if got != "user: how are you?" {
			t.Fatalf("expected appended tail, got %q", got)
		}
	})

	t.Run("identical", func(t *testing.T) {
		prev := "same"
		got := extractConversationDelta(prev, prev)
		if got != "" {
			t.Fatalf("expected empty delta, got %q", got)
		}
	})
}

func TestBuildConversationRecordViews(t *testing.T) {
	records := []conversations.Record{
		{RequestTextMarkdown: "hello", ResponseTextMarkdown: "hi"},
		{RequestTextMarkdown: "hello\nhow are you", ResponseTextMarkdown: "hi\nall good"},
	}
	views := buildConversationRecordViews(records)
	if len(views) != 2 {
		t.Fatalf("expected 2 views, got %d", len(views))
	}
	if views[0].RequestPreviousMarkdown != "" || views[0].ResponsePreviousMarkdown != "" {
		t.Fatalf("expected first view previous fields to be empty")
	}
	if views[1].RequestPreviousMarkdown != "hello" {
		t.Fatalf("unexpected previous request %q", views[1].RequestPreviousMarkdown)
	}
	if views[1].ResponsePreviousMarkdown != "hi" {
		t.Fatalf("unexpected previous response %q", views[1].ResponsePreviousMarkdown)
	}
	if views[1].RequestDeltaMarkdown != "how are you" {
		t.Fatalf("unexpected request delta %q", views[1].RequestDeltaMarkdown)
	}
	if views[1].ResponseDeltaMarkdown != "all good" {
		t.Fatalf("unexpected response delta %q", views[1].ResponseDeltaMarkdown)
	}
}

