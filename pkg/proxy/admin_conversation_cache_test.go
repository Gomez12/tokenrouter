package proxy

import "testing"

func TestConversationViewCacheSetGetAndInvalidate(t *testing.T) {
	h := &AdminHandler{
		conversationViewCache: map[string]conversationViewCacheEntry{},
	}
	id := "conv-key"
	in := []conversationRecordView{
		{RequestRenderMarkdown: "hello"},
	}
	h.setConversationViewCache(id, false, "My Title", in)

	title, views, ok := h.getConversationViewCache(id, false)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if title != "My Title" {
		t.Fatalf("unexpected title %q", title)
	}
	if len(views) != 1 || views[0].RequestRenderMarkdown != "hello" {
		t.Fatalf("unexpected views %#v", views)
	}

	h.invalidateConversationViewCacheForKey(id)
	if _, _, ok := h.getConversationViewCache(id, false); ok {
		t.Fatal("expected cache miss after key invalidation")
	}

	h.setConversationViewCache(id, true, "My Title 2", in)
	h.invalidateConversationViewCacheAll()
	if _, _, ok := h.getConversationViewCache(id, true); ok {
		t.Fatal("expected cache miss after global invalidation")
	}
}
