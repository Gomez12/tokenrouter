package conversations

import "testing"

func TestBuildConversationRecordViewsWithOptions_LatestUserTurnAndInternalTitle(t *testing.T) {
	records := []Record{
		{
			RequestPayloadRaw:  `{"messages":[{"role":"user","content":"how is the weather?"}]}`,
			ResponsePayloadRaw: `{"choices":[{"message":{"role":"assistant","content":"I don't have real-time weather."}}]}`,
		},
		{
			RequestPayloadRaw:  `{"messages":[{"role":"user","content":"Provide a concise, 5-word-or-less title for the conversation, using title case conventions. Only return the title itself.\n\nConversation:\nUser: how is the weather?\nAI: I don't have real-time weather."}]}`,
			ResponsePayloadRaw: `{"choices":[{"message":{"role":"assistant","content":"Weather Inquiry Assistance"}}]}`,
		},
		{
			RequestPayloadRaw:  `{"messages":[{"role":"user","content":"how is the weather?"},{"role":"assistant","content":"I don't have real-time weather."},{"role":"user","content":"let's try weather in spain"}]}`,
			ResponsePayloadRaw: `{"choices":[{"message":{"role":"assistant","content":"Great! I can look up Spain weather."}}]}`,
		},
		{
			RequestPayloadRaw:  `{"messages":[{"role":"user","content":"how is the weather?"},{"role":"assistant","content":"I don't have real-time weather."},{"role":"user","content":"let's try weather in spain"},{"role":"assistant","content":"Great! I can look up Spain weather."},{"role":"user","content":"what is your data source for this?"}]}`,
			ResponsePayloadRaw: `{"choices":[{"message":{"role":"assistant","content":"I used general climatology, not live data."}}]}`,
		},
	}

	hidden := BuildConversationRecordViewsWithOptions(records, ConversationViewOptions{IncludeInternal: false})
	if len(hidden) != 3 {
		t.Fatalf("expected 3 visible records, got %d", len(hidden))
	}
	if hidden[0].RequestRenderMarkdown != "how is the weather?" {
		t.Fatalf("unexpected first request render %q", hidden[0].RequestRenderMarkdown)
	}
	if hidden[1].RequestRenderMarkdown != "let's try weather in spain" {
		t.Fatalf("unexpected second request render %q", hidden[1].RequestRenderMarkdown)
	}
	if hidden[2].RequestRenderMarkdown != "what is your data source for this?" {
		t.Fatalf("unexpected third request render %q", hidden[2].RequestRenderMarkdown)
	}
	if hidden[1].RequestRenderSource != "latest_user_turn" || hidden[2].RequestRenderSource != "latest_user_turn" {
		t.Fatalf("expected latest_user_turn source for follow-up messages")
	}

	all := BuildConversationRecordViewsWithOptions(records, ConversationViewOptions{IncludeInternal: true})
	if len(all) != 4 {
		t.Fatalf("expected all 4 records when include_internal, got %d", len(all))
	}
	if !all[1].IsInternal {
		t.Fatalf("expected record 2 to be marked internal")
	}
	if all[1].InternalKind != "title_generation" {
		t.Fatalf("unexpected internal kind %q", all[1].InternalKind)
	}
	title := ExtractConversationTitle(records)
	if title != "Weather Inquiry Assistance" {
		t.Fatalf("unexpected title %q", title)
	}
}

func TestExtractResponseTextFromRaw_ConcatenatesStreamingDeltas(t *testing.T) {
	raw := `data: {"choices":[{"delta":{"content":"### For my **previous"}}]}

data: {"choices":[{"delta":{"content":" general description** of Spain's weather."}}]}

data: [DONE]`
	got := extractResponseTextFromRaw(raw)
	want := "### For my **previous general description** of Spain's weather."
	if got != want {
		t.Fatalf("unexpected stream join\ngot:  %q\nwant: %q", got, want)
	}
}
