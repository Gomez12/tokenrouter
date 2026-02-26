package conversations

import (
	"encoding/json"
	"strings"
)

type StructuredRecord struct {
	Record
	RequestSystemMarkdown string `json:"request_system_markdown,omitempty"`
	ResponseThinkMarkdown string `json:"response_think_markdown,omitempty"`
}

type ConversationRecordView struct {
	StructuredRecord
	IsInternal               bool   `json:"is_internal,omitempty"`
	InternalKind             string `json:"internal_kind,omitempty"`
	RequestRenderMarkdown    string `json:"request_render_markdown,omitempty"`
	ResponseRenderMarkdown   string `json:"response_render_markdown,omitempty"`
	RequestRenderSource      string `json:"request_render_source,omitempty"`
	ResponseRenderSource     string `json:"response_render_source,omitempty"`
	RequestDeltaMarkdown     string `json:"request_delta_markdown,omitempty"`
	ResponseDeltaMarkdown    string `json:"response_delta_markdown,omitempty"`
	RequestDeltaStartOffset  int    `json:"request_delta_start_offset,omitempty"`
	ResponseDeltaStartOffset int    `json:"response_delta_start_offset,omitempty"`
	RequestPreviousMarkdown  string `json:"request_previous_markdown,omitempty"`
	ResponsePreviousMarkdown string `json:"response_previous_markdown,omitempty"`
}

type Conversation struct {
	ID      string                   `json:"id"`
	Records []ConversationRecordView `json:"records"`
}

type ConversationViewOptions struct {
	IncludeInternal bool
}

func ExtractConversationTitle(records []Record) string {
	views := BuildConversationRecordViewsWithOptions(records, ConversationViewOptions{IncludeInternal: true})
	for _, view := range views {
		if !view.IsInternal || view.InternalKind != "title_generation" {
			continue
		}
		title := normalizeInlineText(view.ResponseRenderMarkdown)
		if title != "" {
			return title
		}
	}
	return ""
}

func (r Record) ToStructuredRecord() StructuredRecord {
	rec := cloneRecord(r)
	rec.RequestHeaders = parseHeadersRaw(rec.RequestHeadersRaw)
	rec.ResponseHeaders = parseHeadersRaw(rec.ResponseHeadersRaw)
	rec.RequestPayload = parsePayloadRaw(rec.RequestPayloadRaw)
	rec.ResponsePayload = parsePayloadRaw(rec.ResponsePayloadRaw)

	storedReq := strings.TrimSpace(rec.RequestTextMarkdown)
	storedResp := strings.TrimSpace(rec.ResponseTextMarkdown)
	rec.RequestTextMarkdown = extractRequestTextFromRaw(rec.RequestPayloadRaw)
	rec.ResponseTextMarkdown = extractResponseTextFromRaw(rec.ResponsePayloadRaw)
	if strings.TrimSpace(rec.RequestTextMarkdown) == "" {
		rec.RequestTextMarkdown = storedReq
	}
	if strings.TrimSpace(rec.ResponseTextMarkdown) == "" {
		rec.ResponseTextMarkdown = storedResp
	}

	return StructuredRecord{
		Record:                rec,
		RequestSystemMarkdown: extractSystemPromptFromRaw(rec.RequestPayloadRaw),
		ResponseThinkMarkdown: extractThinkTextFromRaw(rec.ResponsePayloadRaw),
	}
}

func BuildConversation(id string, records []Record) Conversation {
	return Conversation{ID: strings.TrimSpace(id), Records: BuildConversationRecordViews(records)}
}

func BuildConversationRecordViews(records []Record) []ConversationRecordView {
	return BuildConversationRecordViewsWithOptions(records, ConversationViewOptions{})
}

func BuildConversationRecordViewsWithOptions(records []Record, options ConversationViewOptions) []ConversationRecordView {
	if len(records) == 0 {
		return []ConversationRecordView{}
	}
	out := make([]ConversationRecordView, 0, len(records))
	prevReq := ""
	prevResp := ""
	for _, rec := range records {
		structured := rec.ToStructuredRecord()
		req := strings.TrimSpace(structured.RequestTextMarkdown)
		resp := strings.TrimSpace(structured.ResponseTextMarkdown)
		lastUser := extractLatestUserTurnFromRaw(structured.RequestPayloadRaw)
		reqCandidates := conversationPrefixCandidates(prevReq, prevResp)
		respCandidates := conversationPrefixCandidates(prevResp, prevReq)
		reqDelta, reqOffset := bestConversationDelta(req, reqCandidates...)
		respDelta, respOffset := bestConversationDelta(resp, append(respCandidates, req)...)
		reqRender, reqSource := chooseRenderText(req, reqDelta, lastUser)
		respRender, respSource := chooseRenderText(resp, respDelta, "")
		internalReq := req
		if strings.TrimSpace(lastUser) != "" {
			internalReq = strings.TrimSpace(lastUser)
		}
		internal := isOutOfBandConversationTitleRequest(internalReq, resp)
		internalKind := ""
		if internal {
			internalKind = "title_generation"
		}
		view := ConversationRecordView{
			StructuredRecord:         structured,
			IsInternal:               internal,
			InternalKind:             internalKind,
			RequestRenderMarkdown:    reqRender,
			ResponseRenderMarkdown:   respRender,
			RequestRenderSource:      reqSource,
			ResponseRenderSource:     respSource,
			RequestPreviousMarkdown:  prevReq,
			ResponsePreviousMarkdown: prevResp,
			RequestDeltaMarkdown:     reqDelta,
			ResponseDeltaMarkdown:    respDelta,
			RequestDeltaStartOffset:  reqOffset,
			ResponseDeltaStartOffset: respOffset,
		}
		if !internal || options.IncludeInternal {
			out = append(out, view)
		}
		if !internal {
			prevReq = reqRender
			prevResp = respRender
		}
	}
	return out
}

func chooseRenderText(full string, delta string, preferred string) (string, string) {
	if p := normalizeText(preferred); p != "" {
		return p, "latest_user_turn"
	}
	if d := normalizeText(delta); d != "" {
		return d, "delta_fallback"
	}
	return normalizeText(full), "full_fallback"
}

func ExtractConversationDelta(current, previous string) string {
	delta, _ := extractConversationDeltaWithOffset(current, previous)
	return delta
}

func bestConversationDelta(current string, previousCandidates ...string) (string, int) {
	bestDelta, bestOffset := extractConversationDeltaWithOffset(current, "")
	bestScore := deltaChoiceScore(bestDelta, bestOffset)
	for _, prev := range previousCandidates {
		delta, offset := extractConversationDeltaWithOffset(current, prev)
		score := deltaChoiceScore(delta, offset)
		if score > bestScore {
			bestDelta, bestOffset, bestScore = delta, offset, score
		}
	}
	return bestDelta, bestOffset
}

func conversationPrefixCandidates(primary string, secondary string) []string {
	p := normalizeText(primary)
	s := normalizeText(secondary)
	if p == "" && s == "" {
		return nil
	}
	out := make([]string, 0, 8)
	add := func(v string) {
		v = normalizeText(v)
		if v == "" {
			return
		}
		for _, existing := range out {
			if existing == v {
				return
			}
		}
		out = append(out, v)
	}
	add(p)
	add(s)
	if p != "" && s != "" {
		add(p + "\n" + s)
		add("User: " + p + "\nAI: " + s)
		add("Conversation:\nUser: " + p + "\nAI:\n" + s)
	}
	return out
}

func isOutOfBandConversationTitleRequest(req string, resp string) bool {
	r := strings.ToLower(normalizeText(req))
	if r == "" {
		return false
	}
	if !strings.Contains(r, "title for the conversation") {
		return false
	}
	if !strings.Contains(r, "only return the title") {
		return false
	}
	trimResp := normalizeText(resp)
	if trimResp == "" {
		return true
	}
	return len(strings.Fields(trimResp)) <= 8
}

func deltaChoiceScore(delta string, offset int) int {
	d := normalizeText(delta)
	return offset*100000 - len(d)
}

func extractConversationDeltaWithOffset(current, previous string) (string, int) {
	cur := normalizeText(current)
	prev := normalizeText(previous)
	if cur == "" {
		return "", 0
	}
	if prev == "" {
		return cur, 0
	}
	if cur == prev {
		return "", len(cur)
	}
	if strings.HasPrefix(cur, prev) {
		return strings.TrimSpace(cur[len(prev):]), len(prev)
	}
	prevTail := prev
	const tailLimit = 12000
	if len(prevTail) > tailLimit {
		prevTail = prevTail[len(prevTail)-tailLimit:]
	}
	maxOverlap := len(prevTail)
	if len(cur) < maxOverlap {
		maxOverlap = len(cur)
	}
	const minOverlap = 40
	for n := maxOverlap; n >= minOverlap; n-- {
		if prevTail[len(prevTail)-n:] == cur[:n] {
			return strings.TrimSpace(cur[n:]), n
		}
	}
	return cur, 0
}

func normalizeText(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
}

func parseHeadersRaw(raw string) map[string]string {
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(raw), "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		key, val, ok := strings.Cut(s, ":")
		if !ok {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(key))
		if k == "" {
			continue
		}
		out[k] = strings.TrimSpace(val)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parsePayloadRaw(raw string) json.RawMessage {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	b := []byte(s)
	if json.Valid(b) {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	encoded, _ := json.Marshal(s)
	return encoded
}

func parseRawPayloadEntries(raw string) []json.RawMessage {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	out := make([]json.RawMessage, 0, 8)
	appendJSON := func(data string) {
		trimmed := strings.TrimSpace(data)
		if trimmed == "" {
			return
		}
		msg := json.RawMessage(trimmed)
		if !json.Valid(msg) {
			return
		}
		cp := make([]byte, len(msg))
		copy(cp, msg)
		out = append(out, cp)
	}
	if strings.Contains(s, "\ndata:") || strings.HasPrefix(strings.ToLower(s), "data:") {
		lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(strings.ToLower(trimmed), "data:") {
				continue
			}
			data := strings.TrimSpace(trimmed[5:])
			if data == "" || data == "[DONE]" {
				continue
			}
			appendJSON(data)
		}
		return out
	}
	appendJSON(s)
	return out
}

func extractRequestTextFromRaw(raw string) string {
	parts := make([]string, 0, 8)
	for _, payload := range parseRawPayloadEntries(raw) {
		parts = append(parts, collectPromptText(payload)...)
	}
	return normalizeText(strings.Join(parts, "\n"))
}

func extractLatestUserTurnFromRaw(raw string) string {
	for _, payload := range parseRawPayloadEntries(raw) {
		if s := extractLatestUserMessage(payload); s != "" {
			return s
		}
	}
	return ""
}

func extractLatestUserMessage(payload json.RawMessage) string {
	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(trimJSON(payload), &obj); err != nil {
		return ""
	}
	msgsRaw, ok := obj["messages"]
	if !ok {
		return ""
	}
	msgs := []json.RawMessage{}
	if err := json.Unmarshal(trimJSON(msgsRaw), &msgs); err != nil {
		return ""
	}
	last := ""
	for _, msgRaw := range msgs {
		msgObj := map[string]json.RawMessage{}
		if err := json.Unmarshal(trimJSON(msgRaw), &msgObj); err != nil {
			continue
		}
		roleVal, ok := msgObj["role"]
		if !ok {
			continue
		}
		role, ok := decodeJSONString(roleVal)
		if !ok || strings.ToLower(strings.TrimSpace(role)) != "user" {
			continue
		}
		contentVal, ok := msgObj["content"]
		if !ok {
			continue
		}
		text := normalizeText(strings.Join(flattenTextValues(contentVal), "\n"))
		if text != "" {
			last = text
		}
	}
	return last
}

func extractResponseTextFromRaw(raw string) string {
	fullParts := make([]string, 0, 8)
	var stream strings.Builder
	for _, payload := range parseRawPayloadEntries(raw) {
		text, isDelta := extractResponseChunkText(payload)
		if text == "" {
			continue
		}
		if isDelta {
			stream.WriteString(text)
			continue
		}
		fullParts = append(fullParts, text)
	}
	if s := normalizeText(stream.String()); s != "" {
		return s
	}
	return normalizeText(strings.Join(normalizeTextSlice(fullParts), "\n\n"))
}

func collectPromptText(payload json.RawMessage) []string {
	out := make([]string, 0, 8)
	var walk func(v json.RawMessage, key string)
	walk = func(v json.RawMessage, key string) {
		v = trimJSON(v)
		if len(v) == 0 {
			return
		}
		switch v[0] {
		case '{':
			obj := map[string]json.RawMessage{}
			if err := json.Unmarshal(v, &obj); err != nil {
				return
			}
			for k, vv := range obj {
				walk(vv, strings.ToLower(strings.TrimSpace(k)))
			}
		case '[':
			arr := []json.RawMessage{}
			if err := json.Unmarshal(v, &arr); err != nil {
				return
			}
			for _, vv := range arr {
				walk(vv, key)
			}
		case '"':
			s, ok := decodeJSONString(v)
			if !ok {
				return
			}
			switch key {
			case "prompt", "input", "instructions", "system", "content", "text":
				out = append(out, s)
			}
		}
	}
	walk(payload, "")
	return normalizeTextSlice(out)
}

func collectCompletionText(payload json.RawMessage) []string {
	out := make([]string, 0, 8)
	var walk func(v json.RawMessage, key string)
	walk = func(v json.RawMessage, key string) {
		v = trimJSON(v)
		if len(v) == 0 {
			return
		}
		switch v[0] {
		case '{':
			obj := map[string]json.RawMessage{}
			if err := json.Unmarshal(v, &obj); err != nil {
				return
			}
			for k, vv := range obj {
				lk := strings.ToLower(strings.TrimSpace(k))
				switch lk {
				case "output_text", "delta":
					if s, ok := decodeJSONString(vv); ok {
						out = append(out, s)
					}
				case "text":
					if s, ok := decodeJSONString(vv); ok && key != "input" && key != "prompt" {
						out = append(out, s)
					}
				case "content":
					if s, ok := decodeJSONString(vv); ok && (key == "message" || key == "delta" || key == "choice" || key == "output") {
						out = append(out, s)
					}
				}
				walk(vv, lk)
			}
		case '[':
			arr := []json.RawMessage{}
			if err := json.Unmarshal(v, &arr); err != nil {
				return
			}
			for _, vv := range arr {
				walk(vv, key)
			}
		}
	}
	walk(payload, "")
	return normalizeTextSlice(out)
}

func extractSystemPromptFromRaw(raw string) string {
	parts := make([]string, 0, 8)
	seen := map[string]struct{}{}
	for _, payload := range parseRawPayloadEntries(raw) {
		for _, text := range collectSystemPromptText(payload) {
			n := normalizeText(text)
			if n == "" {
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			parts = append(parts, n)
		}
	}
	return strings.Join(parts, "\n\n")
}

func collectSystemPromptText(payload json.RawMessage) []string {
	out := make([]string, 0, 8)
	var walk func(v json.RawMessage, parentKey string, inheritedRole string)
	walk = func(v json.RawMessage, parentKey string, inheritedRole string) {
		v = trimJSON(v)
		if len(v) == 0 {
			return
		}
		switch v[0] {
		case '{':
			obj := map[string]json.RawMessage{}
			if err := json.Unmarshal(v, &obj); err != nil {
				return
			}
			role := inheritedRole
			if rv, ok := obj["role"]; ok {
				if s, ok2 := decodeJSONString(rv); ok2 {
					role = strings.ToLower(strings.TrimSpace(s))
				}
			}
			for k, vv := range obj {
				lk := strings.ToLower(strings.TrimSpace(k))
				if (lk == "system" || lk == "instructions") && isJSONString(vv) {
					if s, ok := decodeJSONString(vv); ok {
						out = append(out, s)
					}
				}
				if lk == "content" && role == "system" {
					out = append(out, flattenTextValues(vv)...)
				}
				walk(vv, lk, role)
			}
		case '[':
			arr := []json.RawMessage{}
			if err := json.Unmarshal(v, &arr); err != nil {
				return
			}
			for _, vv := range arr {
				walk(vv, parentKey, inheritedRole)
			}
		case '"':
			s, ok := decodeJSONString(v)
			if !ok {
				return
			}
			if parentKey == "system" || parentKey == "instructions" || inheritedRole == "system" {
				out = append(out, s)
			}
		}
	}
	walk(payload, "", "")
	return normalizeTextSlice(out)
}

func flattenTextValues(v json.RawMessage) []string {
	out := make([]string, 0, 4)
	var walk func(json.RawMessage)
	walk = func(cur json.RawMessage) {
		cur = trimJSON(cur)
		if len(cur) == 0 {
			return
		}
		switch cur[0] {
		case '"':
			s, ok := decodeJSONString(cur)
			if ok {
				out = append(out, s)
			}
		case '{':
			obj := map[string]json.RawMessage{}
			if err := json.Unmarshal(cur, &obj); err != nil {
				return
			}
			for _, key := range []string{"text", "content", "input_text"} {
				if val, ok := obj[key]; ok {
					if s, ok2 := decodeJSONString(val); ok2 {
						out = append(out, s)
					}
				}
			}
			for _, vv := range obj {
				walk(vv)
			}
		case '[':
			arr := []json.RawMessage{}
			if err := json.Unmarshal(cur, &arr); err != nil {
				return
			}
			for _, vv := range arr {
				walk(vv)
			}
		}
	}
	walk(v)
	return normalizeTextSlice(out)
}

func extractThinkTextFromRaw(raw string) string {
	var b strings.Builder
	last := ""
	for _, payload := range parseRawPayloadEntries(raw) {
		for _, frag := range collectThinkTextFragments(payload) {
			if frag == "" {
				continue
			}
			norm := strings.ReplaceAll(frag, "\r\n", "\n")
			if norm == last {
				continue
			}
			b.WriteString(norm)
			last = norm
		}
	}
	return normalizeText(b.String())
}

func extractResponseChunkText(payload json.RawMessage) (string, bool) {
	v := trimJSON(payload)
	if len(v) == 0 || v[0] != '{' {
		return "", false
	}
	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(v, &obj); err != nil {
		return "", false
	}
	if delta, ok := obj["delta"]; ok {
		if s, ok := decodeJSONString(delta); ok {
			return s, true
		}
	}
	if outputText, ok := obj["output_text"]; ok {
		if s, ok := decodeJSONString(outputText); ok {
			return s, true
		}
	}
	if choicesRaw, ok := obj["choices"]; ok {
		if s, delta := extractFromChoices(choicesRaw); s != "" {
			return s, delta
		}
	}
	if messageRaw, ok := obj["message"]; ok {
		if s := extractMessageContent(messageRaw); s != "" {
			return s, false
		}
	}
	if responseRaw, ok := obj["response"]; ok {
		if s, delta := extractResponseChunkText(responseRaw); s != "" {
			return s, delta
		}
	}
	parts := collectCompletionText(payload)
	return strings.Join(parts, "\n"), false
}

func extractFromChoices(choicesRaw json.RawMessage) (string, bool) {
	choices := []json.RawMessage{}
	if err := json.Unmarshal(trimJSON(choicesRaw), &choices); err != nil {
		return "", false
	}
	deltas := make([]string, 0, len(choices))
	full := make([]string, 0, len(choices))
	for _, choiceRaw := range choices {
		obj := map[string]json.RawMessage{}
		if err := json.Unmarshal(trimJSON(choiceRaw), &obj); err != nil {
			continue
		}
		if deltaRaw, ok := obj["delta"]; ok {
			if s := extractDeltaContent(deltaRaw); s != "" {
				deltas = append(deltas, s)
			}
		}
		if messageRaw, ok := obj["message"]; ok {
			if s := extractMessageContent(messageRaw); s != "" {
				full = append(full, s)
			}
		}
		if textRaw, ok := obj["text"]; ok {
			if s, ok := decodeJSONString(textRaw); ok {
				full = append(full, s)
			}
		}
	}
	if len(deltas) > 0 {
		return strings.Join(deltas, ""), true
	}
	if len(full) > 0 {
		return strings.Join(normalizeTextSlice(full), "\n\n"), false
	}
	return "", false
}

func extractDeltaContent(deltaRaw json.RawMessage) string {
	if s, ok := decodeJSONString(deltaRaw); ok {
		return s
	}
	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(trimJSON(deltaRaw), &obj); err != nil {
		return ""
	}
	for _, key := range []string{"content", "text", "output_text"} {
		if v, ok := obj[key]; ok {
			if s, ok := decodeJSONString(v); ok {
				return s
			}
		}
	}
	return ""
}

func extractMessageContent(messageRaw json.RawMessage) string {
	v := trimJSON(messageRaw)
	if len(v) == 0 {
		return ""
	}
	if s, ok := decodeJSONString(v); ok {
		return s
	}
	obj := map[string]json.RawMessage{}
	if err := json.Unmarshal(v, &obj); err != nil {
		return ""
	}
	if contentRaw, ok := obj["content"]; ok {
		return normalizeText(strings.Join(flattenTextValues(contentRaw), "\n"))
	}
	if textRaw, ok := obj["text"]; ok {
		if s, ok := decodeJSONString(textRaw); ok {
			return s
		}
	}
	return ""
}

func normalizeInlineText(s string) string {
	flat := strings.ReplaceAll(normalizeText(s), "\n", " ")
	return strings.Join(strings.Fields(flat), " ")
}

func collectThinkTextFragments(payload json.RawMessage) []string {
	out := make([]string, 0, 16)
	var walk func(v json.RawMessage, parentKey string, parentType string)
	walk = func(v json.RawMessage, parentKey string, parentType string) {
		v = trimJSON(v)
		if len(v) == 0 {
			return
		}
		switch v[0] {
		case '{':
			obj := map[string]json.RawMessage{}
			if err := json.Unmarshal(v, &obj); err != nil {
				return
			}
			t := parentType
			if tv, ok := obj["type"]; ok {
				if s, ok2 := decodeJSONString(tv); ok2 {
					t = strings.ToLower(strings.TrimSpace(s))
				}
			}
			for k, vv := range obj {
				lk := strings.ToLower(strings.TrimSpace(k))
				if lk == "" {
					continue
				}
				if isThinkLikeKey(lk) {
					if s, ok := decodeJSONString(vv); ok {
						out = append(out, s)
					}
				}
				if lk == "text" && (isThinkLikeKey(parentKey) || strings.Contains(parentType, "reason") || strings.Contains(parentType, "think")) {
					if s, ok := decodeJSONString(vv); ok {
						out = append(out, s)
					}
				}
				walk(vv, lk, t)
			}
		case '[':
			arr := []json.RawMessage{}
			if err := json.Unmarshal(v, &arr); err != nil {
				return
			}
			for _, vv := range arr {
				walk(vv, parentKey, parentType)
			}
		case '"':
			if isThinkLikeKey(parentKey) || strings.Contains(parentType, "reason") || strings.Contains(parentType, "think") {
				if s, ok := decodeJSONString(v); ok {
					out = append(out, s)
				}
			}
		}
	}
	walk(payload, "", "")
	return out
}

func isThinkLikeKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "reasoning", "thinking", "reasoning_content", "thinking_content", "reasoning_text", "thinking_text", "reasoning_details":
		return true
	default:
		return false
	}
}

func normalizeTextSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		n := normalizeText(s)
		if n == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}

func trimJSON(b json.RawMessage) json.RawMessage {
	trimmed := strings.TrimSpace(string(b))
	if trimmed == "" {
		return nil
	}
	return json.RawMessage(trimmed)
}

func decodeJSONString(v json.RawMessage) (string, bool) {
	v = trimJSON(v)
	if len(v) == 0 || v[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

func isJSONString(v json.RawMessage) bool {
	v = trimJSON(v)
	return len(v) > 0 && v[0] == '"'
}
