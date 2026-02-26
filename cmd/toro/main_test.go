package main

import "testing"

func TestIsValidEnvVarName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{name: "empty", in: "", ok: false},
		{name: "leading digit", in: "1OPENAI", ok: false},
		{name: "contains dash", in: "OPENAI-KEY", ok: false},
		{name: "contains space", in: "OPENAI KEY", ok: false},
		{name: "simple", in: "OPENAI_API_KEY", ok: true},
		{name: "lowercase", in: "openai_base_url", ok: true},
		{name: "leading underscore", in: "_TOKEN", ok: true},
		{name: "with digits", in: "API_KEY_2", ok: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidEnvVarName(tc.in); got != tc.ok {
				t.Fatalf("isValidEnvVarName(%q) = %v, want %v", tc.in, got, tc.ok)
			}
		})
	}
}
