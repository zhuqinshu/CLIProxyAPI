package cliproxy

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestResolveConfigClaudeKey_MatchesAPIKeyEntries(t *testing.T) {
	svc := &Service{
		cfg: &config.Config{
			ClaudeKey: []config.ClaudeKey{
				{
					Name:          "claude-provider",
					BaseURL:       "https://example.com/claude",
					APIKeyEntries: []string{"sk-claude-a", "sk-claude-b"},
				},
			},
		},
	}

	auth := &coreauth.Auth{
		Provider: "claude",
		Attributes: map[string]string{
			"api_key":  "sk-claude-b",
			"base_url": "https://example.com/claude",
		},
	}

	entry := svc.resolveConfigClaudeKey(auth)
	if entry == nil {
		t.Fatal("expected claude config entry, got nil")
	}
	if entry.Name != "claude-provider" {
		t.Fatalf("expected claude provider name %q, got %q", "claude-provider", entry.Name)
	}
}

func TestResolveConfigCodexKey_MatchesAPIKeyEntries(t *testing.T) {
	svc := &Service{
		cfg: &config.Config{
			CodexKey: []config.CodexKey{
				{
					Name:          "codex-provider",
					BaseURL:       "https://example.com/codex",
					APIKeyEntries: []string{"sk-codex-a", "sk-codex-b"},
				},
			},
		},
	}

	auth := &coreauth.Auth{
		Provider: "codex",
		Attributes: map[string]string{
			"api_key":  "sk-codex-b",
			"base_url": "https://example.com/codex",
		},
	}

	entry := svc.resolveConfigCodexKey(auth)
	if entry == nil {
		t.Fatal("expected codex config entry, got nil")
	}
	if entry.Name != "codex-provider" {
		t.Fatalf("expected codex provider name %q, got %q", "codex-provider", entry.Name)
	}
}

