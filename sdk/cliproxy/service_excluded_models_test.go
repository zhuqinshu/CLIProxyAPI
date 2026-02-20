package cliproxy

import (
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestRegisterModelsForAuth_UnregistersWhenAllModelsExcluded(t *testing.T) {
	const (
		disabledAuthID = "test-claude-disabled-all-excluded"
		activeAuthID   = "test-claude-active-channel"
		upstreamModel  = "test-claude-model-a-20260220"
		aliasModel     = "test-claude-model-b-alias-20260220"
	)

	svc := &Service{
		cfg: &config.Config{
			ClaudeKey: []config.ClaudeKey{
				{
					Name:    "disabled-channel",
					BaseURL: "https://claude.example.com/disabled",
					APIKey:  "sk-disabled",
					Models: []internalconfig.ClaudeModel{
						{Name: upstreamModel, Alias: aliasModel},
					},
				},
				{
					Name:    "active-channel",
					BaseURL: "https://claude.example.com/active",
					APIKey:  "sk-active",
					Models: []internalconfig.ClaudeModel{
						{Name: upstreamModel},
					},
				},
			},
		},
	}

	disabledAuth := &coreauth.Auth{
		ID:       disabledAuthID,
		Provider: "claude",
		Attributes: map[string]string{
			"api_key":  "sk-disabled",
			"base_url": "https://claude.example.com/disabled",
		},
	}

	activeAuth := &coreauth.Auth{
		ID:       activeAuthID,
		Provider: "claude",
		Attributes: map[string]string{
			"api_key":  "sk-active",
			"base_url": "https://claude.example.com/active",
		},
	}

	registry := GlobalModelRegistry()
	t.Cleanup(func() {
		registry.UnregisterClient(disabledAuthID)
		registry.UnregisterClient(activeAuthID)
	})

	// Step 1: disabled channel initially exposes alias model.
	svc.registerModelsForAuth(disabledAuth)
	svc.registerModelsForAuth(activeAuth)

	if !registry.ClientSupportsModel(disabledAuthID, aliasModel) {
		t.Fatalf("expected disabled channel to initially register alias model %q", aliasModel)
	}
	if !registry.ClientSupportsModel(activeAuthID, upstreamModel) {
		t.Fatalf("expected active channel to register upstream model %q", upstreamModel)
	}

	// Step 2: exclude all models from disabled channel; stale alias must be unregistered.
	svc.cfg.ClaudeKey[0].ExcludedModels = []string{"*"}
	svc.registerModelsForAuth(disabledAuth)

	if registry.ClientSupportsModel(disabledAuthID, aliasModel) {
		t.Fatalf("expected alias model %q to be unregistered after excluding all models", aliasModel)
	}
	if providers := util.GetProviderName(aliasModel); len(providers) != 0 {
		t.Fatalf("expected alias model %q to have no providers, got %v", aliasModel, providers)
	}
	if !registry.ClientSupportsModel(activeAuthID, upstreamModel) {
		t.Fatalf("expected active channel to keep model %q after other channel disable", upstreamModel)
	}
}
