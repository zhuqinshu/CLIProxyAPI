package cliproxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/config"
)

func TestRegisterModelsForAuth_ClaudeUsesUpstreamModelsWhenNoConfigModels(t *testing.T) {
	const (
		authID    = "test-claude-upstream-discovery-auth"
		apiKey    = "sk-test-upstream"
		modelID   = "claude-upstream-a-20260220"
		modelName = "Claude Upstream A"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Fatalf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"` + modelID + `","display_name":"` + modelName + `","owned_by":"anthropic"}]}`))
	}))
	defer server.Close()

	svc := &Service{cfg: &config.Config{}}
	auth := &coreauth.Auth{
		ID:       authID,
		Provider: "claude",
		Attributes: map[string]string{
			"api_key":  apiKey,
			"base_url": server.URL,
		},
	}

	reg := GlobalModelRegistry()
	t.Cleanup(func() {
		reg.UnregisterClient(authID)
	})

	svc.registerModelsForAuth(auth)

	if !reg.ClientSupportsModel(authID, modelID) {
		t.Fatalf("expected upstream model %q to be registered", modelID)
	}
}

func TestRegisterModelsForAuth_ClaudeExplicitConfigModelsSkipUpstreamDiscovery(t *testing.T) {
	const (
		authID        = "test-claude-config-model-priority-auth"
		apiKey        = "sk-test-config-priority"
		aliasModelID  = "claude-alias-from-config-20260220"
		upstreamModel = "claude-upstream-should-not-be-used-20260220"
	)

	var hitCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hitCount, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"` + upstreamModel + `"}]}`))
	}))
	defer server.Close()

	svc := &Service{
		cfg: &config.Config{
			ClaudeKey: []config.ClaudeKey{
				{
					Name:    "claude-config-priority",
					BaseURL: server.URL,
					APIKey:  apiKey,
					Models: []internalconfig.ClaudeModel{
						{Name: "claude-upstream-original-20260220", Alias: aliasModelID},
					},
				},
			},
		},
	}
	auth := &coreauth.Auth{
		ID:       authID,
		Provider: "claude",
		Attributes: map[string]string{
			"api_key":  apiKey,
			"base_url": server.URL,
		},
	}

	reg := GlobalModelRegistry()
	t.Cleanup(func() {
		reg.UnregisterClient(authID)
	})

	// Even if there is an upstream server available, explicit config models should win.
	svc.registerModelsForAuth(auth)

	if !reg.ClientSupportsModel(authID, aliasModelID) {
		t.Fatalf("expected config alias model %q to be registered", aliasModelID)
	}
	if reg.ClientSupportsModel(authID, upstreamModel) {
		t.Fatalf("did not expect upstream model %q when config models are explicitly set", upstreamModel)
	}
	if atomic.LoadInt32(&hitCount) != 0 {
		t.Fatalf("upstream discovery should be skipped when config models exist, hitCount=%d", hitCount)
	}
}
