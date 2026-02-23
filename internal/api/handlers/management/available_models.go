package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/registry"
)

type modelEntry struct {
	ID                  string `json:"id"`
	DisplayName         string `json:"display_name,omitempty"`
	Type                string `json:"type,omitempty"`
	OwnedBy             string `json:"owned_by,omitempty"`
	ContextLength       int    `json:"context_length,omitempty"`
	MaxCompletionTokens int    `json:"max_completion_tokens,omitempty"`
}

func toModelEntries(models []*registry.ModelInfo) []modelEntry {
	entries := make([]modelEntry, 0, len(models))
	for _, m := range models {
		if m == nil {
			continue
		}
		entries = append(entries, modelEntry{
			ID:                  m.ID,
			DisplayName:         m.DisplayName,
			Type:                m.Type,
			OwnedBy:             m.OwnedBy,
			ContextLength:       m.ContextLength,
			MaxCompletionTokens: m.MaxCompletionTokens,
		})
	}
	return entries
}

// GetAvailableModelsByProvider returns runtime available models for a given provider,
// grouped by config key (channel configuration identifier).
// Provider is provided via path param (:provider) or query param (?provider=...).
func (h *Handler) GetAvailableModelsByProvider(c *gin.Context) {
	provider := strings.TrimSpace(c.Param("provider"))
	if provider == "" {
		provider = strings.TrimSpace(c.Query("provider"))
	}
	if provider == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider is required"})
		return
	}

	provider = strings.ToLower(provider)
	grouped := registry.GetGlobalRegistry().GetAvailableModelsGrouped(provider)

	type channelGroup struct {
		ConfigKey string       `json:"config_key"`
		Models    []modelEntry `json:"models"`
		Count     int          `json:"count"`
	}

	channels := make([]channelGroup, 0, len(grouped))
	totalCount := 0
	for key, models := range grouped {
		entries := toModelEntries(models)
		channels = append(channels, channelGroup{
			ConfigKey: key,
			Models:    entries,
			Count:     len(entries),
		})
		totalCount += len(entries)
	}

	// Also return a flat list for backward compatibility
	allModels := registry.GetGlobalRegistry().GetAvailableModelsByProvider(provider)

	c.JSON(http.StatusOK, gin.H{
		"provider": provider,
		"models":   toModelEntries(allModels),
		"count":    len(allModels),
		"channels": channels,
	})
}
