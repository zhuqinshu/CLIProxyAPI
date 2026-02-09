package config

import (
	"testing"

	"gopkg.in/yaml.v3"
	"github.com/stretchr/testify/assert"
)

func TestCodexKeyMigration(t *testing.T) {
	// 模拟旧的配置文件内容
	yamlData := `
codex-api-key:
  - api-key: "sk-old-key-1"
    base-url: "https://api.openai.com/v1"
    proxy-url: "socks5://localhost:1080"
  - api-key: "sk-old-key-2"
    base-url: "https://api.openai.com/v1"
    proxy-url: "socks5://localhost:1080"
  - api-key: "sk-another-provider"
    base-url: "https://api.other.com/v1"
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	assert.NoError(t, err)

	// 运行迁移逻辑
	cfg.SanitizeCodexKeys()

	// 验证结果
	//预期合并为 2 个 Provider：一个对应 api.openai.com，一个对应 api.other.com
	assert.Equal(t, 2, len(cfg.CodexKey))

	// 验证第一个 Provider (api.openai.com)
	kp1 := cfg.CodexKey[0]
	assert.Equal(t, "codex-api-openai-com", kp1.Name)
	assert.Equal(t, "socks5://localhost:1080", kp1.ProxyURL)
	assert.Equal(t, 2, len(kp1.APIKeyEntries))
	assert.Contains(t, kp1.APIKeyEntries, "sk-old-key-1")
	assert.Contains(t, kp1.APIKeyEntries, "sk-old-key-2")
	assert.Empty(t, kp1.APIKey) // 旧字段应清空

	// 验证第二个 Provider (api.other.com)
	kp2 := cfg.CodexKey[1]
	assert.Equal(t, "codex-api-other-com", kp2.Name)
	assert.Equal(t, 1, len(kp2.APIKeyEntries))
	assert.Contains(t, kp2.APIKeyEntries, "sk-another-provider")
}

func TestClaudeKeyMigration(t *testing.T) {
	// 模拟旧的配置文件内容
	yamlData := `
claude-api-key:
  - api-key: "sk-claude-key-1"
    base-url: "https://api.anthropic.com"
  - api-key: "sk-claude-key-2"
    base-url: "https://api.anthropic.com"
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	assert.NoError(t, err)

	// 运行迁移逻辑
	cfg.SanitizeClaudeKeys()

	// 验证结果
	// 预期合并为 1 个 Provider
	assert.Equal(t, 1, len(cfg.ClaudeKey))

	kp1 := cfg.ClaudeKey[0]
	assert.Equal(t, "claude-api-anthropic-com", kp1.Name)
	assert.Equal(t, 2, len(kp1.APIKeyEntries))
	assert.Contains(t, kp1.APIKeyEntries, "sk-claude-key-1")
	assert.Contains(t, kp1.APIKeyEntries, "sk-claude-key-2")
	assert.Empty(t, kp1.APIKey)
}

func TestNewFormatLoading(t *testing.T) {
    // 测试直接加载新格式是否正常
    yamlData := `
codex-api-key:
  - name: "My Custom Provider"
    base-url: "https://custom.com"
    api-key-entries:
      - "key-1"
      - "key-2"
`
    var cfg Config
    err := yaml.Unmarshal([]byte(yamlData), &cfg)
    assert.NoError(t, err)

    cfg.SanitizeCodexKeys()

    assert.Equal(t, 1, len(cfg.CodexKey))
    assert.Equal(t, "My Custom Provider", cfg.CodexKey[0].Name)
    assert.Equal(t, 2, len(cfg.CodexKey[0].APIKeyEntries))
}

func TestClaudeKeyWithoutBaseURLIsPreserved(t *testing.T) {
	yamlData := `
claude-api-key:
  - name: "default-claude"
    api-key-entries:
      - "sk-claude-key-1"
`
	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	assert.NoError(t, err)

	cfg.SanitizeClaudeKeys()

	if assert.Equal(t, 1, len(cfg.ClaudeKey)) {
		assert.Equal(t, "default-claude", cfg.ClaudeKey[0].Name)
		assert.Equal(t, 1, len(cfg.ClaudeKey[0].APIKeyEntries))
		assert.Equal(t, "sk-claude-key-1", cfg.ClaudeKey[0].APIKeyEntries[0])
	}
}
