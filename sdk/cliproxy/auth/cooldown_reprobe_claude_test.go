package auth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// TestCooldownReprobe_RealClaudeExecutor drives the re-probe through the real
// Claude executor against a fake Anthropic upstream: a still-exhausted weekly
// window keeps the cooldown with the fresh reset, and an early reset clears it.
func TestCooldownReprobe_RealClaudeExecutor(t *testing.T) {
	cliproxyauth.SetQuotaCooldownDisabled(false)

	var allowed atomic.Bool
	var mu sync.Mutex
	var bodies [][]byte
	var paths []string
	freshReset := time.Now().Add(3 * 24 * time.Hour).Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if allowed.Load() {
			w.Header().Set("Anthropic-Ratelimit-Unified-Status", "allowed")
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "allowed")
			w.Header().Set("Anthropic-Ratelimit-Unified-5h-Utilization", "0.0")
			w.Header().Set("Anthropic-Ratelimit-Unified-7d-Status", "allowed")
			w.Header().Set("Anthropic-Ratelimit-Unified-7d-Utilization", "0.01")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"ok"}],"stop_reason":"max_tokens","usage":{"input_tokens":8,"output_tokens":1}}`))
			return
		}
		w.Header().Set("Anthropic-Ratelimit-Unified-Status", "rejected")
		w.Header().Set("Anthropic-Ratelimit-Unified-5h-Status", "allowed")
		w.Header().Set("Anthropic-Ratelimit-Unified-7d-Status", "rejected")
		w.Header().Set("Anthropic-Ratelimit-Unified-7d-Utilization", "1.0")
		w.Header().Set("Anthropic-Ratelimit-Unified-7d-Reset", strconv.FormatInt(freshReset, 10))
		w.Header().Set("Anthropic-Ratelimit-Unified-Representative-Claim", "seven_day")
		w.Header().Set("Anthropic-Ratelimit-Unified-Reset", strconv.FormatInt(freshReset, 10))
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"Number of requests has exceeded your 7-day rate limit."}}`))
	}))
	defer server.Close()

	cfg := &internalconfig.Config{}
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(executor.NewClaudeExecutor(cfg))

	auth := &cliproxyauth.Auth{
		ID:         uuid.NewString() + "-claude.json",
		Provider:   "claude",
		Attributes: map[string]string{"api_key": "test-key", "base_url": server.URL},
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: "claude-sonnet-4-5-20250929"}, {ID: "claude-haiku-4-5-20251001"}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	weekly := 7 * 24 * time.Hour
	manager.MarkResult(context.Background(), cliproxyauth.Result{
		AuthID: auth.ID, Provider: "claude", Model: "claude-sonnet-4-5-20250929",
		RetryAfter: &weekly, CredentialScope: true,
		Error: &cliproxyauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "7d limit rejected"},
	})

	if probed := manager.CooldownReprobeTickForTest(context.Background()); probed != 1 {
		t.Fatalf("first sweep probed %d, want 1", probed)
	}
	benched, _ := manager.GetByID(auth.ID)
	if !benched.Quota.Exceeded {
		t.Fatalf("cooldown cleared by a 429 probe: %+v", benched.Quota)
	}
	if diff := benched.Quota.NextRecoverAt.Unix() - freshReset; diff < -60 || diff > 60 {
		t.Fatalf("retry_at = %v, want refreshed to the probe's 7d reset %v", benched.Quota.NextRecoverAt, time.Unix(freshReset, 0))
	}

	allowed.Store(true)
	if probed := manager.CooldownReprobeTickForTest(context.Background()); probed != 1 {
		t.Fatalf("second sweep probed %d, want 1", probed)
	}
	cleared, _ := manager.GetByID(auth.ID)
	if cleared.Quota.Exceeded || cleared.Unavailable {
		t.Fatalf("cooldown not cleared after an allowed probe: unavailable=%v quota=%+v", cleared.Unavailable, cleared.Quota)
	}
	if got := cleared.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"]; got != "0.01" {
		t.Fatalf("signals not refreshed: %v", cleared.Quota.Signals)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("upstream saw %d requests, want 2", len(bodies))
	}
	for i, body := range bodies {
		if paths[i] != "/v1/messages" {
			t.Fatalf("probe path = %s, want /v1/messages", paths[i])
		}
		if got := gjson.GetBytes(body, "max_tokens").Int(); got != 1 {
			t.Fatalf("probe max_tokens = %d, want 1; body=%s", got, body)
		}
		if got := gjson.GetBytes(body, "model").String(); got != "claude-haiku-4-5-20251001" {
			t.Fatalf("probe model = %s, want Haiku", got)
		}
		if gjson.GetBytes(body, "stream").Bool() {
			t.Fatal("probe must not stream")
		}
		t.Logf("probe upstream body (%d bytes): %s", len(body), body)
	}
}
