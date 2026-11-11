package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const (
	reprobeTestHaiku  = "claude-haiku-4-5-20251001"
	reprobeTestSonnet = "claude-sonnet-4-5-20250929"
)

type reprobeTestRateLimitError struct {
	retryAfter time.Duration
}

func (e reprobeTestRateLimitError) Error() string {
	return `{"type":"error","error":{"type":"rate_limit_error","message":"rate limited"}}`
}
func (e reprobeTestRateLimitError) StatusCode() int { return http.StatusTooManyRequests }
func (e reprobeTestRateLimitError) RetryAfter() *time.Duration {
	d := e.retryAfter
	return &d
}
func (e reprobeTestRateLimitError) IsCredentialScoped() bool { return true }

type reprobeTestCall struct {
	authID  string
	model   string
	payload []byte
}

// reprobeTestExecutor answers every request with the configured headers and error.
type reprobeTestExecutor struct {
	mu      sync.Mutex
	calls   []reprobeTestCall
	headers http.Header
	err     error
}

func (e *reprobeTestExecutor) Identifier() string { return "claude" }

func (e *reprobeTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.calls = append(e.calls, reprobeTestCall{authID: auth.ID, model: req.Model, payload: append([]byte(nil), req.Payload...)})
	headers, err := e.headers, e.err
	e.mu.Unlock()
	internallogging.SetResponseHeaders(ctx, headers)
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"type":"message","content":[{"type":"text","text":"ok"}]}`)}, nil
}

func (e *reprobeTestExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *reprobeTestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }
func (e *reprobeTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *reprobeTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *reprobeTestExecutor) recorded() []reprobeTestCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]reprobeTestCall(nil), e.calls...)
}

func noReprobeWait(context.Context, time.Duration) bool { return true }

func newReprobeTestManager(t *testing.T, interval string) (*Manager, *reprobeTestExecutor) {
	t.Helper()
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	m := NewManager(nil, nil, nil)
	m.SetConfig(&internalconfig.Config{Routing: internalconfig.RoutingConfig{CooldownReprobeInterval: interval}})
	executor := &reprobeTestExecutor{}
	m.RegisterExecutor(executor)
	return m, executor
}

// registerReprobeTestAuth registers a Claude credential with Haiku and Sonnet models.
func registerReprobeTestAuth(t *testing.T, m *Manager, auth *Auth) {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: reprobeTestSonnet}, {ID: reprobeTestHaiku}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
}

func newReprobeTestAuth(suffix string) *Auth {
	return &Auth{
		ID:         uuid.NewString() + "-" + suffix + ".json",
		Provider:   "claude",
		Attributes: map[string]string{"api_key": "test-key"},
	}
}

// benchForWeeklyQuota reproduces the incident: a credential-scoped 429 with a 7d reset.
func benchForWeeklyQuota(m *Manager, authID string) {
	weekly := 7 * 24 * time.Hour
	m.MarkResult(context.Background(), Result{
		AuthID:          authID,
		Provider:        "claude",
		Model:           reprobeTestSonnet,
		RetryAfter:      &weekly,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusTooManyRequests, Message: "7d limit rejected"},
	})
}

func mustAuth(t *testing.T, m *Manager, id string) *Auth {
	t.Helper()
	auth, ok := m.GetByID(id)
	if !ok || auth == nil {
		t.Fatalf("auth %s not found", id)
	}
	return auth
}

func TestCooldownReprobe_AllowedProbeClearsCooldown(t *testing.T) {
	m, executor := newReprobeTestManager(t, "")
	auth := newReprobeTestAuth("allowed")
	registerReprobeTestAuth(t, m, auth)
	benchForWeeklyQuota(m, auth.ID)
	if blocked, _, _ := isAuthBlockedForModel(mustAuth(t, m, auth.ID), reprobeTestSonnet, time.Now()); !blocked {
		t.Fatal("precondition: credential should be cooled after weekly 429")
	}

	executor.headers = http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"allowed"},
		"Anthropic-Ratelimit-Unified-7d-Status":      {"allowed"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"0.02"},
	}
	if probed := m.cooldownReprobeTick(context.Background(), noReprobeWait); probed != 1 {
		t.Fatalf("probed = %d, want 1", probed)
	}

	calls := executor.recorded()
	if len(calls) != 1 {
		t.Fatalf("executor calls = %d, want 1", len(calls))
	}
	if calls[0].model != reprobeTestHaiku {
		t.Fatalf("probe model = %q, want cheapest %q", calls[0].model, reprobeTestHaiku)
	}
	if got := gjson.GetBytes(calls[0].payload, "max_tokens").Int(); got != 1 {
		t.Fatalf("probe max_tokens = %d, want 1", got)
	}

	updated := mustAuth(t, m, auth.ID)
	if updated.Quota.Exceeded || !updated.NextRetryAfter.IsZero() {
		t.Fatalf("credential cooldown not cleared: quota=%+v next=%v", updated.Quota, updated.NextRetryAfter)
	}
	for _, model := range []string{reprobeTestSonnet, reprobeTestHaiku} {
		if blocked, reason, next := isAuthBlockedForModel(updated, model, time.Now()); blocked {
			t.Fatalf("model %s still blocked after allowed probe: reason=%v next=%v", model, reason, next)
		}
	}
	if got := updated.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"]; got != "0.02" {
		t.Fatalf("quota signals not refreshed from probe headers: %v", updated.Quota.Signals)
	}
}

func TestCooldownReprobe_RateLimitedProbeKeepsCooldownWithFreshReset(t *testing.T) {
	m, executor := newReprobeTestManager(t, "45m")
	auth := newReprobeTestAuth("limited")
	registerReprobeTestAuth(t, m, auth)
	benchForWeeklyQuota(m, auth.ID)

	// Upstream now reports the window resets in 3 days, sooner than the stored 7 days.
	freshReset := 3 * 24 * time.Hour
	executor.headers = http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {"rejected"},
		"Anthropic-Ratelimit-Unified-7d-Status":      {"rejected"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"1.0"},
	}
	executor.err = reprobeTestRateLimitError{retryAfter: freshReset}

	before := time.Now()
	if probed := m.cooldownReprobeTick(context.Background(), noReprobeWait); probed != 1 {
		t.Fatalf("probed = %d, want 1", probed)
	}

	updated := mustAuth(t, m, auth.ID)
	if !updated.Quota.Exceeded || updated.Quota.Reason != "credential_quota" {
		t.Fatalf("credential cooldown lost after 429 probe: quota=%+v", updated.Quota)
	}
	want := before.Add(freshReset)
	if diff := updated.Quota.NextRecoverAt.Sub(want); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("retry_at = %v, want refreshed to ~%v", updated.Quota.NextRecoverAt, want)
	}
	for _, model := range []string{reprobeTestSonnet, reprobeTestHaiku} {
		if blocked, _, _ := isAuthBlockedForModel(updated, model, time.Now()); !blocked {
			t.Fatalf("model %s unblocked by a rate-limited probe", model)
		}
	}
	if got := updated.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Status"]; got != "rejected" {
		t.Fatalf("quota signals not refreshed from probe headers: %v", updated.Quota.Signals)
	}
}

func TestCooldownReprobe_AllowedStatusWithExhaustedHeadersKeepsCooldown(t *testing.T) {
	m, executor := newReprobeTestManager(t, "45m")
	auth := newReprobeTestAuth("exhausted-headers")
	registerReprobeTestAuth(t, m, auth)
	benchForWeeklyQuota(m, auth.ID)

	executor.headers = http.Header{"Anthropic-Ratelimit-Unified-7d-Utilization": {"1.0"}}
	m.cooldownReprobeTick(context.Background(), noReprobeWait)

	if updated := mustAuth(t, m, auth.ID); !updated.Quota.Exceeded {
		t.Fatalf("cooldown cleared although headers report the window exhausted: quota=%+v", updated.Quota)
	}
}

func TestCooldownReprobe_SkipsDisabledAuth(t *testing.T) {
	m, executor := newReprobeTestManager(t, "45m")
	disabled := newReprobeTestAuth("disabled")
	registerReprobeTestAuth(t, m, disabled)
	benchForWeeklyQuota(m, disabled.ID)
	// Flip the flag in place so the auth keeps a qualifying cooldown and only
	// the disabled check can exclude it (Register/Update clear disabled cooldowns).
	m.mu.Lock()
	m.auths[disabled.ID].Disabled = true
	m.auths[disabled.ID].Status = StatusDisabled
	m.mu.Unlock()
	if _, ok := cooldownReprobeTarget(mustAuth(t, m, disabled.ID), time.Now()); !ok {
		t.Fatal("precondition: disabled auth should carry a long quota cooldown")
	}

	enabled := newReprobeTestAuth("enabled")
	registerReprobeTestAuth(t, m, enabled)
	benchForWeeklyQuota(m, enabled.ID)

	executor.err = reprobeTestRateLimitError{retryAfter: 7 * 24 * time.Hour}
	if probed := m.cooldownReprobeTick(context.Background(), noReprobeWait); probed != 1 {
		t.Fatalf("probed = %d, want 1 (enabled auth only)", probed)
	}
	for _, call := range executor.recorded() {
		if call.authID == disabled.ID {
			t.Fatal("disabled auth was probed")
		}
	}
}

func TestCooldownReprobe_SkipsCooldownEndingSoon(t *testing.T) {
	m, executor := newReprobeTestManager(t, "45m")
	auth := newReprobeTestAuth("ending-soon")
	registerReprobeTestAuth(t, m, auth)
	soon := 10 * time.Minute
	m.MarkResult(context.Background(), Result{
		AuthID:          auth.ID,
		Provider:        "claude",
		Model:           reprobeTestSonnet,
		RetryAfter:      &soon,
		CredentialScope: true,
		Error:           &Error{HTTPStatus: http.StatusTooManyRequests, Message: "5h limit rejected"},
	})

	if probed := m.cooldownReprobeTick(context.Background(), noReprobeWait); probed != 0 || len(executor.recorded()) != 0 {
		t.Fatalf("probed = %d calls = %d, want none for a cooldown under 30m", probed, len(executor.recorded()))
	}
}

func TestCooldownReprobe_IntervalZeroDisables(t *testing.T) {
	m, executor := newReprobeTestManager(t, "0")
	auth := newReprobeTestAuth("interval-zero")
	registerReprobeTestAuth(t, m, auth)
	benchForWeeklyQuota(m, auth.ID)

	if probed := m.cooldownReprobeTick(context.Background(), noReprobeWait); probed != 0 {
		t.Fatalf("probed = %d, want 0 when interval is 0", probed)
	}
	if calls := executor.recorded(); len(calls) != 0 {
		t.Fatalf("executor called %d times while re-probing is disabled", len(calls))
	}
	if updated := mustAuth(t, m, auth.ID); !updated.Quota.Exceeded {
		t.Fatal("cooldown changed while re-probing is disabled")
	}
}

func TestCooldownReprobeInterval(t *testing.T) {
	cases := map[string]time.Duration{
		"":      DefaultCooldownReprobeInterval,
		"0":     0,
		"0s":    0,
		"-5m":   0,
		"10m":   10 * time.Minute,
		"1h30m": 90 * time.Minute,
		"600":   10 * time.Minute,
		"bogus": DefaultCooldownReprobeInterval,
	}
	for raw, want := range cases {
		cfg := &internalconfig.Config{Routing: internalconfig.RoutingConfig{CooldownReprobeInterval: raw}}
		if got := CooldownReprobeInterval(cfg); got != want {
			t.Errorf("CooldownReprobeInterval(%q) = %v, want %v", raw, got, want)
		}
	}
	if got := CooldownReprobeInterval(nil); got != DefaultCooldownReprobeInterval {
		t.Errorf("CooldownReprobeInterval(nil) = %v, want default", got)
	}
}
