package auth

import (
	"context"
	"math"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	log "github.com/sirupsen/logrus"
)

// Cooldown re-probing.
//
// A Claude quota 429 cools the credential until the reset advertised by the
// unified rate-limit headers, which for the 7d window can be days away. The
// selector never sends traffic to a cooled credential, so if Anthropic lifts
// the limit early (for example a one-off usage reset) the proxy cannot notice.
// The re-probe loop periodically sends one minimal request to each credential
// whose quota cooldown still has a long way to go. An allowed answer clears the
// cooldown through ResetQuota; a renewed 429 keeps it with the fresh deadline.

const (
	// DefaultCooldownReprobeInterval is used when routing.cooldown-reprobe-interval is unset.
	DefaultCooldownReprobeInterval = 45 * time.Minute
	// cooldownReprobeMinRemaining skips cooldowns that will lift on their own soon.
	cooldownReprobeMinRemaining = 30 * time.Minute
	// cooldownReprobeDisabledPoll is how often a disabled loop rechecks the config.
	cooldownReprobeDisabledPoll = time.Minute
	// cooldownReprobeMaxStagger caps the random delay between probes of one sweep.
	cooldownReprobeMaxStagger = 30 * time.Second
	// cooldownReprobePrompt matches the Claude Code quota preflight, which the
	// Claude executor already recognizes as a probe request.
	cooldownReprobePrompt = "quota"
)

// cooldownReprobeJitter returns a random duration in [0, max). Tests replace it.
var cooldownReprobeJitter = func(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max)))
}

// CooldownReprobeInterval resolves routing.cooldown-reprobe-interval. Unset or
// invalid values use the default; zero or negative values disable re-probing.
func CooldownReprobeInterval(cfg *internalconfig.Config) time.Duration {
	if cfg == nil {
		return DefaultCooldownReprobeInterval
	}
	raw := strings.TrimSpace(cfg.Routing.CooldownReprobeInterval)
	if raw == "" {
		return DefaultCooldownReprobeInterval
	}
	parsed, errParse := time.ParseDuration(raw)
	if errParse != nil {
		if seconds, errAtoi := strconv.Atoi(raw); errAtoi == nil {
			parsed = time.Duration(seconds) * time.Second
		} else {
			log.Warnf("invalid routing.cooldown-reprobe-interval %q, using default %s", raw, DefaultCooldownReprobeInterval)
			return DefaultCooldownReprobeInterval
		}
	}
	if parsed <= 0 {
		return 0
	}
	return parsed
}

// StartCooldownReprobe launches the background re-probe loop. Starting it again
// replaces the previous loop. The interval is re-read from the runtime config
// on every cycle, so config reloads take effect without a restart.
func (m *Manager) StartCooldownReprobe(parent context.Context) {
	if m == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.mu.Lock()
	cancelPrev := m.reprobeCancel
	m.reprobeCancel = cancel
	m.mu.Unlock()
	if cancelPrev != nil {
		cancelPrev()
	}
	go m.runCooldownReprobeLoop(ctx)
}

// StopCooldownReprobe stops the background re-probe loop, if running.
func (m *Manager) StopCooldownReprobe() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.reprobeCancel
	m.reprobeCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) runCooldownReprobeLoop(ctx context.Context) {
	for {
		wait := cooldownReprobeDisabledPoll
		if interval := CooldownReprobeInterval(m.runtimeConfigSnapshot()); interval > 0 {
			// +/-10% so probes from several proxies or restarts do not align.
			spread := interval / 5
			wait = interval - spread/2 + cooldownReprobeJitter(spread)
		}
		if !sleepContext(ctx, wait) {
			return
		}
		m.cooldownReprobeTick(ctx, sleepContext)
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// cooldownReprobeTick probes every eligible credential once and returns how many
// probes were sent. It does nothing when re-probing is disabled. wait staggers
// consecutive probes and aborts the sweep when it returns false.
func (m *Manager) cooldownReprobeTick(ctx context.Context, wait func(context.Context, time.Duration) bool) int {
	if m == nil || m.HomeEnabled() {
		return 0
	}
	interval := CooldownReprobeInterval(m.runtimeConfigSnapshot())
	if interval <= 0 {
		return 0
	}
	candidates := m.cooldownReprobeCandidates(time.Now())
	stagger := min(cooldownReprobeMaxStagger, interval/20)
	probed := 0
	for i, candidate := range candidates {
		if i > 0 && wait != nil && !wait(ctx, cooldownReprobeJitter(stagger)) {
			break
		}
		if ctx.Err() != nil {
			break
		}
		if m.reprobeCooldown(ctx, candidate) {
			probed++
		}
	}
	return probed
}

type cooldownReprobeCandidate struct {
	auth        *Auth
	model       string
	credential  bool
	cooldownEnd time.Time
}

// cooldownReprobeCandidates lists enabled Claude credentials under a quota
// cooldown with more than cooldownReprobeMinRemaining left, highest priority first.
func (m *Manager) cooldownReprobeCandidates(now time.Time) []cooldownReprobeCandidate {
	m.mu.RLock()
	snapshots := make([]*Auth, 0, len(m.auths))
	for _, auth := range m.auths {
		if auth != nil {
			snapshots = append(snapshots, auth.Clone())
		}
	}
	m.mu.RUnlock()

	out := make([]cooldownReprobeCandidate, 0)
	for _, auth := range snapshots {
		if !isClaudeAuth(auth) || auth.Disabled || auth.Status == StatusDisabled ||
			hasUnauthorizedAuthFailure(auth) || m.cooldownDisabledForAuth(auth) {
			continue
		}
		candidate, ok := cooldownReprobeTarget(auth, now)
		if !ok {
			continue
		}
		out = append(out, candidate)
	}
	slices.SortFunc(out, func(a, b cooldownReprobeCandidate) int {
		if pa, pb := authPriority(a.auth), authPriority(b.auth); pa != pb {
			return pb - pa
		}
		return strings.Compare(a.auth.ID, b.auth.ID)
	})
	return out
}

func isQuotaCooldownReason(reason string) bool {
	switch strings.TrimSpace(reason) {
	case "quota", "credential_quota":
		return true
	default:
		return false
	}
}

func quotaCooldownEnd(q QuotaState, nextRetryAfter time.Time) time.Time {
	if !q.Exceeded || !isQuotaCooldownReason(q.Reason) {
		return time.Time{}
	}
	end := q.NextRecoverAt
	if nextRetryAfter.After(end) {
		end = nextRetryAfter
	}
	return end
}

// cooldownReprobeTarget decides whether auth needs a probe and which model to
// probe. A credential-wide cooldown is probed on the cheapest registered model;
// a model-only cooldown is probed on the model with the longest cooldown.
func cooldownReprobeTarget(auth *Auth, now time.Time) (cooldownReprobeCandidate, bool) {
	threshold := now.Add(cooldownReprobeMinRemaining)
	candidate := cooldownReprobeCandidate{auth: auth}
	if end := quotaCooldownEnd(auth.Quota, auth.NextRetryAfter); end.After(threshold) {
		candidate.credential = true
		candidate.cooldownEnd = end
	}
	var cooledModel string
	var cooledEnd time.Time
	modelKeys := make([]string, 0, len(auth.ModelStates))
	for key := range auth.ModelStates {
		modelKeys = append(modelKeys, key)
	}
	slices.Sort(modelKeys)
	for _, key := range modelKeys {
		state := auth.ModelStates[key]
		if state == nil || strings.TrimSpace(key) == "" {
			continue
		}
		if end := quotaCooldownEnd(state.Quota, state.NextRetryAfter); end.After(threshold) && end.After(cooledEnd) {
			cooledModel, cooledEnd = key, end
		}
	}
	if !candidate.credential && cooledModel == "" {
		return cooldownReprobeCandidate{}, false
	}
	if candidate.credential {
		candidate.model = cheapestClaudeModelForAuth(auth.ID)
	}
	if candidate.model == "" {
		candidate.model = cooledModel
	}
	if candidate.model == "" {
		if models := modelsForRegisteredAuth(auth.ID); len(models) > 0 {
			slices.Sort(models)
			candidate.model = models[0]
		}
	}
	if candidate.cooldownEnd.Before(cooledEnd) {
		candidate.cooldownEnd = cooledEnd
	}
	return candidate, candidate.model != ""
}

// cheapestClaudeModelForAuth prefers a registered Haiku model, which is the
// cheapest Claude tier and the model Claude Code itself uses for quota checks.
func cheapestClaudeModelForAuth(authID string) string {
	var haiku []string
	for _, model := range registry.GetGlobalRegistry().GetModelsForClient(authID) {
		if model == nil {
			continue
		}
		id := strings.TrimSpace(model.ID)
		if strings.Contains(strings.ToLower(id), "haiku") && !strings.Contains(id, "[") {
			haiku = append(haiku, id)
		}
	}
	if len(haiku) == 0 {
		return ""
	}
	// Newest dated snapshot first; IDs sort chronologically within a family.
	slices.Sort(haiku)
	return haiku[len(haiku)-1]
}

func authLogName(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return filepath.Base(name)
	}
	return auth.ID
}

// reprobeCooldown sends one minimal request for candidate and applies the
// outcome. It reports whether an upstream request was attempted.
func (m *Manager) reprobeCooldown(parent context.Context, candidate cooldownReprobeCandidate) bool {
	auth := candidate.auth
	name := authLogName(auth)
	executor := m.executorFor(auth.Provider)
	if executor == nil {
		log.Debugf("cooldown reprobe skipped for %s: no executor for provider %s", name, auth.Provider)
		return false
	}

	ctx := parent
	if rt := m.roundTripperFor(auth); rt != nil {
		ctx = context.WithValue(ctx, roundTripperContextKey{}, rt)
		ctx = context.WithValue(ctx, "cliproxy.roundtripper", rt)
	}
	ctx = newUpstreamAttemptContext(ctx)
	prepared, errPrepare := m.prepareRequestAuth(ctx, executor, auth)
	if errPrepare != nil {
		log.Infof("cooldown reprobe skipped for %s: prepare auth failed: %v", name, errPrepare)
		return false
	}
	auth = prepared
	executor = executorForAuth(executor, auth)

	routeModel := candidate.model
	upstreamModel := routeModel
	candidates, pooled, _, _ := m.executionModelCandidatesWithAlias(auth, routeModel)
	if len(candidates) > 0 && strings.TrimSpace(candidates[0]) != "" {
		upstreamModel = candidates[0]
	}
	resultModel := m.stateModelForExecution(auth, routeModel, upstreamModel, pooled)

	payload := []byte(`{"model":` + strconv.Quote(upstreamModel) + `,"max_tokens":1,"messages":[{"role":"user","content":"` + cooldownReprobePrompt + `"}]}`)
	claudeFormat := sdktranslator.FromString("claude")
	req := cliproxyexecutor.Request{Model: upstreamModel, Payload: payload, Format: claudeFormat}
	opts := cliproxyexecutor.Options{
		OriginalRequest: payload,
		SourceFormat:    claudeFormat,
		ResponseFormat:  claudeFormat,
		Headers:         make(http.Header),
	}

	log.Infof("cooldown reprobe: probing %s (model=%s, cooldown until %s)", name, upstreamModel, candidate.cooldownEnd.Format(time.RFC3339))
	seq := m.nextExecutionSeq()
	resp, errExec := executor.Execute(ctx, auth, req, opts)
	if parent.Err() != nil {
		return true
	}
	headers := internallogging.GetResponseHeaders(ctx)
	result := Result{
		AuthID:            auth.ID,
		Provider:          auth.Provider,
		Model:             resultModel,
		RouteModel:        routeModel,
		Success:           errExec == nil,
		CompletedResponse: errExec == nil && !resp.Incomplete && isCompletedExecutionPayload(resp.Payload),
		Options:           opts,
		CredentialVersion: auth.CredentialVersion,
		RegistrationEpoch: auth.RegistrationEpoch,
		ExecutionSeq:      seq,
	}

	if errExec == nil {
		if claudeUnifiedHeadersRejected(headers) {
			log.Infof("cooldown reprobe: %s answered but rate-limit headers still report rejection; keeping cooldown", name)
			return true
		}
		if _, _, errReset := m.ResetQuota(parent, auth.ID); errReset != nil {
			log.Warnf("cooldown reprobe: %s is allowed again but clearing its cooldown failed: %v", name, errReset)
			return true
		}
		// Record the success so the fresh unified-ratelimit headers replace the
		// stale quota signals the soonest-reset strategy ranks on.
		m.MarkResult(ctx, result)
		log.Infof("cooldown reprobe: %s is allowed again; cooldown cleared", name)
		return true
	}

	status := statusCodeFromError(errExec)
	if status != http.StatusTooManyRequests {
		// Only quota answers are acted on; other failures say nothing about the
		// quota and are left to regular traffic and the refresh loop.
		log.Infof("cooldown reprobe: %s probe failed with status %d; cooldown unchanged", name, status)
		return true
	}
	result.Error = resultErrorFromError(errExec)
	result.RetryAfter = retryAfterFromError(errExec)
	result.CredentialScope = isCredentialScopedError(errExec)
	if result.RetryAfter != nil && *result.RetryAfter > 0 {
		newEnd := time.Now().Add(*result.RetryAfter)
		if newEnd.Before(candidate.cooldownEnd.Add(-time.Minute)) {
			// Cooldown writes are monotonic, so an earlier upstream reset can
			// only be applied after clearing the stale deadline.
			if _, _, errReset := m.ResetQuota(parent, auth.ID); errReset != nil {
				log.Warnf("cooldown reprobe: %s failed to shorten cooldown: %v", name, errReset)
			}
		}
	}
	m.MarkResult(ctx, result)
	nextRetry := "unknown"
	if result.RetryAfter != nil {
		nextRetry = time.Now().Add(*result.RetryAfter).Format(time.RFC3339)
	}
	log.Infof("cooldown reprobe: %s still rate limited; cooldown kept (retry at %s)", name, nextRetry)
	return true
}

// claudeUnifiedHeadersRejected reports whether a response still declares an
// exhausted shared 5h/7d window, either by status or by utilization at the limit.
func claudeUnifiedHeadersRejected(headers http.Header) bool {
	if len(headers) == 0 {
		return false
	}
	for _, name := range []string{
		"Anthropic-Ratelimit-Unified-5h-Status",
		"Anthropic-Ratelimit-Unified-7d-Status",
	} {
		if strings.EqualFold(strings.TrimSpace(headers.Get(name)), "rejected") {
			return true
		}
	}
	for _, name := range []string{
		"Anthropic-Ratelimit-Unified-5h-Utilization",
		"Anthropic-Ratelimit-Unified-7d-Utilization",
	} {
		raw := strings.TrimSpace(headers.Get(name))
		if raw == "" {
			continue
		}
		if util, errParse := strconv.ParseFloat(raw, 64); errParse == nil && !math.IsNaN(util) && util >= 1.0 {
			return true
		}
	}
	return false
}
