package auth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func unixSignal(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// quotaSignalTestManager builds a manager with a file quota signal store and the
// given Claude auth IDs registered. Each call simulates one process lifetime.
func quotaSignalTestManager(t *testing.T, path string, ids ...string) *Manager {
	t.Helper()
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	m := NewManager(nil, nil, nil)
	m.SetQuotaSignalStore(NewFileQuotaSignalStore(path))
	reg := registry.GetGlobalRegistry()
	for _, id := range ids {
		reg.RegisterClient(id, "claude", []*registry.ModelInfo{{ID: reprobeTestSonnet}, {ID: reprobeTestHaiku}})
		t.Cleanup(func() { reg.UnregisterClient(id) })
		auth := &Auth{ID: id, Provider: "claude", Attributes: map[string]string{"api_key": "test-key"}}
		if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}
	return m
}

// observe records an upstream response for id the way live traffic does:
// headers on the context, result through MarkResult.
func observe(m *Manager, id string, status int, headers http.Header) {
	ctx := internallogging.WithFreshResponseHeadersHolder(context.Background())
	internallogging.SetResponseHeaders(ctx, headers)
	result := Result{AuthID: id, Provider: "claude", Model: reprobeTestSonnet, Success: status < 300}
	if status >= 300 {
		retry := time.Hour
		result.RetryAfter = &retry
		result.Error = &Error{HTTPStatus: status, Message: "rate limited"}
	}
	m.MarkResult(ctx, result)
}

func TestQuotaSignals_ExhaustedWeeklyWindowStaysBenchedAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), QuotaSignalFileName)
	benched := uuid.NewString() + "-benched.json"
	healthy := uuid.NewString() + "-healthy.json"
	rolled := uuid.NewString() + "-rolled.json"
	weeklyReset := time.Now().Add(3 * 24 * time.Hour)

	// Process 1: one account hits its weekly limit, one is healthy, one was
	// rejected in a window that has since reset.
	before := quotaSignalTestManager(t, path, benched, healthy, rolled)
	observe(before, benched, http.StatusTooManyRequests, http.Header{
		"Anthropic-Ratelimit-Unified-7d-Status":      {"rejected"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"1.0"},
		"Anthropic-Ratelimit-Unified-7d-Reset":       {unixSignal(weeklyReset)},
	})
	observe(before, healthy, http.StatusOK, http.Header{
		"Anthropic-Ratelimit-Unified-7d-Status":      {"allowed"},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {"0.40"},
		"Anthropic-Ratelimit-Unified-7d-Reset":       {unixSignal(time.Now().Add(2 * 24 * time.Hour))},
	})
	observe(before, rolled, http.StatusOK, http.Header{
		"Anthropic-Ratelimit-Unified-7d-Status": {"rejected"},
		"Anthropic-Ratelimit-Unified-7d-Reset":  {unixSignal(time.Now().Add(-time.Hour))},
	})
	if errPersist := before.PersistQuotaSignals(context.Background()); errPersist != nil {
		t.Fatalf("persist: %v", errPersist)
	}
	if info, errStat := os.Stat(path); errStat != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot file not written with 0600: info=%v err=%v", info, errStat)
	}

	// Process 2: a fresh manager restores before any selection.
	after := quotaSignalTestManager(t, path, benched, healthy, rolled)
	if errRestore := after.RestoreQuotaSignals(context.Background()); errRestore != nil {
		t.Fatalf("restore: %v", errRestore)
	}

	got := mustAuth(t, after, benched)
	blocked, reason, next := isAuthBlockedForModel(got, reprobeTestSonnet, time.Now())
	if !blocked || reason != blockReasonCooldown {
		t.Fatalf("benched account selectable after restart: blocked=%v reason=%v", blocked, reason)
	}
	if diff := next.Sub(weeklyReset); diff < -time.Second || diff > time.Second {
		t.Fatalf("restored cooldown until %v, want the persisted reset %v", next, weeklyReset)
	}
	if got.Quota.Reason != "credential_quota" {
		t.Fatalf("restored cooldown reason = %q, want credential_quota", got.Quota.Reason)
	}
	for _, id := range []string{healthy, rolled} {
		if blocked, reason, _ := isAuthBlockedForModel(mustAuth(t, after, id), reprobeTestSonnet, time.Now()); blocked {
			t.Fatalf("account %s blocked after restart (reason=%v), want selectable", id, reason)
		}
	}
	if util := mustAuth(t, after, healthy).Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"]; util != "0.40" {
		t.Fatalf("healthy account signals not restored: %q", util)
	}
}

func TestQuotaSignals_RestoreKeepsLongerExistingCooldown(t *testing.T) {
	path := filepath.Join(t.TempDir(), QuotaSignalFileName)
	id := uuid.NewString() + "-longer.json"
	shortReset := time.Now().Add(2 * time.Hour)
	if errSave := NewFileQuotaSignalStore(path).Save(context.Background(), map[string]QuotaSignalSnapshot{
		id: {Provider: "claude", ObservedAt: time.Now().Add(-time.Minute), Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Status": "rejected",
			"Anthropic-Ratelimit-Unified-5h-Reset":  unixSignal(shortReset),
		}},
	}); errSave != nil {
		t.Fatalf("seed snapshot: %v", errSave)
	}

	m := quotaSignalTestManager(t, path, id)
	benchForWeeklyQuota(m, id) // e.g. restored from .cds state: 7 days
	if errRestore := m.RestoreQuotaSignals(context.Background()); errRestore != nil {
		t.Fatalf("restore: %v", errRestore)
	}
	if next := mustAuth(t, m, id).Quota.NextRecoverAt; next.Before(time.Now().Add(6 * 24 * time.Hour)) {
		t.Fatalf("restore shortened an existing 7d cooldown to %v", next)
	}
}

func TestQuotaSignals_StopPersistsFinalSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), QuotaSignalFileName)
	id := uuid.NewString() + "-shutdown.json"
	m := quotaSignalTestManager(t, path, id)
	m.StartQuotaSignalPersistence(context.Background(), time.Hour)
	observe(m, id, http.StatusOK, http.Header{"Anthropic-Ratelimit-Unified-7d-Utilization": {"0.25"}})
	m.StopQuotaSignalPersistence()

	snapshots, errLoad := NewFileQuotaSignalStore(path).Load(context.Background())
	if errLoad != nil {
		t.Fatalf("load: %v", errLoad)
	}
	if got := snapshots[id].Signals["Anthropic-Ratelimit-Unified-7d-Utilization"]; got != "0.25" {
		t.Fatalf("shutdown did not persist the latest observation: %+v", snapshots)
	}
}

// TestQuotaSignals_RestoredSignalsRankFirstSelection reproduces the startup race:
// the very first selections after a restart must already rank by soonest reset
// instead of rotating through credentials that only look unobserved.
func TestQuotaSignals_RestoredSignalsRankFirstSelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), QuotaSignalFileName)
	// IDs chosen so round-robin over "unknown" credentials would start elsewhere.
	soonest := "z-soonest-" + uuid.NewString() + ".json"
	later := "a-later-" + uuid.NewString() + ".json"
	nearlySpent := "b-spent-" + uuid.NewString() + ".json"
	if errSave := NewFileQuotaSignalStore(path).Save(context.Background(), map[string]QuotaSignalSnapshot{
		soonest: {Provider: "claude", ObservedAt: time.Now(), Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.30",
			"Anthropic-Ratelimit-Unified-7d-Reset":       unixSignal(time.Now().Add(2 * 24 * time.Hour)),
		}},
		later: {Provider: "claude", ObservedAt: time.Now(), Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.10",
			"Anthropic-Ratelimit-Unified-7d-Reset":       unixSignal(time.Now().Add(5 * 24 * time.Hour)),
		}},
		nearlySpent: {Provider: "claude", ObservedAt: time.Now(), Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Status":      "allowed_warning",
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.99",
			"Anthropic-Ratelimit-Unified-7d-Reset":       unixSignal(time.Now().Add(12 * time.Hour)),
		}},
	}); errSave != nil {
		t.Fatalf("seed snapshot: %v", errSave)
	}

	m := quotaSignalTestManager(t, path, soonest, later, nearlySpent)
	if errRestore := m.RestoreQuotaSignals(context.Background()); errRestore != nil {
		t.Fatalf("restore: %v", errRestore)
	}
	auths := []*Auth{mustAuth(t, m, soonest), mustAuth(t, m, later), mustAuth(t, m, nearlySpent)}
	if blocked, _, _ := isAuthBlockedForModel(auths[2], reprobeTestSonnet, time.Now()); blocked {
		t.Fatal("a 0.99-utilized account must stay selectable (ranked last), not be benched")
	}
	selector := &SoonestResetSelector{}
	for i := 0; i < 3; i++ {
		got, errPick := selector.Pick(context.Background(), "claude", reprobeTestSonnet, cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatalf("pick #%d: %v", i, errPick)
		}
		if got.ID != soonest {
			t.Fatalf("pick #%d = %s, want soonest-reset account with headroom %s", i, got.ID, soonest)
		}
	}
}

// Config-defined credentials are re-synthesized and pushed through Update after
// startup. The incoming auth carries no observation; the restored one must survive
// even when the credential is not cooling (only cooling ones used to keep it).
func TestQuotaSignals_UpdateKeepsObservationOfHealthyCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), QuotaSignalFileName)
	id := uuid.NewString() + "-config-key"
	reset := unixSignal(time.Now().Add(3 * 24 * time.Hour))
	if errSave := NewFileQuotaSignalStore(path).Save(context.Background(), map[string]QuotaSignalSnapshot{
		id: {Provider: "claude", ObservedAt: time.Now().Add(-time.Minute), Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.04",
			"Anthropic-Ratelimit-Unified-7d-Reset":       reset,
		}},
	}); errSave != nil {
		t.Fatalf("seed snapshot: %v", errSave)
	}
	m := quotaSignalTestManager(t, path, id)
	if errRestore := m.RestoreQuotaSignals(context.Background()); errRestore != nil {
		t.Fatalf("restore: %v", errRestore)
	}
	fresh := &Auth{ID: id, Provider: "claude", Attributes: map[string]string{"api_key": "test-key"}}
	if _, errUpdate := m.Update(WithSkipPersist(context.Background()), fresh); errUpdate != nil {
		t.Fatalf("update: %v", errUpdate)
	}
	if got := mustAuth(t, m, id).Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"]; got != reset {
		t.Fatalf("restored observation lost on re-registration: signals=%v", mustAuth(t, m, id).Quota.Signals)
	}
}
