package auth

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Full request-path selection tests built on the live signals of 11 Nov 2026,
// when reprobe2 (73eb26ad) bound new sessions to founder, ops, casper.hsieh and
// gmail instead of msn. Requests go through Manager.Execute / ExecuteStream,
// which select on the provider=mixed path behind session affinity with
// soonest-reset, exactly as production is configured.

const (
	liveModel       = "claude-opus-5-5"
	liveFounder     = "claude-291913e3-founder@endurancecoaching.ai.json"
	liveOps         = "claude-4949e4b1-ops@endurancecoaching.ai.json"
	liveCasperHsieh = "claude-5e8b6774-casper.hsieh@endurancecoaching.ai.json"
	liveMSN         = "claude-627d100c-casper7995@msn.com.json"
	liveGmail       = "claude-88efcacc-chsieh7995@gmail.com.json"
	// liveThinkgym is the sixth account, configured at priority -1. Its file
	// name and signals are fixtures; its reset is the soonest of all so the
	// test proves priority, not reset order, keeps it out.
	liveThinkgym = "claude-thinkgym-fixture.json"
)

var liveAccounts = []string{liveFounder, liveOps, liveCasperHsieh, liveMSN, liveGmail, liveThinkgym}

func liveShortName(id string) string {
	for _, name := range []string{"founder", "ops", "casper.hsieh", "msn", "gmail", "thinkgym"} {
		if strings.Contains(id, name) {
			return name
		}
	}
	return id
}

// liveIncidentAt is 11 Nov 2026 13:46:27 SGT. Fixture resets keep their real
// distance from it, shifted to the test clock, so the scenario stays valid
// after the real dates pass.
var liveIncidentAt = time.Date(2026, 11, 11, 5, 46, 27, 0, time.UTC)

func liveReset(unix int64) time.Time {
	return time.Now().Add(time.Unix(unix, 0).Sub(liveIncidentAt))
}

type liveWindow struct {
	status string
	util   string
	reset  time.Time
}

func (w liveWindow) headers() http.Header {
	return http.Header{
		"Anthropic-Ratelimit-Unified-Status":         {w.status},
		"Anthropic-Ratelimit-Unified-7d-Status":      {w.status},
		"Anthropic-Ratelimit-Unified-7d-Utilization": {w.util},
		"Anthropic-Ratelimit-Unified-7d-Reset":       {strconv.FormatInt(w.reset.Unix(), 10)},
	}
}

func liveFixtureWindows() map[string]liveWindow {
	return map[string]liveWindow{
		liveMSN:         {"allowed", "0.04", liveReset(1794600000)}, // Sat 14 Nov 04:00 SGT
		liveOps:         {"allowed", "0.12", liveReset(1794934800)}, // Wed 18 Nov 01:00 SGT
		liveFounder:     {"allowed", "0.01", liveReset(1794970800)}, // Wed 18 Nov 11:00 SGT
		liveCasperHsieh: {"rejected", "1.0", liveReset(1794600000)},
		liveGmail:       {"rejected", "1.0", liveReset(1794542400)}, // Fri 13 Nov 12:00 SGT
		liveThinkgym:    {"allowed", "0.00", liveReset(1794420000)}, // fixture: Thu 12 Nov 02:00 SGT
	}
}

// liveUpstream answers like Anthropic for each account: the account's current
// unified headers, and a credential-scoped 429 while its window is rejected.
type liveUpstream struct {
	mu       sync.Mutex
	windows  map[string]liveWindow
	attempts []string
}

func (u *liveUpstream) set(id string, w liveWindow) {
	u.mu.Lock()
	u.windows[id] = w
	u.mu.Unlock()
}

func (u *liveUpstream) answer(ctx context.Context, auth *Auth) (http.Header, error) {
	u.mu.Lock()
	w := u.windows[auth.ID]
	u.attempts = append(u.attempts, auth.ID)
	u.mu.Unlock()
	headers := w.headers()
	internallogging.SetResponseHeaders(ctx, headers)
	if w.status == "rejected" {
		return headers, reprobeTestRateLimitError{retryAfter: time.Until(w.reset)}
	}
	return headers, nil
}

func (u *liveUpstream) takeAttempts() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := u.attempts
	u.attempts = nil
	return out
}

func (u *liveUpstream) Identifier() string { return "claude" }

func (u *liveUpstream) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if _, err := u.answer(ctx, auth); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}`)}, nil
}

func (u *liveUpstream) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	headers, err := u.answer(ctx, auth)
	if err != nil {
		return nil, err
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n")}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: chunks}, nil
}

func (u *liveUpstream) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }
func (u *liveUpstream) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (u *liveUpstream) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// liveProcess starts one proxy lifetime: a fresh manager and affinity cache,
// restoring quota signals from the snapshot file before the first request.
func liveProcess(t *testing.T, snapshotPath string, upstream *liveUpstream) *Manager {
	t.Helper()
	m := NewManager(nil, nil, nil)
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &SoonestResetSelector{}, TTL: time.Hour})
	t.Cleanup(affinity.Stop)
	m.SetSelector(affinity)
	m.RegisterExecutor(upstream)
	m.SetConfig(nil)
	reg := registry.GetGlobalRegistry()
	for _, id := range liveAccounts {
		reg.RegisterClient(id, "claude", []*registry.ModelInfo{{ID: liveModel}, {ID: reprobeTestHaiku}})
		auth := &Auth{ID: id, FileName: id, Provider: "claude", Status: StatusActive, Attributes: map[string]string{"api_key": "fixture-key"}}
		if id == liveThinkgym {
			auth.Attributes["priority"] = "-1"
		}
		if _, errRegister := m.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}
	m.SetQuotaSignalStore(NewFileQuotaSignalStore(snapshotPath))
	if errRestore := m.RestoreQuotaSignals(context.Background()); errRestore != nil {
		t.Fatalf("restore quota signals: %v", errRestore)
	}
	return m
}

type liveRequestPath struct {
	name string
	send func(m *Manager, session string) error
}

func liveRequest(session string) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	payload := []byte(`{"model":"` + liveModel + `","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)
	format := sdktranslator.FromString("claude")
	return cliproxyexecutor.Request{Model: liveModel, Payload: payload, Format: format},
		cliproxyexecutor.Options{
			SourceFormat:    format,
			OriginalRequest: payload,
			Headers:         http.Header{"X-Claude-Code-Session-Id": {session}},
		}
}

var liveRequestPaths = []liveRequestPath{
	{"Execute (provider=mixed)", func(m *Manager, session string) error {
		req, opts := liveRequest(session)
		_, err := m.Execute(context.Background(), []string{"claude"}, req, opts)
		return err
	}},
	{"ExecuteStream (provider=mixed)", func(m *Manager, session string) error {
		req, opts := liveRequest(session)
		opts.Stream = true
		result, err := m.ExecuteStream(context.Background(), []string{"claude"}, req, opts)
		if err != nil {
			return err
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				return chunk.Err
			}
		}
		return nil
	}},
}

func TestSoonestResetLive_FullRequestPath(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })
	t.Cleanup(func() {
		for _, id := range liveAccounts {
			registry.GetGlobalRegistry().UnregisterClient(id)
		}
	})

	for _, path := range liveRequestPaths {
		t.Run(path.name, func(t *testing.T) {
			windows := liveFixtureWindows()
			upstream := &liveUpstream{windows: windows}
			snapshotPath := filepath.Join(t.TempDir(), QuotaSignalFileName)
			snapshots := make(map[string]QuotaSignalSnapshot)
			for id, w := range windows {
				signals := map[string]string{}
				for name, values := range w.headers() {
					signals[name] = values[0]
				}
				snapshots[id] = QuotaSignalSnapshot{Provider: "claude", ObservedAt: time.Now().Add(-time.Minute), Signals: signals}
			}
			if errSave := NewFileQuotaSignalStore(snapshotPath).Save(context.Background(), snapshots); errSave != nil {
				t.Fatalf("seed snapshot: %v", errSave)
			}

			var m *Manager
			restart := func() {
				if m != nil {
					if errPersist := m.PersistQuotaSignals(context.Background()); errPersist != nil {
						t.Fatalf("persist before restart: %v", errPersist)
					}
				}
				m = liveProcess(t, snapshotPath, upstream)
			}
			benched := func(id string) bool {
				auth, _ := m.GetByID(id)
				blocked, _, _ := isAuthBlockedForModel(auth, liveModel, time.Now())
				return blocked
			}

			type step struct {
				label        string
				before       func()
				session      string
				wantAttempts []string
				after        func()
			}
			steps := []step{
				{label: "startup with snapshot", before: restart, after: func() {
					for _, id := range []string{liveCasperHsieh, liveGmail} {
						if !benched(id) {
							t.Fatalf("%s not benched after snapshot restore", liveShortName(id))
						}
					}
				}},
				{label: "new binding", session: "s1", wantAttempts: []string{liveMSN}},
				{label: "new binding", session: "s2", wantAttempts: []string{liveMSN}},
				{label: "new binding", session: "s3", wantAttempts: []string{liveMSN}},
				{label: "existing binding", session: "s1", wantAttempts: []string{liveMSN}},
				{label: "msn starts returning 429", before: func() {
					upstream.set(liveMSN, liveWindow{"rejected", "1.0", windows[liveMSN].reset})
				}},
				{label: "new binding, msn 429 fails over", session: "s4", wantAttempts: []string{liveMSN, liveOps}, after: func() {
					if !benched(liveMSN) {
						t.Fatal("msn not benched after its 429")
					}
				}},
				{label: "existing binding on benched msn", session: "s1", wantAttempts: []string{liveOps}},
				{label: "new binding", session: "s5", wantAttempts: []string{liveOps}},
				{label: "existing binding", session: "s4", wantAttempts: []string{liveOps}},
				{label: "restart", before: restart, after: func() {
					for _, id := range []string{liveMSN, liveCasperHsieh, liveGmail} {
						if !benched(id) {
							t.Fatalf("%s not benched after restart", liveShortName(id))
						}
					}
				}},
				{label: "new binding after restart", session: "s6", wantAttempts: []string{liveOps}},
				{label: "pre-restart session (cache lost)", session: "s1", wantAttempts: []string{liveOps}},
				{label: "msn reset passes, re-probe observes it", before: func() {
					fresh := liveWindow{"allowed", "0.00", time.Now().Add(7 * 24 * time.Hour)}
					upstream.set(liveMSN, fresh)
					// Move msn's stored deadline and window to the past, as when its reset time arrives.
					past := time.Now().Add(-time.Second)
					m.mu.Lock()
					auth := m.auths[liveMSN]
					auth.Quota.NextRecoverAt, auth.NextRetryAfter = past, past
					for _, state := range auth.ModelStates {
						state.NextRetryAfter, state.Quota.NextRecoverAt = past, past
					}
					auth.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Reset"] = strconv.FormatInt(past.Unix(), 10)
					m.mu.Unlock()
					m.cooldownReprobeSweep(context.Background(), noReprobeWait, true)
					if got := upstream.takeAttempts(); !slices.Contains(got, liveMSN) {
						t.Fatalf("re-probe did not observe recovered msn; probed %v", got)
					}
				}, after: func() {
					if benched(liveMSN) {
						t.Fatal("msn still benched after its reset passed")
					}
				}},
				// msn's next reset is now 7 days out, after ops (18 Nov 01:00), so
				// soonest-reset correctly keeps ops first.
				{label: "new binding, msn back with a later reset", session: "s7", wantAttempts: []string{liveOps}},
				{label: "ops and founder become exhausted", before: func() {
					upstream.set(liveOps, liveWindow{"rejected", "1.0", windows[liveOps].reset})
					upstream.set(liveFounder, liveWindow{"rejected", "1.0", windows[liveFounder].reset})
				}},
				{label: "new binding, recovered msn used again", session: "s8", wantAttempts: []string{liveOps, liveFounder, liveMSN}},
				{label: "new binding", session: "s9", wantAttempts: []string{liveMSN}},
			}

			t.Logf("%-3s %-42s %-8s %s", "#", "step", "session", "attempts (last = served)")
			request := 0
			for _, s := range steps {
				if s.before != nil {
					s.before()
				}
				if s.session != "" {
					request++
					upstream.takeAttempts()
					if errSend := path.send(m, s.session); errSend != nil {
						t.Fatalf("%s %s: request failed: %v", s.label, s.session, errSend)
					}
					got := upstream.takeAttempts()
					names := make([]string, len(got))
					for i, id := range got {
						names[i] = liveShortName(id)
					}
					t.Logf("%-3d %-42s %-8s %s", request, s.label, s.session, strings.Join(names, " -> "))
					if !slices.Equal(got, s.wantAttempts) {
						want := make([]string, len(s.wantAttempts))
						for i, id := range s.wantAttempts {
							want[i] = liveShortName(id)
						}
						t.Fatalf("%s %s: attempts %v, want %v", s.label, s.session, names, want)
					}
					for _, id := range got {
						if id == liveCasperHsieh || id == liveGmail || id == liveThinkgym {
							t.Fatalf("%s %s: %s must never be chosen", s.label, s.session, liveShortName(id))
						}
					}
				} else {
					t.Logf("--  %s", s.label)
				}
				if s.after != nil {
					s.after()
				}
			}
		})
	}
}

// TestSoonestResetLive_UnobservedAccountsDoNotOutrankMSN replays the 13:46 cold
// start on the mixed path: only msn and founder had reported; ops was still
// streaming its first response and casper.hsieh and gmail were exhausted but
// unobserved. Unobserved accounts must not win new bindings over msn.
func TestSoonestResetLive_UnobservedAccountsDoNotOutrankMSN(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })
	t.Cleanup(func() {
		for _, id := range liveAccounts {
			registry.GetGlobalRegistry().UnregisterClient(id)
		}
	})

	windows := liveFixtureWindows()
	m := liveProcess(t, filepath.Join(t.TempDir(), QuotaSignalFileName), &liveUpstream{windows: windows})
	m.mu.Lock()
	for _, id := range []string{liveMSN, liveFounder} {
		signals := map[string]string{}
		for name, values := range windows[id].headers() {
			signals[name] = values[0]
		}
		m.auths[id].Quota.Signals = signals
		m.auths[id].Quota.ObservedAt = time.Now()
	}
	m.mu.Unlock()
	for session := range 5 {
		opts := cliproxyexecutor.Options{Metadata: map[string]any{
			cliproxyexecutor.DerivedSessionIDMetadataKey: fmt.Sprintf("cold-%d", session),
		}}
		auth, _, _, errPick := m.pickNextMixed(context.Background(), []string{"claude"}, liveModel, opts, nil)
		if errPick != nil {
			t.Fatalf("session %d: %v", session, errPick)
		}
		if auth.ID != liveMSN {
			t.Fatalf("session %d bound to %s, want msn (unobserved accounts outranked the soonest reset)", session, liveShortName(auth.ID))
		}
	}
}
