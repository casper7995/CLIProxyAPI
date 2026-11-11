package auth

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type claudeWindow struct {
	reset7d  time.Time
	raw7d    string
	status7d string
	reset5h  time.Time
	status5h string
	util5h   string
}

func claudeAuth(id string, w *claudeWindow) *Auth {
	auth := &Auth{ID: id, Provider: "claude"}
	if w == nil {
		return auth
	}
	signals := map[string]string{}
	switch {
	case w.raw7d != "":
		signals["Anthropic-Ratelimit-Unified-7d-Reset"] = w.raw7d
	case !w.reset7d.IsZero():
		signals["Anthropic-Ratelimit-Unified-7d-Reset"] = strconv.FormatInt(w.reset7d.Unix(), 10)
	}
	if !w.reset5h.IsZero() {
		signals["Anthropic-Ratelimit-Unified-5h-Reset"] = strconv.FormatInt(w.reset5h.Unix(), 10)
	}
	if w.status7d != "" {
		signals["Anthropic-Ratelimit-Unified-7d-Status"] = w.status7d
	}
	if w.status5h != "" {
		signals["Anthropic-Ratelimit-Unified-5h-Status"] = w.status5h
	}
	if w.util5h != "" {
		signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = w.util5h
	}
	auth.Quota.Signals = signals
	auth.Quota.ObservedAt = time.Now()
	return auth
}

func pickIDs(t *testing.T, selector Selector, provider string, auths []*Auth, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		got, err := selector.Pick(context.Background(), provider, "claude-opus", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() #%d error = %v", i, err)
		}
		if got == nil {
			t.Fatalf("Pick() #%d auth = nil", i)
		}
		ids = append(ids, got.ID)
	}
	return ids
}

func TestSoonestResetSelectorPick_Order(t *testing.T) {
	t.Parallel()

	now := time.Now()
	day := 24 * time.Hour

	tests := []struct {
		name  string
		auths []*Auth
		want  string
	}{
		{
			name: "soonest 7d reset wins",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(5 * day)}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(1 * day)}),
				claudeAuth("c", &claudeWindow{reset7d: now.Add(3 * day)}),
			},
			want: "b",
		},
		{
			name: "observed account with headroom beats an unobserved one",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(6 * day)}),
				claudeAuth("z", nil),
			},
			want: "a",
		},
		{
			name: "unparseable reset counts as unknown",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(6 * day)}),
				claudeAuth("z", &claudeWindow{raw7d: "soon"}),
			},
			want: "a",
		},
		{
			name: "past 7d reset counts as unknown",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(6 * day)}),
				claudeAuth("z", &claudeWindow{reset7d: now.Add(-time.Hour)}),
			},
			want: "a",
		},
		{
			name: "unobserved account beats a rejected one",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(time.Hour), status7d: "rejected"}),
				claudeAuth("z", nil),
			},
			want: "z",
		},
		{
			name: "7d rejected goes after later known resets",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(time.Hour), status7d: "rejected"}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(6 * day), status7d: "allowed"}),
			},
			want: "b",
		},
		{
			name: "5h rejected goes after later known resets",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(time.Hour), reset5h: now.Add(time.Hour), status5h: "rejected"}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(6 * day)}),
			},
			want: "b",
		},
		{
			name: "5h rejection whose reset passed no longer demotes",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(time.Hour), reset5h: now.Add(-time.Minute), status5h: "rejected"}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(6 * day)}),
			},
			want: "a",
		},
		{
			name: "rejected accounts ordered by when the rejection lifts",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(4 * day), status7d: "rejected"}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(5 * day), reset5h: now.Add(time.Hour), status5h: "rejected"}),
			},
			want: "b",
		},
		{
			name: "equal reset breaks tie on lower 5h utilization",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(day), util5h: "0.80"}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(day), util5h: "0.10"}),
			},
			want: "b",
		},
		{
			name: "missing 5h utilization sorts after a known one",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(day)}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(day), util5h: "0.95"}),
			},
			want: "b",
		},
		{
			name: "full tie breaks on auth ID",
			auths: []*Auth{
				claudeAuth("b", &claudeWindow{reset7d: now.Add(day), util5h: "0.5"}),
				claudeAuth("a", &claudeWindow{reset7d: now.Add(day), util5h: "0.5"}),
			},
			want: "a",
		},
		{
			name: "only the highest priority tier is considered",
			auths: func() []*Auth {
				low := claudeAuth("low", &claudeWindow{reset7d: now.Add(time.Hour)})
				low.Attributes = map[string]string{"priority": "0"}
				high := claudeAuth("high", &claudeWindow{reset7d: now.Add(6 * day)})
				high.Attributes = map[string]string{"priority": "10"}
				return []*Auth{low, high}
			}(),
			want: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			selector := &SoonestResetSelector{}
			got := pickIDs(t, selector, "claude", tt.auths, 3)
			for i, id := range got {
				if id != tt.want {
					t.Fatalf("Pick() #%d = %q, want %q (all picks %v)", i, id, tt.want, got)
				}
			}
		})
	}
}

func TestSoonestResetSelectorPick_UnknownAccountsRoundRobin(t *testing.T) {
	t.Parallel()

	now := time.Now()
	// Unobserved accounts rotate among themselves once no observed account has headroom.
	auths := []*Auth{
		claudeAuth("spent", &claudeWindow{reset7d: now.Add(time.Hour), status7d: "rejected"}),
		claudeAuth("u2", nil),
		claudeAuth("u1", &claudeWindow{reset7d: now.Add(-time.Hour)}),
	}
	got := pickIDs(t, &SoonestResetSelector{}, "claude", auths, 4)
	want := []string{"u1", "u2", "u1", "u2"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picks = %v, want %v", got, want)
		}
	}
}

func TestSoonestResetSelectorPick_FallsBackToRoundRobin(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name     string
		provider string
		auths    []*Auth
	}{
		{
			name:     "non-Claude candidates",
			provider: "gemini",
			auths:    []*Auth{{ID: "b", Provider: "gemini"}, {ID: "a", Provider: "gemini"}, {ID: "c", Provider: "gemini"}},
		},
		{
			name:     "Claude candidates without signals",
			provider: "claude",
			auths:    []*Auth{claudeAuth("b", nil), claudeAuth("a", nil), claudeAuth("c", nil)},
		},
		{
			name:     "mixed pool with a non-Claude candidate",
			provider: "mixed",
			auths: []*Auth{
				claudeAuth("a", &claudeWindow{reset7d: now.Add(time.Hour)}),
				claudeAuth("b", &claudeWindow{reset7d: now.Add(2 * time.Hour)}),
				{ID: "c", Provider: "codex"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := pickIDs(t, &SoonestResetSelector{}, tt.provider, tt.auths, 4)
			want := []string{"a", "b", "c", "a"}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("picks = %v, want %v", got, want)
				}
			}
		})
	}
}

func TestSoonestResetSelectorPick_NoCandidates(t *testing.T) {
	t.Parallel()

	if _, err := (&SoonestResetSelector{}).Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil); err == nil {
		t.Fatal("Pick() with no candidates error = nil, want error")
	}
}

func TestSoonestResetSelectorPick_Concurrent(t *testing.T) {
	now := time.Now()
	selector := &SoonestResetSelector{}
	auths := []*Auth{
		claudeAuth("spent", &claudeWindow{reset7d: now.Add(time.Hour), status7d: "rejected"}),
		claudeAuth("u1", nil),
		claudeAuth("u2", nil),
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	counts := map[string]int{}
	errs := make(chan error, 1)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				got, err := selector.Pick(context.Background(), "claude", "claude-opus", cliproxyexecutor.Options{}, auths)
				if err != nil || got == nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				mu.Lock()
				counts[got.ID]++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	select {
	case err := <-errs:
		t.Fatalf("concurrent Pick() failed: %v", err)
	default:
	}
	if counts["spent"] != 0 || counts["u1"] != 1600 || counts["u2"] != 1600 {
		t.Fatalf("counts = %v, want u1=1600 u2=1600 spent=0", counts)
	}
}

func TestManagerSoonestResetSelectorReadsRegisteredQuotaSignals(t *testing.T) {
	now := time.Now()
	for _, tt := range []struct {
		name     string
		selector Selector
	}{
		{name: "plain", selector: &SoonestResetSelector{}},
		{name: "session affinity fallback", selector: NewSessionAffinitySelector(&SoonestResetSelector{})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(nil, tt.selector, nil)
			manager.executors["claude"] = schedulerTestExecutor{}
			for _, auth := range []*Auth{
				claudeAuth("a-late", &claudeWindow{reset7d: now.Add(6 * 24 * time.Hour)}),
				claudeAuth("b-soon", &claudeWindow{reset7d: now.Add(2 * time.Hour)}),
				claudeAuth("c-mid", &claudeWindow{reset7d: now.Add(3 * 24 * time.Hour)}),
			} {
				if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
					t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
				}
			}
			for i := 0; i < 3; i++ {
				got, _, errPick := manager.pickNext(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
				if errPick != nil {
					t.Fatalf("pickNext() error = %v", errPick)
				}
				if got == nil || got.ID != "b-soon" {
					t.Fatalf("pickNext() #%d = %v, want b-soon", i, got)
				}
			}
		})
	}
}

func claudeSignalsAuth(id string, signals map[string]string) *Auth {
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{Signals: signals, ObservedAt: time.Now()}}
}

func TestSoonestResetSelectorPick_NearLimitAccountsRankLast(t *testing.T) {
	now := time.Now()
	reset := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	spent7d := claudeSignalsAuth("a-spent-7d", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed_warning",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.99",
		"Anthropic-Ratelimit-Unified-7d-Reset":       reset(24 * time.Hour),
	})
	rejected7d := claudeSignalsAuth("b-rejected-7d", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status": "rejected",
		"Anthropic-Ratelimit-Unified-7d-Reset":  reset(12 * time.Hour),
	})
	spent5h := claudeSignalsAuth("c-spent-5h", map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": "0.985",
		"Anthropic-Ratelimit-Unified-5h-Reset":       reset(time.Hour),
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.20",
		"Anthropic-Ratelimit-Unified-7d-Reset":       reset(6 * time.Hour),
	})
	headroomSoon := claudeSignalsAuth("d-headroom-soon", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.50",
		"Anthropic-Ratelimit-Unified-7d-Reset":       reset(3 * 24 * time.Hour),
	})
	headroomLate := claudeSignalsAuth("e-headroom-late", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.20",
		"Anthropic-Ratelimit-Unified-7d-Reset":       reset(5 * 24 * time.Hour),
	})

	selector := &SoonestResetSelector{}
	all := []*Auth{spent7d, rejected7d, spent5h, headroomSoon, headroomLate}
	if got := pickIDs(t, selector, "claude", all, 3); got[0] != headroomSoon.ID || got[1] != headroomSoon.ID || got[2] != headroomSoon.ID {
		t.Fatalf("picks = %v, want the soonest-reset account with headroom %s", got, headroomSoon.ID)
	}
	if got := pickIDs(t, selector, "claude", []*Auth{spent7d, headroomLate}, 1); got[0] != headroomLate.ID {
		t.Fatalf("pick = %v, want headroom account over 0.99-utilized one", got)
	}
	// With only spent accounts left, the one whose window lifts first wins.
	if got := pickIDs(t, selector, "claude", []*Auth{spent7d, rejected7d, spent5h}, 1); got[0] != spent5h.ID {
		t.Fatalf("pick = %v, want the spent account that lifts first %s", got, spent5h.ID)
	}
}

func TestSoonestResetSelectorPick_NearLimitWindowAlreadyReset(t *testing.T) {
	now := time.Now()
	// The 0.99 reading belongs to a window that already rolled over, so it no longer applies.
	rolled := claudeSignalsAuth("a-rolled", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.99",
		"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(now.Add(-time.Hour).Unix(), 10),
	})
	spent := claudeSignalsAuth("b-spent", map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.99",
		"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
	})
	if got := pickIDs(t, &SoonestResetSelector{}, "claude", []*Auth{spent, rolled}, 1); got[0] != rolled.ID {
		t.Fatalf("pick = %v, want the rolled-over account %s", got, rolled.ID)
	}
}
