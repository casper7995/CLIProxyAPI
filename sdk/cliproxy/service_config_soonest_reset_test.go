package cliproxy

import (
	"context"
	"strconv"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestSoonestResetRoutingStrategyNames(t *testing.T) {
	for _, input := range []string{"soonest-reset", "SoonestReset", " sr "} {
		state := normalizedRoutingRuntimeState(&internalconfig.Config{
			Routing: internalconfig.RoutingConfig{Strategy: input},
		})
		if state.strategy != "soonest-reset" {
			t.Fatalf("strategy(%q) = %q, want soonest-reset", input, state.strategy)
		}
	}
}

func TestSoonestResetRoutingSelector(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "soonest-reset"},
	})
	if _, ok := newRoutingSelector(state).(*coreauth.SoonestResetSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.SoonestResetSelector", newRoutingSelector(state))
	}
}

func TestSoonestResetRoutingSelectorWithSessionAffinityFallsBackToSoonestReset(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "soonest-reset", SessionAffinity: true},
	})
	affinity, ok := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want *auth.SessionAffinitySelector", newRoutingSelector(state))
	}
	defer affinity.Stop()

	now := time.Now()
	auth := func(id string, reset time.Duration) *coreauth.Auth {
		a := &coreauth.Auth{ID: id, Provider: "claude"}
		a.Quota.Signals = map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(now.Add(reset).Unix(), 10),
		}
		return a
	}
	auths := []*coreauth.Auth{auth("a", 6*24*time.Hour), auth("b", time.Hour), auth("c", 3*24*time.Hour)}

	// No session signal in the request, so the affinity selector delegates to its fallback;
	// a round-robin fallback would return "a".
	for i := 0; i < 3; i++ {
		got, err := affinity.Pick(context.Background(), "claude", "claude-opus", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		if got == nil || got.ID != "b" {
			t.Fatalf("Pick() #%d = %v, want b", i, got)
		}
	}
}
