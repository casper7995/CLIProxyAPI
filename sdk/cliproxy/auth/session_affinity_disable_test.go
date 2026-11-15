package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestManagerDisableClearsSessionAffinity(t *testing.T) {
	ctx := context.Background()
	selector := NewSessionAffinitySelector(&SoonestResetSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	manager.executors["claude"] = schedulerTestExecutor{provider: "claude"}

	now := time.Now()
	const model = "claude-opus-5-5"
	register := func(auth *Auth) {
		t.Helper()
		registry.GetGlobalRegistry().RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatalf("Register(%s): %v", auth.ID, err)
		}
	}

	authA := claudeAuth("auth-a", &claudeWindow{reset7d: now.Add(48 * time.Hour)})
	authA.Status = StatusActive
	register(authA)

	sessionOpts := cliproxyexecutor.Options{
		Headers:  http.Header{"X-Session-ID": []string{"sess-disable-affinity"}},
		Metadata: map[string]any{},
	}
	pick := func(label string) string {
		t.Helper()
		got, err := manager.SelectAuth(ctx, "claude", model, sessionOpts)
		if err != nil {
			t.Fatalf("%s: SelectAuth: %v", label, err)
		}
		if got == nil {
			t.Fatalf("%s: SelectAuth returned nil auth", label)
		}
		return got.ID
	}

	if got := pick("initial bind"); got != "auth-a" {
		t.Fatalf("initial bind = %s, want auth-a", got)
	}

	authB := claudeAuth("auth-b", &claudeWindow{reset7d: now.Add(2 * time.Hour)})
	authB.Status = StatusActive
	register(authB)

	if got := pick("affinity holds after better candidate appears"); got != "auth-a" {
		t.Fatalf("after registering sooner-reset auth-b, pick = %s, want auth-a (affinity)", got)
	}

	_, committed, err := manager.Modify(ctx, "auth-a", 0, func(current *Auth) error {
		// Non-disable update: quota signals / status message only.
		if current.Quota.Signals == nil {
			current.Quota.Signals = map[string]string{}
		}
		current.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "0.1"
		current.Quota.ObservedAt = time.Now()
		current.StatusMessage = "quota snapshot"
		return nil
	})
	if err != nil || !committed {
		t.Fatalf("non-disable Modify: committed=%v err=%v", committed, err)
	}
	if got := pick("affinity holds after non-disable update"); got != "auth-a" {
		t.Fatalf("after quota-signal update, pick = %s, want auth-a", got)
	}

	_, committed, err = manager.Modify(ctx, "auth-a", 0, func(current *Auth) error {
		current.Disabled = true
		current.Status = StatusDisabled
		current.StatusMessage = "disabled via test"
		return nil
	})
	if err != nil || !committed {
		t.Fatalf("disable Modify: committed=%v err=%v", committed, err)
	}

	if _, status := manager.LookupSessionAffinity("claude", model, "sess-disable-affinity"); status == "bound" {
		t.Fatalf("LookupSessionAffinity status = %s, want binding cleared after disable", status)
	}
	if got := pick("rebind after disable"); got != "auth-b" {
		t.Fatalf("after disabling auth-a, pick = %s, want auth-b (soonest-reset)", got)
	}
}
