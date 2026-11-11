package helps

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The software tuple measured from Claude Code 2.1.322 on 11 Nov 2026. The
// baseline (2.1.280 / 0.112.1 / v26.3.0) is a floor: a genuine newer client
// keeps its own tuple, otherwise Claude Code reports a version mismatch.
const (
	measured2_1_322UA      = "claude-cli/2.1.322 (external, cli)"
	measured2_1_322Package = "0.128.0"
	measured2_1_322Runtime = "v26.12.1"
)

func claudeCodeTupleHeaders(ua, pkg, runtime string) http.Header {
	return http.Header{
		"User-Agent":                  {ua},
		"X-Stainless-Package-Version": {pkg},
		"X-Stainless-Runtime-Version": {runtime},
		"X-Stainless-Os":              {"Linux"},
		"X-Stainless-Arch":            {"x64"},
	}
}

func legacyUpstreamHeaders(t *testing.T, incoming http.Header, confirmed bool) http.Header {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	ApplyClaudeLegacyDeviceHeaders(r, incoming, nil, confirmed)
	return r.Header
}

func assertTuple(t *testing.T, got http.Header, ua, pkg, runtime string) {
	t.Helper()
	if got.Get("User-Agent") != ua || got.Get("X-Stainless-Package-Version") != pkg || got.Get("X-Stainless-Runtime-Version") != runtime {
		t.Fatalf("upstream tuple = %q / %q / %q, want %q / %q / %q",
			got.Get("User-Agent"), got.Get("X-Stainless-Package-Version"), got.Get("X-Stainless-Runtime-Version"), ua, pkg, runtime)
	}
}

func TestClaudeDeviceFloor_NewerClaudeCodePassesThrough(t *testing.T) {
	incoming := claudeCodeTupleHeaders(measured2_1_322UA, measured2_1_322Package, measured2_1_322Runtime)

	got := legacyUpstreamHeaders(t, incoming, true)
	assertTuple(t, got, measured2_1_322UA, measured2_1_322Package, measured2_1_322Runtime)
	if got.Get("X-Stainless-Os") != "Linux" || got.Get("X-Stainless-Arch") != "x64" {
		t.Fatalf("platform = %q/%q, want the client's Linux/x64", got.Get("X-Stainless-Os"), got.Get("X-Stainless-Arch"))
	}

	ResetClaudeDeviceProfileCache()
	profile := resolveClaudeDeviceProfileLocal(&cliproxyauth.Auth{ID: "auth-floor-pass"}, "", incoming, nil)
	if profile.UserAgent != measured2_1_322UA || profile.PackageVersion != measured2_1_322Package || profile.RuntimeVersion != measured2_1_322Runtime {
		t.Fatalf("stabilized profile = %#v, want the 2.1.322 tuple", profile)
	}
}

func TestClaudeDeviceFloor_OlderClaudeCodeGetsTheFloor(t *testing.T) {
	incoming := claudeCodeTupleHeaders("claude-cli/2.1.250 (external, cli)", "0.110.0", "v26.1.0")

	got := legacyUpstreamHeaders(t, incoming, true)
	assertTuple(t, got, defaultClaudeFingerprintUserAgent, defaultClaudeFingerprintPackageVersion, defaultClaudeFingerprintRuntimeVersion)

	ResetClaudeDeviceProfileCache()
	profile := resolveClaudeDeviceProfileLocal(&cliproxyauth.Auth{ID: "auth-floor-old"}, "", incoming, nil)
	if profile.UserAgent != defaultClaudeFingerprintUserAgent {
		t.Fatalf("stabilized profile = %#v, want the baseline floor", profile)
	}

	// A newer UA paired with an SDK package below the floor is not a coherent
	// client tuple, so it is floored as a whole rather than mixed.
	mixed := claudeCodeTupleHeaders(measured2_1_322UA, "0.100.0", measured2_1_322Runtime)
	assertTuple(t, legacyUpstreamHeaders(t, mixed, true),
		defaultClaudeFingerprintUserAgent, defaultClaudeFingerprintPackageVersion, defaultClaudeFingerprintRuntimeVersion)
}

func TestClaudeDeviceFloor_NonClaudeCodeClientGetsTheBaseline(t *testing.T) {
	for name, incoming := range map[string]http.Header{
		"third-party UA":        claudeCodeTupleHeaders("lobe-chat/1.0", "0.10.0", "v18.0.0"),
		"copied UA unconfirmed": claudeCodeTupleHeaders(measured2_1_322UA, measured2_1_322Package, measured2_1_322Runtime),
	} {
		t.Run(name, func(t *testing.T) {
			got := legacyUpstreamHeaders(t, incoming, false)
			assertTuple(t, got, defaultClaudeFingerprintUserAgent, defaultClaudeFingerprintPackageVersion, defaultClaudeFingerprintRuntimeVersion)
			if got.Get("X-Stainless-Os") != defaultClaudeFingerprintOS || got.Get("X-Stainless-Arch") != defaultClaudeFingerprintArch {
				t.Fatalf("platform = %q/%q, want the baseline platform", got.Get("X-Stainless-Os"), got.Get("X-Stainless-Arch"))
			}
		})
	}
}

// The stabilized (7-day) profile upgrades when a newer genuine client appears,
// refreshes its TTL, and is not downgraded by an older one.
func TestClaudeDeviceFloor_CachedProfileUpgradesOnNewerVersion(t *testing.T) {
	ResetClaudeDeviceProfileCache()
	auth := &cliproxyauth.Auth{ID: "auth-floor-upgrade"}
	first := claudeCodeTupleHeaders("claude-cli/2.1.300 (external, cli)", "0.120.0", "v26.10.0")
	if got := resolveClaudeDeviceProfileLocal(auth, "", first, nil); got.UserAgent != "claude-cli/2.1.300 (external, cli)" {
		t.Fatalf("first profile = %q, want 2.1.300 stored", got.UserAgent)
	}

	newer := claudeCodeTupleHeaders(measured2_1_322UA, measured2_1_322Package, measured2_1_322Runtime)
	got := resolveClaudeDeviceProfileLocal(auth, "", newer, nil)
	if got.UserAgent != measured2_1_322UA || got.PackageVersion != measured2_1_322Package || got.RuntimeVersion != measured2_1_322Runtime {
		t.Fatalf("upgraded profile = %#v, want the 2.1.322 tuple", got)
	}

	older := claudeCodeTupleHeaders("claude-cli/2.1.300 (external, cli)", "0.120.0", "v26.10.0")
	if got := resolveClaudeDeviceProfileLocal(auth, "", older, nil); got.UserAgent != measured2_1_322UA {
		t.Fatalf("profile after older client = %q, want stabilized 2.1.322 kept", got.UserAgent)
	}

	// A request without a usable client tuple still gets the stored profile.
	if got := resolveClaudeDeviceProfileLocal(auth, "", http.Header{}, nil); got.UserAgent != measured2_1_322UA {
		t.Fatalf("profile without client headers = %q, want stabilized 2.1.322", got.UserAgent)
	}

	key := claudeDeviceProfileCacheKey(auth, "", ClaudeDeviceProfile{UserAgent: measured2_1_322UA})
	claudeDeviceProfileCacheMu.RLock()
	entry, ok := claudeDeviceProfileCache[key]
	claudeDeviceProfileCacheMu.RUnlock()
	if !ok || entry.profile.UserAgent != measured2_1_322UA {
		t.Fatalf("cache entry = %#v (found %v), want the 2.1.322 profile", entry, ok)
	}
	if remaining := time.Until(entry.expire); remaining < claudeDeviceProfileTTL-time.Minute {
		t.Fatalf("cache TTL remaining = %v, want refreshed to ~%v", remaining, claudeDeviceProfileTTL)
	}
}
