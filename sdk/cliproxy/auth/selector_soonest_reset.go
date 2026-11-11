package auth

import (
	"cmp"
	"context"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SoonestResetSelector sends Claude subscription traffic to the credential whose weekly (7d)
// unified rate-limit window resets soonest, so quota that would otherwise expire unused is spent
// first. It reads the Anthropic-Ratelimit-Unified-* headers last observed on Auth.Quota.Signals;
// exhausted credentials are left to the manager's cooldown handling, which removes them before Pick.
//
// Candidates are ordered as follows, and the first is picked:
//  1. Credentials without a usable 7d reset (never observed, unparseable, or already past because the
//     window rolled over), rotated round-robin so each one is probed and reports fresh signals.
//  2. Credentials by soonest 7d reset.
//  3. Credentials whose last response reported an exhausted 5h or 7d window (status rejected, or
//     utilization at or above claudeNearLimitUtilization) that has not reset yet, by when the
//     window lifts. A nearly spent window must not win just because its reset is soonest.
//
// Ties go to the lower 5h utilization, then the lower auth ID. A pool that is not entirely Claude
// rotates round-robin.
type SoonestResetSelector struct {
	rotation RoundRobinSelector
}

const (
	claudeUnified5hResetSignal       = "Anthropic-Ratelimit-Unified-5h-Reset"
	claudeUnified5hStatusSignal      = "Anthropic-Ratelimit-Unified-5h-Status"
	claudeUnified5hUtilizationSignal = "Anthropic-Ratelimit-Unified-5h-Utilization"
	claudeUnified7dResetSignal       = "Anthropic-Ratelimit-Unified-7d-Reset"
	claudeUnified7dStatusSignal      = "Anthropic-Ratelimit-Unified-7d-Status"
	claudeUnified7dUtilizationSignal = "Anthropic-Ratelimit-Unified-7d-Utilization"

	// claudeNearLimitUtilization is the utilization from which soonest-reset treats a window as spent:
	// the next few requests would exhaust it, so it ranks with rejected credentials.
	claudeNearLimitUtilization = 0.98
	// claudeExhaustedUtilization is the utilization at which a window is fully used.
	claudeExhaustedUtilization = 1.0
)

type soonestResetTier int

const (
	soonestResetUnknown soonestResetTier = iota
	soonestResetKnown
	soonestResetRejected
)

type soonestResetRank struct {
	auth   *Auth
	tier   soonestResetTier
	at     time.Time
	util5h float64
}

// Pick selects the available credential whose weekly window resets soonest.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	key := provider + ":" + canonicalModelKey(model)
	if !slices.ContainsFunc(available, func(auth *Auth) bool { return !isClaudeAuth(auth) }) {
		ranks := make([]soonestResetRank, 0, len(available))
		var unknown []*Auth
		for _, auth := range available {
			rank := rankBySoonestReset(auth, now)
			if rank.tier == soonestResetUnknown {
				unknown = append(unknown, auth)
				continue
			}
			ranks = append(ranks, rank)
		}
		if len(unknown) == 0 {
			return slices.MinFunc(ranks, compareSoonestResetRank).auth, nil
		}
		available = unknown
	}
	return s.rotation.next(key, available), nil
}

func isClaudeAuth(auth *Auth) bool {
	return auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "claude")
}

func rankBySoonestReset(auth *Auth, now time.Time) soonestResetRank {
	signals := auth.Quota.Signals
	rank := soonestResetRank{auth: auth, util5h: math.Inf(1)}
	if util, errParse := strconv.ParseFloat(strings.TrimSpace(signals[claudeUnified5hUtilizationSignal]), 64); errParse == nil && !math.IsNaN(util) {
		rank.util5h = util
	}
	if until, ok := claudeExhaustedUntil(signals, now, claudeNearLimitUtilization); ok {
		rank.tier = soonestResetRejected
		rank.at = until
		return rank
	}
	if reset, ok := parseQuotaSignalTime(signals[claudeUnified7dResetSignal]); ok && reset.After(now) {
		rank.tier = soonestResetKnown
		rank.at = reset
	}
	return rank
}

// claudeExhaustedUntil returns the latest future reset among the shared 5h and 7d windows that
// are exhausted: status rejected, or utilization at or above minUtilization. A window whose reset
// is missing or already past is ignored, because its last reading no longer applies.
func claudeExhaustedUntil(signals map[string]string, now time.Time, minUtilization float64) (time.Time, bool) {
	var until time.Time
	for _, window := range [][3]string{
		{claudeUnified5hStatusSignal, claudeUnified5hUtilizationSignal, claudeUnified5hResetSignal},
		{claudeUnified7dStatusSignal, claudeUnified7dUtilizationSignal, claudeUnified7dResetSignal},
	} {
		exhausted := strings.EqualFold(strings.TrimSpace(signals[window[0]]), "rejected")
		if !exhausted {
			util, errParse := strconv.ParseFloat(strings.TrimSpace(signals[window[1]]), 64)
			exhausted = errParse == nil && !math.IsNaN(util) && util >= minUtilization
		}
		if !exhausted {
			continue
		}
		if reset, ok := parseQuotaSignalTime(signals[window[2]]); ok && reset.After(now) && reset.After(until) {
			until = reset
		}
	}
	return until, !until.IsZero()
}

func compareSoonestResetRank(a, b soonestResetRank) int {
	return cmp.Or(
		cmp.Compare(a.tier, b.tier),
		a.at.Compare(b.at),
		cmp.Compare(a.util5h, b.util5h),
		strings.Compare(a.auth.ID, b.auth.ID),
	)
}

// parseQuotaSignalTime mirrors parseUnixOrTimestamp in internal/runtime/executor/helps, which
// imports this package and so cannot be imported here: Unix seconds (fractional allowed),
// RFC 3339, or an HTTP date.
func parseQuotaSignalTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if sec, err := strconv.ParseFloat(raw, 64); err == nil && sec > 0 {
		secInt := int64(sec)
		nsec := int64((sec - float64(secInt)) * 1e9)
		return time.Unix(secInt, nsec), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	if t, err := http.ParseTime(raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}
