package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Quota signal persistence.
//
// Passive quota observations (the Anthropic-Ratelimit-Unified-* watermarks on
// Auth.Quota.Signals) otherwise live only in memory. After a restart every
// Claude credential looked unobserved: soonest-reset could not rank them, and a
// credential whose weekly window was exhausted was selected again and had to
// fail once before it was benched. The snapshot keeps the last observation per
// credential across restarts. Restoring it, before the server takes traffic,
// warms the selector and re-derives quota cooldowns from exhausted windows.

// QuotaSignalFileName is the snapshot file kept in the auth directory. It does
// not end in .json, so the auth loader and watcher ignore it.
const QuotaSignalFileName = "quota-signals.snapshot"

// maxDerivedQuotaCooldown bounds a cooldown derived from a persisted reset; a
// later timestamp is not a rate-limit window (the 7d window plus clock skew).
const maxDerivedQuotaCooldown = 7*24*time.Hour + time.Hour

// QuotaSignalSnapshot is the persisted passive quota observation of one credential.
type QuotaSignalSnapshot struct {
	Provider   string            `json:"provider"`
	ObservedAt time.Time         `json:"observed_at"`
	Signals    map[string]string `json:"signals"`
}

// QuotaSignalStore persists quota observations keyed by auth ID.
type QuotaSignalStore interface {
	Load(context.Context) (map[string]QuotaSignalSnapshot, error)
	Save(context.Context, map[string]QuotaSignalSnapshot) error
}

type quotaSignalFile struct {
	Version   int                            `json:"version"`
	UpdatedAt time.Time                      `json:"updated_at"`
	Auths     map[string]QuotaSignalSnapshot `json:"auths"`
}

// FileQuotaSignalStore keeps all snapshots in one JSON file, replaced atomically.
type FileQuotaSignalStore struct {
	mu   sync.Mutex
	path string
}

// NewFileQuotaSignalStore creates a store backed by path.
func NewFileQuotaSignalStore(path string) *FileQuotaSignalStore {
	return &FileQuotaSignalStore{path: strings.TrimSpace(path)}
}

// Load reads the snapshot. A missing file is empty state.
func (s *FileQuotaSignalStore) Load(_ context.Context) (map[string]QuotaSignalSnapshot, error) {
	if s == nil || s.path == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, errRead := os.ReadFile(s.path)
	if errRead != nil {
		if errors.Is(errRead, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read quota signal snapshot: %w", errRead)
	}
	var file quotaSignalFile
	if errUnmarshal := json.Unmarshal(raw, &file); errUnmarshal != nil {
		return nil, fmt.Errorf("parse quota signal snapshot: %w", errUnmarshal)
	}
	return file.Auths, nil
}

// Save replaces the snapshot through a temporary file and rename.
func (s *FileQuotaSignalStore) Save(_ context.Context, snapshots map[string]QuotaSignalSnapshot) error {
	if s == nil || s.path == "" {
		return nil
	}
	raw, errMarshal := json.Marshal(quotaSignalFile{Version: 1, UpdatedAt: time.Now().UTC(), Auths: snapshots})
	if errMarshal != nil {
		return fmt.Errorf("marshal quota signal snapshot: %w", errMarshal)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if errMkdir := os.MkdirAll(filepath.Dir(s.path), 0o700); errMkdir != nil {
		return fmt.Errorf("create quota signal directory: %w", errMkdir)
	}
	tmp, errCreate := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".tmp-*")
	if errCreate != nil {
		return fmt.Errorf("create quota signal temp file: %w", errCreate)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, errWrite := tmp.Write(raw); errWrite != nil {
		_ = tmp.Close()
		return fmt.Errorf("write quota signal snapshot: %w", errWrite)
	}
	if errClose := tmp.Close(); errClose != nil {
		return fmt.Errorf("close quota signal snapshot: %w", errClose)
	}
	if errChmod := os.Chmod(tmpName, 0o600); errChmod != nil {
		return fmt.Errorf("chmod quota signal snapshot: %w", errChmod)
	}
	if errRename := os.Rename(tmpName, s.path); errRename != nil {
		return fmt.Errorf("replace quota signal snapshot: %w", errRename)
	}
	return nil
}

// SetQuotaSignalStore sets the store used to persist and restore quota observations.
func (m *Manager) SetQuotaSignalStore(store QuotaSignalStore) {
	if m == nil {
		return
	}
	m.quotaSignalMu.Lock()
	m.quotaSignalStore = store
	m.quotaSignalSaved = nil
	m.quotaSignalMu.Unlock()
}

// RestoreQuotaSignals loads persisted quota observations into registered auths.
// A newer live observation is kept. For Claude credentials whose restored
// snapshot shows an exhausted 5h or 7d window (status rejected or utilization
// at 1.0) with a reset still ahead, a credential quota cooldown is re-created
// until that reset, unless a longer one is already in place. Call it after
// auths are loaded and before the server takes traffic.
func (m *Manager) RestoreQuotaSignals(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.quotaSignalMu.Lock()
	store := m.quotaSignalStore
	m.quotaSignalMu.Unlock()
	if store == nil {
		return nil
	}
	snapshots, errLoad := store.Load(ctx)
	if errLoad != nil {
		return errLoad
	}
	if len(snapshots) == 0 {
		return nil
	}

	now := time.Now()
	restored, cooled := 0, 0
	updated := make([]*Auth, 0)
	m.mu.Lock()
	for authID, snapshot := range snapshots {
		auth := m.auths[strings.TrimSpace(authID)]
		if auth == nil || len(snapshot.Signals) == 0 || snapshot.ObservedAt.IsZero() ||
			!strings.EqualFold(strings.TrimSpace(auth.Provider), strings.TrimSpace(snapshot.Provider)) ||
			!ProviderSupportsQuotaObservation(auth.Provider) {
			continue
		}
		changed := false
		if auth.Quota.ObservedAt.Before(snapshot.ObservedAt) {
			auth.Quota.ObservedAt = snapshot.ObservedAt
			auth.Quota.Signals = maps.Clone(snapshot.Signals)
			restored++
			changed = true
		}
		if m.deriveQuotaCooldownLocked(auth, now) {
			cooled++
			changed = true
			log.Infof("quota signals: %s restored as cooling until %s (persisted window exhausted)",
				authLogName(auth), auth.Quota.NextRecoverAt.Format(time.RFC3339))
		}
		if changed {
			auth.Generation++
			updated = append(updated, auth.Clone())
		}
	}
	m.mu.Unlock()

	if m.scheduler != nil {
		for _, snapshot := range updated {
			m.scheduler.upsertAuth(snapshot)
		}
	}
	if cooled > 0 {
		m.persistCooldownStates(context.Background())
	}
	m.quotaSignalMu.Lock()
	m.quotaSignalSaved = snapshots
	m.quotaSignalMu.Unlock()
	log.Infof("quota signals restored for %d credential(s), %d re-benched for exhausted windows", restored, cooled)
	return nil
}

// deriveQuotaCooldownLocked re-creates a credential quota cooldown from the
// auth's quota signals. It reports whether the auth changed. m.mu must be held.
func (m *Manager) deriveQuotaCooldownLocked(auth *Auth, now time.Time) bool {
	if !isClaudeAuth(auth) || auth.Disabled || auth.Status == StatusDisabled ||
		hasUnauthorizedAuthFailure(auth) || m.cooldownDisabledForAuth(auth) {
		return false
	}
	until, ok := claudeExhaustedUntil(auth.Quota.Signals, now, claudeExhaustedUtilization)
	if !ok || until.Sub(now) > maxDerivedQuotaCooldown {
		return false
	}
	if auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota" && !auth.Quota.NextRecoverAt.Before(until) {
		return false
	}
	return m.restoreCooldownRecordLocked(CooldownStateRecord{
		Provider:       auth.Provider,
		AuthID:         auth.ID,
		NextRetryAfter: until,
		Reason:         "quota",
		Quota:          QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: until},
		UpdatedAt:      auth.Quota.ObservedAt,
	}, now)
}

// quotaSignalSnapshots captures the current observation of every credential
// whose provider supports quota observation.
func (m *Manager) quotaSignalSnapshots() map[string]QuotaSignalSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]QuotaSignalSnapshot)
	for id, auth := range m.auths {
		if auth == nil || len(auth.Quota.Signals) == 0 || auth.Quota.ObservedAt.IsZero() ||
			!ProviderSupportsQuotaObservation(auth.Provider) {
			continue
		}
		out[id] = QuotaSignalSnapshot{
			Provider:   strings.ToLower(strings.TrimSpace(auth.Provider)),
			ObservedAt: auth.Quota.ObservedAt.UTC(),
			Signals:    maps.Clone(auth.Quota.Signals),
		}
	}
	return out
}

// PersistQuotaSignals writes the current observations when they changed since
// the last save.
func (m *Manager) PersistQuotaSignals(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	snapshots := m.quotaSignalSnapshots()
	m.quotaSignalMu.Lock()
	defer m.quotaSignalMu.Unlock()
	if m.quotaSignalStore == nil || quotaSignalSnapshotsEqual(m.quotaSignalSaved, snapshots) {
		return nil
	}
	if errSave := m.quotaSignalStore.Save(ctx, snapshots); errSave != nil {
		return errSave
	}
	m.quotaSignalSaved = snapshots
	return nil
}

func quotaSignalSnapshotsEqual(a, b map[string]QuotaSignalSnapshot) bool {
	return maps.EqualFunc(a, b, func(x, y QuotaSignalSnapshot) bool {
		return x.Provider == y.Provider && x.ObservedAt.Equal(y.ObservedAt) && maps.Equal(x.Signals, y.Signals)
	})
}

// StartQuotaSignalPersistence saves changed observations every interval until
// StopQuotaSignalPersistence, which also performs a final save.
func (m *Manager) StartQuotaSignalPersistence(parent context.Context, interval time.Duration) {
	if m == nil || interval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	m.quotaSignalMu.Lock()
	prevCancel, prevDone := m.quotaSignalCancel, m.quotaSignalDone
	m.quotaSignalCancel, m.quotaSignalDone = cancel, done
	m.quotaSignalMu.Unlock()
	if prevCancel != nil {
		prevCancel()
		<-prevDone
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if errPersist := m.PersistQuotaSignals(ctx); errPersist != nil {
					log.Warnf("failed to persist quota signals: %v", errPersist)
				}
			}
		}
	}()
}

// StopQuotaSignalPersistence stops the save loop and writes a final snapshot.
func (m *Manager) StopQuotaSignalPersistence() {
	if m == nil {
		return
	}
	m.quotaSignalMu.Lock()
	cancel, done := m.quotaSignalCancel, m.quotaSignalDone
	m.quotaSignalCancel, m.quotaSignalDone = nil, nil
	m.quotaSignalMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
	if errPersist := m.PersistQuotaSignals(context.Background()); errPersist != nil {
		log.Warnf("failed to persist quota signals on shutdown: %v", errPersist)
	}
}
