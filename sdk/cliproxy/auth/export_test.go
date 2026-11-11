package auth

import "context"

// CooldownReprobeTickForTest runs one re-probe sweep without staggering, for
// integration tests in package auth_test that drive real provider executors.
func (m *Manager) CooldownReprobeTickForTest(ctx context.Context) int {
	return m.cooldownReprobeTick(ctx, noReprobeWait)
}
