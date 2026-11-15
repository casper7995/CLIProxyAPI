package config

import "testing"

func TestSoonestResetRoutingStrategyParses(t *testing.T) {
	raw := []byte("routing: {strategy: soonest-reset, session-affinity: true}\n")
	if err := ValidateV8Config(raw); err != nil {
		t.Fatalf("ValidateV8Config() error = %v", err)
	}
	cfg, err := ParseConfigBytes(raw)
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if cfg.Routing.Strategy != "soonest-reset" || !cfg.Routing.SessionAffinity {
		t.Fatalf("routing = %+v, want strategy soonest-reset with session affinity", cfg.Routing)
	}
}
