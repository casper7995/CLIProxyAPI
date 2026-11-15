package cliproxy

import (
	"path/filepath"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestResolveQuotaSignalStore(t *testing.T) {
	dir := t.TempDir()
	s := &Service{}
	store, ok := s.resolveQuotaSignalStore(&config.Config{AuthDir: dir}).(*coreauth.FileQuotaSignalStore)
	if !ok || store == nil {
		t.Fatal("expected a file quota signal store for a local auth dir")
	}
	if filepath.Ext(coreauth.QuotaSignalFileName) == ".json" {
		t.Fatal("snapshot must not use .json, which the auth loader and watcher treat as credentials")
	}

	home := &config.Config{AuthDir: dir}
	home.Home.Enabled = true
	if store := s.resolveQuotaSignalStore(home); store != nil {
		t.Fatal("home mode must not persist quota signals locally")
	}
	if store := s.resolveQuotaSignalStore(nil); store != nil {
		t.Fatal("nil config must not create a store")
	}
}
