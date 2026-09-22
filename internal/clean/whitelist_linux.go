//go:build linux

package clean

import (
	"os"
	"path/filepath"
)

// osWhitelist is the verified Linux cache layout: per-user regenerable tool
// caches under $XDG_CACHE_HOME / $HOME only. System paths (/var/tmp, /var/cache)
// are never candidates — headless servers get the same user-scoped guard.
func osWhitelist() []string {
	h := home()
	if h == "" {
		return nil
	}
	cache := os.Getenv("XDG_CACHE_HOME")
	if cache == "" {
		cache = filepath.Join(h, ".cache")
	}
	return keepUnderHome([]string{
		filepath.Join(cache, "go-build"),
		filepath.Join(cache, "pip"),
		filepath.Join(cache, "pnpm"),
		filepath.Join(cache, "electron"),
		filepath.Join(cache, "deno"),
		filepath.Join(cache, "node-gyp"),
		filepath.Join(h, ".npm", "_cacache"),
		filepath.Join(h, ".cargo", "registry", "cache"),
		filepath.Join(h, ".gradle", "caches"),
	})
}

// osProtected adds Linux user-config and app-data dirs that are never targets.
func osProtected() []string {
	h := home()
	if h == "" {
		return nil
	}
	return []string{
		filepath.Join(h, ".config"),
		filepath.Join(h, ".local", "share"),
	}
}
