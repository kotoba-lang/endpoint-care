//go:build darwin

package clean

import "path/filepath"

// osWhitelist is the verified macOS cache layout: regenerable per-user caches
// under ~/Library only.
func osWhitelist() []string {
	h := home()
	if h == "" {
		return nil
	}
	caches := filepath.Join(h, "Library", "Caches")
	return keepUnderHome([]string{
		filepath.Join(caches, "go-build"),
		filepath.Join(caches, "node-gyp"),
		filepath.Join(caches, "pnpm"),
		filepath.Join(caches, "electron"),
		filepath.Join(caches, "pip"),
		filepath.Join(caches, "deno"),
		filepath.Join(caches, "org.swift.swiftpm"),
		filepath.Join(h, "Library", "Logs"),
	})
}

// osProtected adds macOS per-app state that is never a cleanup target.
func osProtected() []string {
	h := home()
	if h == "" {
		return nil
	}
	return []string{
		filepath.Join(h, "Library", "Application Support"),
	}
}
