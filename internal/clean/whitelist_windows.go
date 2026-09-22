//go:build windows

package clean

import (
	"os"
	"path/filepath"
)

// localAppData resolves %LOCALAPPDATA% with the documented fallback under
// the user profile, so a missing env var never yields a bare-name root.
func localAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	if h := home(); h != "" {
		return filepath.Join(h, "AppData", "Local")
	}
	return ""
}

// osWhitelist is the verified Windows per-user cache layout under
// %LOCALAPPDATA%. User TEMP is deliberately NOT a root: running processes
// keep open files there and one explicit path per operation cannot arbitrate.
func osWhitelist() []string {
	d := localAppData()
	if d == "" {
		return nil
	}
	return keepUnderHome([]string{
		filepath.Join(d, "go-build"),          // default GOCACHE on Windows
		filepath.Join(d, "pip", "Cache"),      // pip cache dir
		filepath.Join(d, "npm-cache"),         // npm cache default
		filepath.Join(d, "pnpm"),              // pnpm store
		filepath.Join(d, "electron", "Cache"), // electron download cache
		filepath.Join(d, "deno"),              // deno cache
		filepath.Join(d, "node-gyp", "Cache"), // node-gyp headers
	})
}

// osProtected keeps Roaming profile state and the Windows app profile out of
// reach even if a future whitelist entry overlaps them.
func osProtected() []string {
	h := home()
	if h == "" {
		return nil
	}
	out := []string{filepath.Join(h, "AppData", "Roaming")}
	if d := localAppData(); d != "" {
		out = append(out, filepath.Join(d, "Microsoft"))
	}
	return out
}
