package scan

import "github.com/smuggled/smuggled/internal/config"

// dbg calls cfg.DebugLog if debug mode is active. All scan modules use this
// helper for consistent debug output without nil-checking DebugLog everywhere.
func dbg(cfg config.Config, format string, args ...any) {
	if cfg.DebugLog != nil {
		cfg.DebugLog(format, args...)
	}
}
