package scan

import "github.com/smuggled/smuggled/internal/config"

// dbg calls cfg.DebugLog if debug mode is active. All scan modules use this
// helper for consistent debug output without nil-checking DebugLog everywhere.
func dbg(cfg config.Config, format string, args ...any) {
	if cfg.DebugLog != nil {
		cfg.DebugLog(format, args...)
	}
}

// isRateLimited returns true for status codes that indicate the server is
// rate-limiting or temporarily overloaded rather than responding to the
// request content. These must never be treated as a smuggling signal.
func isRateLimited(status int) bool {
	return status == 429 || status == 503
}
