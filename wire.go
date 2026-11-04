package protocol

import (
	"strconv"
	"strings"
)

// RevisionNewer reports whether cand is strictly newer than cur.
// Revisions are decimal strings (controller-assigned unix nanos); an
// empty cur accepts anything non-empty, an empty cand is never newer.
func RevisionNewer(cand, cur string) bool {
	cand = strings.TrimSpace(cand)
	if cand == "" {
		return false
	}
	cur = strings.TrimSpace(cur)
	if cur == "" {
		return true
	}
	c, err1 := strconv.ParseUint(cand, 10, 64)
	u, err2 := strconv.ParseUint(cur, 10, 64)
	if err1 != nil || err2 != nil {
		// Unparseable — fall back to inequality so a corrupted stored
		// revision can never wedge the agent into rejecting updates.
		return cand != cur
	}
	return c > u
}
