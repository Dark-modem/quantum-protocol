package protocol

// artifact.go — the SHARED artifact-version pick (REFACTOR-PLAN-AGENT D5,
// the protocol-last item of both refactor plans): the agent's manifest
// walk (internal/agent engineResolveArtifact) and the panel's
// desired-state stamp (internal/panel latestArtifactVersionIn) coded the
// same "highest version wins" rule twice in two repos. This file is the
// one canonical implementation; each side keeps a thin wrapper that does
// its own input validation (the agent: manifest-entry completeness +
// artifact-name charset; the panel: store rows) and delegates here.
//
// NOT a wire type: ArtifactVersionRow is an in-memory view of whatever
// artifact records each side holds, and PickArtifactVersion is pure —
// no I/O, no clock, no globals, no JSON.

// ArtifactVersionRow is the minimal view of one artifact record the
// version pick needs. Row ORDER carries meaning: PickArtifactVersion
// resolves version ties to the FIRST row in order — the same
// first-found behavior both sides shipped (the panel's
// ListEngineArtifacts is uploaded_at DESC, so the newest upload wins a
// tie; the agent's original strict-`>` walk kept the first entry in
// manifest order).
type ArtifactVersionRow struct {
	Engine  string
	Goarch  string
	Version string
}

// PickArtifactVersion returns the highest Version among rows matching
// engine+arch. Version comparison is the PLAIN STRING comparison both
// sides shipped (NOT semver — "1.9" > "1.10" lexicographically; that
// quirk is pinned in artifact_test.go and must not be "fixed" here
// without a cross-repo change). Rows with an empty Version never win.
// Returns "" when nothing matches.
func PickArtifactVersion(rows []ArtifactVersionRow, engine, arch string) string {
	best := ""
	for _, r := range rows {
		if r.Engine != engine || r.Goarch != arch || r.Version == "" {
			continue
		}
		if best == "" || r.Version > best {
			best = r.Version
		}
	}
	return best
}
