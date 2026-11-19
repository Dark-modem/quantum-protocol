package protocol

// artifact_test.go — pins PickArtifactVersion to the semantics BOTH
// original implementations shipped (agent engineResolveArtifact walk,
// panel latestArtifactVersionIn walk) before they started delegating
// here. The lexicographic quirk ("1.9" > "1.10") is the SHIPPED behavior
// on both sides — pinning it here so a future "fix" shows up as a
// deliberate cross-repo decision, never silently.

import "testing"

func row(engine, goarch, version string) ArtifactVersionRow {
	return ArtifactVersionRow{Engine: engine, Goarch: goarch, Version: version}
}

func TestPickArtifactVersionBasics(t *testing.T) {
	// empty rows → ""
	if got := PickArtifactVersion(nil, "frp", "amd64"); got != "" {
		t.Fatalf("nil rows: got %q", got)
	}
	// no row matches the engine+arch → ""
	arts := []ArtifactVersionRow{
		row("frp", "amd64", "0.61.2"),
		row("frp", "arm64", "0.61.3"),
		row("backhaul", "amd64", "1.0.0"),
	}
	if got := PickArtifactVersion(arts, "backhaul", "arm64"); got != "" {
		t.Fatalf("no-match arch: got %q", got)
	}
	if got := PickArtifactVersion(arts, "nosuch", "amd64"); got != "" {
		t.Fatalf("no-match engine: got %q", got)
	}
	// arch filtering: the amd64 pool must not see the arm64 winner
	if got := PickArtifactVersion(arts, "frp", "amd64"); got != "0.61.2" {
		t.Fatalf("amd64 pick: got %q", got)
	}
	if got := PickArtifactVersion(arts, "frp", "arm64"); got != "0.61.3" {
		t.Fatalf("arm64 pick: got %q", got)
	}
	// empty Version never wins, even when it is the only row
	if got := PickArtifactVersion([]ArtifactVersionRow{row("frp", "amd64", "")}, "frp", "amd64"); got != "" {
		t.Fatalf("empty-version row must be skipped: got %q", got)
	}
}

func TestPickArtifactVersionHighestWins(t *testing.T) {
	arts := []ArtifactVersionRow{
		row("frp", "amd64", "0.60.0"),
		row("frp", "amd64", "0.61.2"),
		row("frp", "amd64", "0.61.1"),
	}
	if got := PickArtifactVersion(arts, "frp", "amd64"); got != "0.61.2" {
		t.Fatalf("highest wins: got %q", got)
	}
}

// TestPickArtifactVersionLexicographic pins the shipped comparison: plain
// string `>`, NOT semver. Both original walks used exactly this rule, so
// the agent's manifest pick and the panel's stamp agree on it today.
func TestPickArtifactVersionLexicographic(t *testing.T) {
	arts := []ArtifactVersionRow{
		row("frp", "amd64", "1.10"),
		row("frp", "amd64", "1.9"),
	}
	if got := PickArtifactVersion(arts, "frp", "amd64"); got != "1.9" {
		t.Fatalf("lexicographic quirk changed: got %q (want 1.9 — plain string compare is the shipped rule)", got)
	}
}

// TestPickArtifactVersionTieFirst pins tie resolution: equal versions
// return that version; the wrappers' documented contract is that the
// FIRST row in order owns the tie (panel: uploaded_at DESC = newest
// upload; agent: first qualifying manifest entry).
func TestPickArtifactVersionTieFirst(t *testing.T) {
	arts := []ArtifactVersionRow{
		row("frp", "amd64", "0.61.2"),
		row("frp", "amd64", "0.61.2"),
	}
	if got := PickArtifactVersion(arts, "frp", "amd64"); got != "0.61.2" {
		t.Fatalf("tie: got %q", got)
	}
	// order must not change the returned VALUE for ties
	reversed := []ArtifactVersionRow{arts[1], arts[0]}
	if got := PickArtifactVersion(reversed, "frp", "amd64"); got != "0.61.2" {
		t.Fatalf("tie reversed: got %q", got)
	}
}

// TestPickArtifactVersionManifestOrder is the agent-side shape: the
// manifest serves entries newest-upload-first and the original walk kept
// the first qualifying entry with the highest version.
func TestPickArtifactVersionManifestOrder(t *testing.T) {
	arts := []ArtifactVersionRow{
		row("frp", "amd64", "0.61.2"),
		row("frp", "amd64", "0.60.0"),
		row("frp", "amd64", "0.61.2"),
		row("frp", "arm64", "0.99.0"),
	}
	if got := PickArtifactVersion(arts, "frp", "amd64"); got != "0.61.2" {
		t.Fatalf("manifest order: got %q", got)
	}
}
