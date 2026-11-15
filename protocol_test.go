package protocol

// Compatibility suite: these tests are the shared contract between the
// panel and the agent. The golden fixtures in fixtures/ pin the exact
// wire bytes both sides must keep speaking; a change that breaks any
// test here is a protocol change and must bump ProtoVersion.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// fixtureCase maps one golden fixture file to the envelope type and the
// typed struct its data must decode into.
type fixtureCase struct {
	file    string
	typ     string
	version int
	new     func() any
}

var fixtureCases = []fixtureCase{
	{"hello.json", MsgHello, ProtoVersionV1, func() any { return &Hello{} }},
	{"welcome.json", MsgWelcome, ProtoVersionV1, func() any { return &Welcome{} }},
	{"heartbeat.json", MsgHeartbeat, ProtoVersionV1, func() any { return &Heartbeat{} }},
	{"desired.json", MsgDesired, ProtoVersionV1, func() any { return &Desired{} }},
	{"ack.json", MsgAck, ProtoVersionV1, func() any { return &Ack{} }},
	{"command.json", MsgCommand, ProtoVersionV1, func() any { return &Command{} }},
	{"result.json", MsgResult, ProtoVersionV1, func() any { return &CommandResult{} }},
	{"register.json", MsgRegister, ProtoVersionV1, func() any { return &RegisterMsg{} }},
	{"register_result.json", MsgRegisterResult, ProtoVersionV1, func() any { return &RegisterResult{} }},
	{"error.json", MsgError, ProtoVersionV1, func() any { return &ErrorMsg{} }},
	// v2 (Phase 1A)
	{"desired-v2.json", MsgDesired, ProtoVersionV2, func() any { return &DesiredV2{} }},
	{"heartbeat-v2.json", MsgHeartbeat, ProtoVersionV2, func() any { return &HeartbeatV2{} }},
	{"command-hardening-apply.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"command-hardening-rollback.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"command-netopt-profile-apply.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"command-netopt-profile-rollback.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	// v2 (Phase 2A): hardening per HARDENING.md §5 + service forwards
	{"command-hardening-detect.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"command-hardening-plan.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"command-hardening-confirm.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"command-hardening-status.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"desired-v2-hardening.json", MsgDesired, ProtoVersionV2, func() any { return &DesiredV2{} }},
	{"desired-v2-forwards.json", MsgDesired, ProtoVersionV2, func() any { return &DesiredV2{} }},
	{"ack-hardening.json", MsgAck, ProtoVersionV2, func() any { return &Ack{} }},
	// v2 (Phase 2A R1-R3, panel requests)
	{"desired-v2-forwards-spec.json", MsgDesired, ProtoVersionV2, func() any { return &DesiredV2{} }},
	{"command-netopt-profile-confirm.json", MsgCommand, ProtoVersionV2, func() any { return &Command{} }},
	{"hello-v2.json", MsgHello, ProtoVersionV2, func() any { return &Hello{} }},
	// v2 (Phase 11): per-tunnel process metrics + engine installation status
	{"heartbeat-v2-proc.json", MsgHeartbeat, ProtoVersionV2, func() any { return &HeartbeatV2{} }},
	// v2 (Phase 17 R6): per-agent self identifier stamped by the panel
	{"desired-v2-self.json", MsgDesired, ProtoVersionV2, func() any { return &DesiredV2{} }},
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func TestGoldenFixturesDecode(t *testing.T) {
	for _, fc := range fixtureCases {
		t.Run(fc.file, func(t *testing.T) {
			version, typ, data, err := DecodeAny(readFixture(t, fc.file))
			if err != nil {
				t.Fatalf("DecodeAny(%s): %v", fc.file, err)
			}
			if version != fc.version {
				t.Fatalf("envelope version = %d, want %d", version, fc.version)
			}
			if typ != fc.typ {
				t.Fatalf("envelope type = %q, want %q", typ, fc.typ)
			}
			msg := fc.new()
			if err := json.Unmarshal(data, msg); err != nil {
				t.Fatalf("unmarshal %s data into %T: %v", fc.file, msg, err)
			}
		})
	}
}

// TestGoldenFixturesDecodeV1Strict pins that every v1 fixture still
// decodes through the v1-only Decode (the API v1 call sites use).
func TestGoldenFixturesDecodeV1Strict(t *testing.T) {
	for _, fc := range fixtureCases {
		if fc.version != ProtoVersionV1 {
			continue
		}
		t.Run(fc.file, func(t *testing.T) {
			typ, data, err := Decode(readFixture(t, fc.file))
			if err != nil {
				t.Fatalf("Decode(%s): %v", fc.file, err)
			}
			if typ != fc.typ {
				t.Fatalf("type = %q, want %q", typ, fc.typ)
			}
			_ = data
		})
	}
}

// TestFixtureRoundTrip re-encodes the decoded fixture and requires the
// result to be semantically identical (same JSON document; key order is
// not part of the contract).
func TestFixtureRoundTrip(t *testing.T) {
	for _, fc := range fixtureCases {
		t.Run(fc.file, func(t *testing.T) {
			raw := readFixture(t, fc.file)
			version, data, err := decodeForVersion(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			msg := fc.new()
			if err := json.Unmarshal(data, msg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			re, err := EncodeVersioned(version, fc.typ, msg)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			var want, got any
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(re, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				wj, _ := json.Marshal(want)
				gj, _ := json.Marshal(got)
				t.Fatalf("round-trip changed the document:\n want: %s\n  got: %s", wj, gj)
			}
		})
	}
}

// decodeForVersion decodes a fixture with the version-appropriate API:
// v1 fixtures go through the v1-only Decode, v2 fixtures through
// DecodeAny — mirroring how deployed call sites consume them.
func decodeForVersion(raw []byte) (version int, data json.RawMessage, err error) {
	if v, _, d, e := DecodeAny(raw); v == ProtoVersionV2 {
		return v, d, e
	}
	_, data, err = Decode(raw)
	return ProtoVersionV1, data, err
}

// TestWireStringsPinned guards the literal wire strings against silent
// renames. These values are shared with deployed agents.
func TestWireStringsPinned(t *testing.T) {
	wire := map[string]string{
		"ProtoVersion":          "1", // compared as int below
		"HeaderAgentID":         HeaderAgentID,
		"HeaderAgentKey":        HeaderAgentKey,
		"HeaderEnrollToken":     HeaderEnrollToken,
		"CapMatrix":             CapMatrix,
		"CapTraffic":            CapTraffic,
		"CapHealth":             CapHealth,
		"CapNodeDetect":         CapNodeDetect,
		"MsgHello":              MsgHello,
		"MsgWelcome":            MsgWelcome,
		"MsgHeartbeat":          MsgHeartbeat,
		"MsgDesired":            MsgDesired,
		"MsgAck":                MsgAck,
		"MsgCommand":            MsgCommand,
		"MsgResult":             MsgResult,
		"MsgRegister":           MsgRegister,
		"MsgRegisterResult":     MsgRegisterResult,
		"MsgError":              MsgError,
		"CmdMatrixRestart":      CmdMatrixRestart,
		"CmdMatrixStart":        CmdMatrixStart,
		"CmdMatrixStop":         CmdMatrixStop,
		"CmdMatrixRegister":     CmdMatrixRegister,
		"CmdDiagPing":           CmdDiagPing,
		"CmdAgentUpdate":        CmdAgentUpdate,
		"CmdFwDetect":           CmdFwDetect,
		"CmdFwSnapshot":         CmdFwSnapshot,
		"CmdFwPlan":             CmdFwPlan,
		"CmdFwApply":            CmdFwApply,
		"CmdFwTeardown":         CmdFwTeardown,
		"CmdPortCheck":          CmdPortCheck,
		"CmdPortList":           CmdPortList,
		"CmdNetDetect":          CmdNetDetect,
		"CmdNetPlan":            CmdNetPlan,
		"CmdNetApply":           CmdNetApply,
		"CmdNetStatus":          CmdNetStatus,
		"CmdNetRB":              CmdNetRB,
		"CmdNetRevert":          CmdNetRevert,
		"CmdHardeningDetect":    CmdHardeningDetect,
		"CmdHardeningPlan":      CmdHardeningPlan,
		"CmdHardeningApply":     CmdHardeningApply,
		"CmdHardeningConfirm":   CmdHardeningConfirm,
		"CmdHardeningRollback":  CmdHardeningRollback,
		"CmdHardeningStatus":    CmdHardeningStatus,
		"CmdNetProfileApply":    CmdNetProfileApply,
		"CmdNetProfileConfirm":  CmdNetProfileConfirm,
		"CmdNetProfileRollback": CmdNetProfileRollback,
		"CapHardening":          CapHardening,
	}
	want := map[string]string{
		"HeaderAgentID":         "X-Agent-Id",
		"HeaderAgentKey":        "X-Agent-Key",
		"HeaderEnrollToken":     "X-Enroll-Token",
		"CapMatrix":             "matrix",
		"CapTraffic":            "traffic",
		"CapHealth":             "health",
		"CapNodeDetect":         "node-detect",
		"MsgHello":              "hello",
		"MsgWelcome":            "welcome",
		"MsgHeartbeat":          "heartbeat",
		"MsgDesired":            "desired",
		"MsgAck":                "ack",
		"MsgCommand":            "command",
		"MsgResult":             "result",
		"MsgRegister":           "register",
		"MsgRegisterResult":     "register_result",
		"MsgError":              "error",
		"CmdMatrixRestart":      "matrix.restart",
		"CmdMatrixStart":        "matrix.start",
		"CmdMatrixStop":         "matrix.stop",
		"CmdMatrixRegister":     "matrix.register",
		"CmdDiagPing":           "diag.ping",
		"CmdAgentUpdate":        "agent.update",
		"CmdFwDetect":           "firewall.detect",
		"CmdFwSnapshot":         "firewall.snapshot",
		"CmdFwPlan":             "firewall.plan",
		"CmdFwApply":            "firewall.apply",
		"CmdFwTeardown":         "firewall.teardown",
		"CmdPortCheck":          "port.check",
		"CmdPortList":           "port.list",
		"CmdNetDetect":          "netopt.detect",
		"CmdNetPlan":            "netopt.plan",
		"CmdNetApply":           "netopt.apply",
		"CmdNetStatus":          "netopt.status",
		"CmdNetRB":              "netopt.rollback",
		"CmdNetRevert":          "netopt.revert",
		"CmdHardeningDetect":    "hardening.detect",
		"CmdHardeningPlan":      "hardening.plan",
		"CmdHardeningApply":     "hardening.apply",
		"CmdHardeningConfirm":   "hardening.confirm",
		"CmdHardeningRollback":  "hardening.rollback",
		"CmdHardeningStatus":    "hardening.status",
		"CmdNetProfileApply":    "netopt.profile.apply",
		"CmdNetProfileConfirm":  "netopt.profile.confirm",
		"CmdNetProfileRollback": "netopt.profile.rollback",
		"CapHardening":          "hardening",
	}
	for name, got := range wire {
		if name == "ProtoVersion" {
			continue
		}
		if want[name] != got {
			t.Errorf("%s = %q, want %q (wire change — bump ProtoVersion)", name, got, want[name])
		}
	}
	if ProtoVersion != 1 {
		t.Errorf("ProtoVersion = %d, want 1", ProtoVersion)
	}
}

func TestRevisionNewer(t *testing.T) {
	cases := []struct {
		cand, cur string
		want      bool
	}{
		{"", "", false},
		{"", "123", false},
		{"123", "", true},
		{"2", "1", true},
		{"1", "2", false},
		{"2", "2", false},
		{"  2 ", " 1 ", true},
		{"abc", "2", true}, // unparseable falls back to inequality
		{"abc", "abc", false},
		{"1796470000000000002", "1796470000000000001", true},
	}
	for _, c := range cases {
		if got := RevisionNewer(c.cand, c.cur); got != c.want {
			t.Errorf("RevisionNewer(%q, %q) = %v, want %v", c.cand, c.cur, got, c.want)
		}
	}
}

func TestVersionMismatch(t *testing.T) {
	raw := []byte(`{"v":999,"type":"hello","data":{}}`)
	typ, data, err := Decode(raw)
	if err == nil {
		t.Fatal("Decode(v=999): expected error")
	}
	if typ != "hello" {
		t.Errorf("type = %q, want hello (type is reported even on mismatch)", typ)
	}
	if data != nil {
		t.Errorf("data = %v, want nil", data)
	}
	var pme *ProtoMismatchError
	if !errors.As(err, &pme) {
		t.Fatalf("error is %T, want *ProtoMismatchError", err)
	}
	if pme.Got != 999 {
		t.Errorf("Got = %d, want 999", pme.Got)
	}
}

func TestUnknownTypePassesThrough(t *testing.T) {
	// Forward compatibility: newer controllers may send types an older
	// side does not know. Decode must surface the type, not reject it.
	raw := []byte(`{"v":1,"type":"future.thing","data":{"x":1}}`)
	typ, data, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if typ != "future.thing" {
		t.Errorf("type = %q", typ)
	}
	if string(data) != `{"x":1}` {
		t.Errorf("data = %s", data)
	}
}

// TestValidCommandsComplete requires every Cmd* constant to be listed in
// ValidCommands — the agent-side allowlist must never drift from the
// command set.
func TestValidCommandsComplete(t *testing.T) {
	cmds := map[string]bool{
		CmdMatrixRestart: true, CmdMatrixStart: true, CmdMatrixStop: true,
		CmdMatrixRegister: true, CmdDiagPing: true, CmdAgentUpdate: true,
		CmdFwDetect: true, CmdFwSnapshot: true, CmdFwPlan: true, CmdFwApply: true,
		CmdFwTeardown: true, CmdPortCheck: true, CmdPortList: true,
		CmdNetDetect: true, CmdNetPlan: true, CmdNetApply: true, CmdNetStatus: true,
		CmdNetRB: true, CmdNetRevert: true,
		CmdHardeningDetect: true, CmdHardeningPlan: true, CmdHardeningApply: true,
		CmdHardeningConfirm: true, CmdHardeningRollback: true, CmdHardeningStatus: true,
		CmdNetProfileApply: true, CmdNetProfileConfirm: true, CmdNetProfileRollback: true,
	}
	for op := range cmds {
		if !ValidCommands[op] {
			t.Errorf("command %q missing from ValidCommands", op)
		}
	}
	if len(ValidCommands) != len(cmds) {
		t.Errorf("ValidCommands has %d entries, want %d", len(ValidCommands), len(cmds))
	}
	for op := range MutatingOps {
		if !ValidCommands[op] {
			t.Errorf("mutating op %q not in ValidCommands", op)
		}
	}
	// Profile applies and rollbacks are host-mutating: they must require
	// the confirm param like the other mutating ops. Confirms are NOT
	// mutating (PROTOCOL-REQUESTS R2): disarming is the safe direction;
	// the fail-closed direction is the timer.
	if MutatingOps[CmdHardeningDetect] || MutatingOps[CmdHardeningPlan] || MutatingOps[CmdHardeningStatus] ||
		MutatingOps[CmdHardeningConfirm] || MutatingOps[CmdNetProfileConfirm] {
		t.Error("confirm/detect/plan/status ops must stay non-mutating")
	}
	for _, op := range []string{CmdHardeningApply, CmdHardeningRollback, CmdNetProfileApply, CmdNetProfileRollback} {
		if !MutatingOps[op] {
			t.Errorf("profile op %q must be in MutatingOps", op)
		}
	}
}

// TestEncodeDecodeSymmetry covers the in-memory path both sides use.
func TestEncodeDecodeSymmetry(t *testing.T) {
	hello := Hello{ID: "agt_x", Version: "v1", Hostname: "h", OS: "linux", Arch: "amd64", Caps: []string{CapMatrix}}
	raw, err := Encode(MsgHello, hello)
	if err != nil {
		t.Fatal(err)
	}
	typ, data, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if typ != MsgHello {
		t.Fatalf("type = %q", typ)
	}
	var back Hello
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hello, back) {
		t.Fatalf("round trip mismatch: %+v vs %+v", hello, back)
	}
}

// TestDesiredV2Self (R6, phase 17): the panel stamps Self with the
// receiving agent's mesh server name; the fixture pins the wire shape.
// Backward compatibility: pre-R6 documents (desired-v2.json) have NO
// Self and every helper must answer false, and an old agent decoding a
// Self-stamped document ignores the unknown field.
func TestDesiredV2Self(t *testing.T) {
	_, _, data, err := DecodeAny(readFixture(t, "desired-v2-self.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc DesiredV2
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Self == nil || doc.Self.Name != "ir-drak-1" || doc.Self.Role != "iran" {
		t.Fatalf("self not decoded: %+v", doc.Self)
	}
	if !doc.IsSelfServer("ir-drak-1") {
		t.Fatal("IsSelfServer must match the stamped name")
	}
	if doc.IsSelfServer("hz-fra-1") || doc.IsSelfServer("") {
		t.Fatal("IsSelfServer must not match other/empty names")
	}

	// Pre-R6 document: no Self, helper always false.
	_, _, preData, err := DecodeAny(readFixture(t, "desired-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pre DesiredV2
	if err := json.Unmarshal(preData, &pre); err != nil {
		t.Fatal(err)
	}
	if pre.Self != nil || pre.IsSelfServer("ir-drak-1") {
		t.Fatalf("pre-R6 doc must have no Self: %+v", pre.Self)
	}

	// A typed struct WITHOUT the field (an old agent's inlined copy)
	// silently drops the unknown key — the compat property R6 relies on.
	var legacy struct {
		Revision string       `json:"revision"`
		Engines  []EngineSpec `json:"engines,omitempty"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Revision == "" || len(legacy.Engines) == 0 {
		t.Fatalf("legacy decode lost known fields: %+v", legacy)
	}

	// Encode/decode round trip keeps Self (wire symmetry both sides need).
	b, err := json.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	var back DesiredV2
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Self == nil || back.Self.Name != "ir-drak-1" || back.Self.Role != "iran" {
		t.Fatalf("self lost on round trip: %+v", back.Self)
	}

	// Nil-receiver and empty-name edges.
	var nilDoc *DesiredV2
	if nilDoc.IsSelfServer("x") {
		t.Fatal("nil doc must answer false")
	}
	empty := DesiredV2{Self: &SelfInfo{}}
	if empty.IsSelfServer("") || empty.IsSelfServer("x") {
		t.Fatal("empty Self.Name must answer false")
	}
}
