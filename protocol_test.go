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
	file string
	typ  string
	new  func() any
}

var fixtureCases = []fixtureCase{
	{"hello.json", MsgHello, func() any { return &Hello{} }},
	{"welcome.json", MsgWelcome, func() any { return &Welcome{} }},
	{"heartbeat.json", MsgHeartbeat, func() any { return &Heartbeat{} }},
	{"desired.json", MsgDesired, func() any { return &Desired{} }},
	{"ack.json", MsgAck, func() any { return &Ack{} }},
	{"command.json", MsgCommand, func() any { return &Command{} }},
	{"result.json", MsgResult, func() any { return &CommandResult{} }},
	{"register.json", MsgRegister, func() any { return &RegisterMsg{} }},
	{"register_result.json", MsgRegisterResult, func() any { return &RegisterResult{} }},
	{"error.json", MsgError, func() any { return &ErrorMsg{} }},
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
			typ, data, err := Decode(readFixture(t, fc.file))
			if err != nil {
				t.Fatalf("Decode(%s): %v", fc.file, err)
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

// TestFixtureRoundTrip re-encodes the decoded fixture and requires the
// result to be semantically identical (same JSON document; key order is
// not part of the contract).
func TestFixtureRoundTrip(t *testing.T) {
	for _, fc := range fixtureCases {
		t.Run(fc.file, func(t *testing.T) {
			raw := readFixture(t, fc.file)
			_, data, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode(%s): %v", fc.file, err)
			}
			msg := fc.new()
			if err := json.Unmarshal(data, msg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			re, err := Encode(fc.typ, msg)
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

// TestWireStringsPinned guards the literal wire strings against silent
// renames. These values are shared with deployed agents.
func TestWireStringsPinned(t *testing.T) {
	wire := map[string]string{
		"ProtoVersion":      "1", // compared as int below
		"HeaderAgentID":     HeaderAgentID,
		"HeaderAgentKey":    HeaderAgentKey,
		"HeaderEnrollToken": HeaderEnrollToken,
		"CapMatrix":         CapMatrix,
		"CapTraffic":        CapTraffic,
		"CapHealth":         CapHealth,
		"CapNodeDetect":     CapNodeDetect,
		"MsgHello":          MsgHello,
		"MsgWelcome":        MsgWelcome,
		"MsgHeartbeat":      MsgHeartbeat,
		"MsgDesired":        MsgDesired,
		"MsgAck":            MsgAck,
		"MsgCommand":        MsgCommand,
		"MsgResult":         MsgResult,
		"MsgRegister":       MsgRegister,
		"MsgRegisterResult": MsgRegisterResult,
		"MsgError":          MsgError,
		"CmdMatrixRestart":  CmdMatrixRestart,
		"CmdMatrixStart":    CmdMatrixStart,
		"CmdMatrixStop":     CmdMatrixStop,
		"CmdMatrixRegister": CmdMatrixRegister,
		"CmdDiagPing":       CmdDiagPing,
		"CmdAgentUpdate":    CmdAgentUpdate,
		"CmdFwDetect":       CmdFwDetect,
		"CmdFwSnapshot":     CmdFwSnapshot,
		"CmdFwPlan":         CmdFwPlan,
		"CmdFwApply":        CmdFwApply,
		"CmdFwTeardown":     CmdFwTeardown,
		"CmdPortCheck":      CmdPortCheck,
		"CmdPortList":       CmdPortList,
		"CmdNetDetect":      CmdNetDetect,
		"CmdNetPlan":        CmdNetPlan,
		"CmdNetApply":       CmdNetApply,
		"CmdNetStatus":      CmdNetStatus,
		"CmdNetRB":          CmdNetRB,
		"CmdNetRevert":      CmdNetRevert,
	}
	want := map[string]string{
		"HeaderAgentID":     "X-Agent-Id",
		"HeaderAgentKey":    "X-Agent-Key",
		"HeaderEnrollToken": "X-Enroll-Token",
		"CapMatrix":         "matrix",
		"CapTraffic":        "traffic",
		"CapHealth":         "health",
		"CapNodeDetect":     "node-detect",
		"MsgHello":          "hello",
		"MsgWelcome":        "welcome",
		"MsgHeartbeat":      "heartbeat",
		"MsgDesired":        "desired",
		"MsgAck":            "ack",
		"MsgCommand":        "command",
		"MsgResult":         "result",
		"MsgRegister":       "register",
		"MsgRegisterResult": "register_result",
		"MsgError":          "error",
		"CmdMatrixRestart":  "matrix.restart",
		"CmdMatrixStart":    "matrix.start",
		"CmdMatrixStop":     "matrix.stop",
		"CmdMatrixRegister": "matrix.register",
		"CmdDiagPing":       "diag.ping",
		"CmdAgentUpdate":    "agent.update",
		"CmdFwDetect":       "firewall.detect",
		"CmdFwSnapshot":     "firewall.snapshot",
		"CmdFwPlan":         "firewall.plan",
		"CmdFwApply":        "firewall.apply",
		"CmdFwTeardown":     "firewall.teardown",
		"CmdPortCheck":      "port.check",
		"CmdPortList":       "port.list",
		"CmdNetDetect":      "netopt.detect",
		"CmdNetPlan":        "netopt.plan",
		"CmdNetApply":       "netopt.apply",
		"CmdNetStatus":      "netopt.status",
		"CmdNetRB":          "netopt.rollback",
		"CmdNetRevert":      "netopt.revert",
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
