package protocol

// v2 contract tests: negotiation, envelope versioning, desired-state v2
// semantics, per-tunnel wire+payload reporting, and the profile-command
// confirm/rollback-timer rule.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNegotiate(t *testing.T) {
	// Both v1: v1. v2 controller + v1 agent: v1 (downgrade, never up).
	// v1 controller + v2 agent: v1. Both v2: v2. Anything below the
	// supported floor is an error.
	cases := []struct {
		a, b, want int
		wantErr    bool
	}{
		{1, 1, 1, false},
		{2, 1, 1, false},
		{1, 2, 1, false},
		{2, 2, 2, false},
		{0, 2, 0, true},
		{3, 3, 0, true}, // both speak an unsupported future version
	}
	for _, c := range cases {
		got, err := Negotiate(c.a, c.b)
		if c.wantErr {
			if err == nil {
				t.Errorf("Negotiate(%d,%d) = %d, want error", c.a, c.b, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Negotiate(%d,%d) = %d, %v; want %d, nil", c.a, c.b, got, err, c.want)
		}
	}
}

func TestDecodeAnyAcceptsV1AndV2(t *testing.T) {
	v1, err := Encode(MsgHello, Hello{ID: "agt_x", Version: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	v2, err := EncodeVersioned(ProtoVersionV2, MsgDesired, DesiredV2{Revision: "7"})
	if err != nil {
		t.Fatal(err)
	}
	version, typ, data, err := DecodeAny(v1)
	if err != nil || version != ProtoVersionV1 || typ != MsgHello || len(data) == 0 {
		t.Fatalf("v1: %d %q %v", version, typ, err)
	}
	version, typ, data, err = DecodeAny(v2)
	if err != nil || version != ProtoVersionV2 || typ != MsgDesired || len(data) == 0 {
		t.Fatalf("v2: %d %q %v", version, typ, err)
	}
	var d DesiredV2
	if err := json.Unmarshal(data, &d); err != nil || d.Revision != "7" {
		t.Fatalf("v2 desired payload: %v %+v", err, d)
	}
}

func TestDecodeAnyRejectsUnknownVersions(t *testing.T) {
	for _, v := range []int{0, 3, 99} {
		raw, err := EncodeVersioned(v, MsgHello, Hello{ID: "x"})
		if err != nil {
			t.Fatal(err)
		}
		version, _, data, err := DecodeAny(raw)
		if err == nil {
			t.Fatalf("DecodeAny(v=%d) accepted", v)
		}
		var pme *ProtoMismatchError
		if !asProtoMismatch(err, &pme) {
			t.Fatalf("v=%d: error is %T, want *ProtoMismatchError", v, err)
		}
		if pme.Got != v || data != nil {
			t.Fatalf("v=%d: Got=%d data=%v", v, pme.Got, data)
		}
		if version != v {
			t.Fatalf("v=%d: reported version %d", v, version)
		}
		if !strings.Contains(pme.Error(), "supported 1..2") {
			t.Fatalf("message %q should state the supported range", pme.Error())
		}
	}
}

func asProtoMismatch(err error, target **ProtoMismatchError) bool {
	if pme, ok := err.(*ProtoMismatchError); ok {
		*target = pme
		return true
	}
	return false
}

// TestDesiredV2FixtureSemantics pins the v2 desired state contract beyond
// the generic round-trip: opaque engine params survive byte-identically,
// weights scope from tunnel (most specific) to topology, and the
// hardening reference rides along.
func TestDesiredV2FixtureSemantics(t *testing.T) {
	_, _, data, err := DecodeAny(readFixture(t, "desired-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d DesiredV2
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if d.Revision == "" || d.HardeningRef != "hardening/v3-baseline" {
		t.Fatalf("revision/hardening: %+v", d)
	}
	if len(d.Engines) != 3 || len(d.Tunnels) != 4 {
		t.Fatalf("engines=%d tunnels=%d", len(d.Engines), len(d.Tunnels))
	}
	// The engine_params a tunnel carries must round-trip byte-identically:
	// the engine owns that JSON, the protocol must not reinterpret it.
	want := `{"instance": "matrix", "role": "hub"}`
	if string(d.Tunnels[0].EngineParams) != want {
		t.Fatalf("engine_params = %s, want %s", d.Tunnels[0].EngineParams, want)
	}
	if !d.Tunnels[2].Enabled && d.Tunnels[2].Engine != "backhaul" {
		t.Fatalf("tunnel 2: %+v", d.Tunnels[2])
	}
	b := d.Balancing
	if b == nil || len(b.Weights) != 3 || b.HealthCheck.IntervalS != 15 ||
		b.HealthCheck.Probe != "icmp" || len(b.Failover.PreferOrder) != 2 ||
		b.Failover.SwitchBackS != 300 {
		t.Fatalf("balancing: %+v", b)
	}
	// Weight specificity: the tunnel-scoped rule exists alongside the
	// server-scoped ones; resolution order is documented in the type.
	if b.Weights[2].TunnelID != "tun-drak1-hz1-b" || b.Weights[2].Weight != 10 {
		t.Fatalf("tunnel weight rule: %+v", b.Weights[2])
	}
}

// TestHeartbeatV2FixtureSemantics pins the per-tunnel wire+payload report
// contract: both counters always real bytes, overhead ratio derived only
// when both are known.
func TestHeartbeatV2FixtureSemantics(t *testing.T) {
	_, _, data, err := DecodeAny(readFixture(t, "heartbeat-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var hb HeartbeatV2
	if err := json.Unmarshal(data, &hb); err != nil {
		t.Fatal(err)
	}
	st := hb.State
	if st == nil || len(st.Tunnels) != 2 || len(st.Engines) != 1 {
		t.Fatalf("state: %+v", st)
	}
	up := st.Tunnels[0]
	if !up.Up || !up.CountersKnown || up.WireRx != 10500000 || up.PayloadRx != 10000000 {
		t.Fatalf("tunnel runtime: %+v", up)
	}
	if up.OverheadRatio < 1.0499 || up.OverheadRatio > 1.0501 {
		t.Fatalf("overhead ratio = %v, want ~1.05", up.OverheadRatio)
	}
	down := st.Tunnels[1]
	if down.Up || down.CountersKnown || down.OverheadRatio != 0 {
		t.Fatalf("down tunnel must carry no counters: %+v", down)
	}
	if st.Engines[0].Engine != "matrix" || st.Engines[0].Ratio != 1.05 {
		t.Fatalf("engine overhead: %+v", st.Engines[0])
	}
	// The v1 matrix block still rides along for the matrix driver.
	if len(st.Matrix) != 1 || st.Matrix[0].Instance != "matrix" {
		t.Fatalf("matrix legacy block: %+v", st.Matrix)
	}
}

func TestProfileCommandFixtures(t *testing.T) {
	for _, f := range []string{"command-hardening-apply.json", "command-hardening-rollback.json",
		"command-netopt-profile-apply.json", "command-netopt-profile-rollback.json"} {
		_, _, data, err := DecodeAny(readFixture(t, f))
		if err != nil {
			t.Fatal(err)
		}
		var c Command
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		if !ValidCommands[c.Op] {
			t.Errorf("%s: op %q not allowlisted", f, c.Op)
		}
		if !MutatingOps[c.Op] {
			t.Errorf("%s: op %q must be mutating", f, c.Op)
		}
		if c.Params[ParamConfirm] != "yes" {
			t.Errorf("%s: mutating profile op without confirm=yes: %v", f, c.Params)
		}
	}
	// The apply fixtures carry the automatic-rollback timer; rollbacks may too.
	_, _, payload, _ := DecodeAny(readFixture(t, "command-hardening-apply.json"))
	var c Command
	_ = json.Unmarshal(payload, &c)
	if got := RollbackTimerS(c.Params); got != 300 {
		t.Errorf("hardening.apply rollback timer = %d, want 300", got)
	}
	if got := RollbackTimerS(nil); got != 0 {
		t.Errorf("RollbackTimerS(nil) = %d, want 0", got)
	}
	if got := RollbackTimerS(map[string]string{ParamRollbackTimerS: "12x"}); got != 0 {
		t.Errorf("non-numeric timer must read as 0, got %d", got)
	}
}

// TestV1AgentStillWorksWithV2Peer documents the negotiation promise: a
// v1-only peer and a v2 peer agree on v1, and every v1 message remains
// decodable by a v2-speaking endpoint via DecodeAny.
func TestV1AgentStillWorksWithV2Peer(t *testing.T) {
	v, err := Negotiate(ProtoVersionV1, MaxSupportedVersion)
	if err != nil || v != ProtoVersionV1 {
		t.Fatalf("negotiate v1 peer vs v2 peer = %d, %v", v, err)
	}
	// A v2 controller must answer a v1 hello with a v1 welcome.
	hello, _ := Encode(MsgHello, Hello{ID: "agt_old", Version: "v1.29.0"})
	version, typ, _, err := DecodeAny(hello)
	if err != nil || version != ProtoVersionV1 || typ != MsgHello {
		t.Fatalf("v1 hello via DecodeAny: %d %q %v", version, typ, err)
	}
	welcome, err := EncodeVersioned(v, MsgWelcome, Welcome{OK: true, Server: "v2"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Decode(welcome); err != nil {
		t.Fatalf("v1 peer must be able to Decode the v1-encoded welcome: %v", err)
	}
}
