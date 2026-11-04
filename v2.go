package protocol

// Protocol v2 (Phase 1A): richer desired state (engines/tunnels/balancing/
// hardening), per-tunnel runtime reporting with wire+payload bytes, and
// hardening/netopt profile commands with confirm + rollback timer.
//
// Version negotiation: the envelope's V field IS the protocol version of
// that message. An endpoint sends hello/welcome in the highest version it
// speaks; the responder continues the session in
// Negotiate(peerMax, ownMax) = min. v1 agents therefore keep working with
// a v2 controller (it answers in v1), and per-envelope versions make any
// deviation visible and testable.

import (
	"encoding/json"
	"fmt"
)

// Protocol versions.
const (
	ProtoVersionV1 = 1
	ProtoVersionV2 = 2
)

// MinSupportedVersion / MaxSupportedVersion bound what DecodeAny accepts.
const (
	MinSupportedVersion = ProtoVersionV1
	MaxSupportedVersion = ProtoVersionV2
)

// EncodeVersioned wraps a payload into an envelope of the given protocol
// version. Payload structs must match that version's shape.
func EncodeVersioned(version int, typ string, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{V: version, Type: typ, Data: data})
}

// DecodeAny unwraps an envelope of any supported version (see
// MinSupportedVersion..MaxSupportedVersion) and reports which version the
// message used. The v1-only Decode remains for v1 call sites.
func DecodeAny(raw []byte) (version int, typ string, data json.RawMessage, err error) {
	var env Envelope
	if err = json.Unmarshal(raw, &env); err != nil {
		return 0, "", nil, err
	}
	if env.V < MinSupportedVersion || env.V > MaxSupportedVersion {
		return env.V, env.Type, nil, &ProtoMismatchError{Got: env.V}
	}
	return env.V, env.Type, env.Data, nil
}

// Negotiate picks the session version between two endpoints, each
// declaring the highest version it speaks. It errors when the overlap is
// empty (no version both sides understand).
func Negotiate(a, b int) (int, error) {
	v := a
	if b < v {
		v = b
	}
	if v < MinSupportedVersion || v > MaxSupportedVersion {
		return 0, fmt.Errorf("no common protocol version between %d and %d (supported %d..%d)",
			a, b, MinSupportedVersion, MaxSupportedVersion)
	}
	return v, nil
}

// ---- v2 desired state -------------------------------------------------
//
// DesiredV2 is the v2 full desired state for one agent. Revision fencing
// is unchanged from v1: strictly newer decimal-string revisions only,
// applied idempotently.

// DesiredV2 carries engines, tunnels, the balancing policy and the
// hardening profile reference.
type DesiredV2 struct {
	Revision     string           `json:"revision"`
	Engines      []EngineSpec     `json:"engines,omitempty"`
	Tunnels      []TunnelSpec     `json:"tunnels,omitempty"`
	Balancing    *BalancingPolicy `json:"balancing,omitempty"`
	HardeningRef string           `json:"hardening_ref,omitempty"`
	// Hardening carries the Profile document of HARDENING.md §2,
	// opaquely (see the comment above DesiredFieldHardening). Absent =
	// leave the host's hardening state alone.
	Hardening json.RawMessage `json:"hardening,omitempty"`
	// HardeningTimeoutSec is the optional safe-apply confirm window in
	// seconds (>= 120; the module clamps). Absent/0 = module default.
	HardeningTimeoutSec int `json:"hardening_timeout_sec,omitempty"`
	// TargetGroups name balancing groups of tunnels; ForwardRules
	// publish service ports balanced across a group.
	TargetGroups []TargetGroup `json:"target_groups,omitempty"`
	Forwards     []ForwardRule `json:"forwards,omitempty"`
}

// EngineSpec enables or disables one engine on the agent. A disabled
// engine must consume zero resources (no processes, no goroutines).
type EngineSpec struct {
	ID      string `json:"id"` // e.g. "matrix"; engine-defined
	Enabled bool   `json:"enabled"`
}

// TunnelSpec is one tunnel instance the agent must run. EngineParams is
// opaque here: only the named engine validates and interprets it.
type TunnelSpec struct {
	ID           string          `json:"id"`
	TopologyID   string          `json:"topology_id"`
	LocalServer  string          `json:"local_server"`
	RemoteServer string          `json:"remote_server"`
	Engine       string          `json:"engine"`
	EngineParams json.RawMessage `json:"engine_params,omitempty"`
	Enabled      bool            `json:"enabled"`
}

// BalancingPolicy is what the agent enforces locally (it must keep working
// when the panel is dead).
type BalancingPolicy struct {
	Weights     []WeightRule      `json:"weights,omitempty"`
	HealthCheck HealthCheckParams `json:"health_check"`
	Failover    FailoverRules     `json:"failover"`
}

// WeightRule assigns traffic weight. Rules are scoped: tunnel_id is the
// most specific, then (local_server, remote_server), then topology.
type WeightRule struct {
	TopologyID   string `json:"topology_id,omitempty"`
	LocalServer  string `json:"local_server,omitempty"`
	RemoteServer string `json:"remote_server,omitempty"`
	TunnelID     string `json:"tunnel_id,omitempty"`
	Weight       int    `json:"weight"` // 0 = excluded from balancing
}

// HealthCheckParams drive the agent's local health checks.
type HealthCheckParams struct {
	IntervalS       int    `json:"interval_s"`
	TimeoutMS       int    `json:"timeout_ms"`
	Probe           string `json:"probe"` // "icmp" | "tcp" | "engine"
	ConsecutiveDown int    `json:"consecutive_down"`
	ConsecutiveUp   int    `json:"consecutive_up"`
}

// FailoverRules drive automatic failover between foreign servers.
type FailoverRules struct {
	PreferOrder []string `json:"prefer_order,omitempty"` // remote servers, best first
	SwitchBackS int      `json:"switch_back_s,omitempty"`
	MaxLossPct  float64  `json:"max_loss_pct,omitempty"`
}

// ---- v2 reports -------------------------------------------------------

// TunnelRuntime is one tunnel's observed state in v2 reports: health plus
// BOTH byte counters. Wire bytes come from the carrier interface
// counters; payload bytes from the engine's own accounting. Quantum
// statistics are always real bytes — no coefficient is ever applied here.
type TunnelRuntime struct {
	TunnelID      string  `json:"tunnel_id"`
	Engine        string  `json:"engine"`
	Up            bool    `json:"up"`
	LatencyMs     float64 `json:"latency_ms,omitempty"`
	WireRx        uint64  `json:"wire_rx,omitempty"`
	WireTx        uint64  `json:"wire_tx,omitempty"`
	PayloadRx     uint64  `json:"payload_rx,omitempty"`
	PayloadTx     uint64  `json:"payload_tx,omitempty"`
	CountersKnown bool    `json:"counters_known"`
	// OverheadRatio = wire/payload over the sample window; present only
	// when both counters are known and payload > 0.
	OverheadRatio float64 `json:"overhead_ratio,omitempty"`
}

// EngineOverheadSample is a per-engine overhead observation for the
// panel's per-engine overhead ratio store.
type EngineOverheadSample struct {
	Engine    string `json:"engine"`
	Tunnels   int    `json:"tunnels"`
	WireRx    uint64 `json:"wire_rx"`
	PayloadRx uint64 `json:"payload_rx"`
	// Ratio = WireRx/PayloadRx over the sample window (payload > 0).
	Ratio float64 `json:"ratio"`
}

// StateReportV2 is the v2 full state report (heartbeat payload). The v1
// Matrix field is kept: the matrix driver reports through it unchanged.
type StateReportV2 struct {
	AppliedRevision string                 `json:"applied_revision,omitempty"`
	Matrix          []MatrixStatus         `json:"matrix,omitempty"`
	Tunnels         []TunnelRuntime        `json:"tunnels,omitempty"`
	Engines         []EngineOverheadSample `json:"engines,omitempty"`
	Resources       *ResourceReport        `json:"resources,omitempty"`
	UpdateProgress  *UpdateProgress        `json:"update_progress,omitempty"`
	NodeDetect      *NodeDetect            `json:"node_detect,omitempty"`
	Errors          []string               `json:"errors,omitempty"`
}

// ---- v2 commands ------------------------------------------------------
//
// Hardening/netopt profile commands reuse the v1 command envelope and its
// params map. Mutating profile applies REQUIRE params["confirm"] == "yes"
// (same rule as the v1 firewall/netopt ops) and SHOULD carry
// params["rollback_timer_s"] (decimal seconds): the agent schedules an
// automatic rollback to the previous profile if the apply is not
// confirmed-good within that window, so a bad profile can never lock the
// operator out.

// ParamConfirm is the required value of params["confirm"] for mutating ops.
const ParamConfirm = "confirm"

// ParamRollbackTimerS is the optional automatic-rollback timer in seconds.
const ParamRollbackTimerS = "rollback_timer_s"

// RollbackTimerS reads params[ParamRollbackTimerS] as decimal seconds;
// 0 = no timer.
func RollbackTimerS(params map[string]string) int {
	if params == nil {
		return 0
	}
	n := 0
	for _, c := range params[ParamRollbackTimerS] {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// HeartbeatV2 is the v2 heartbeat envelope payload: a v1 heartbeat whose
// state block is the richer StateReportV2.
type HeartbeatV2 struct {
	TS      int64          `json:"ts"`
	UptimeS int64          `json:"uptime_s"`
	State   *StateReportV2 `json:"state,omitempty"`
}

// ---- Phase 2A additions: hardening desired state + service forwards ----

// Hardening desired-state fields on DesiredV2 (HARDENING.md §5a). The
// hardening document is the Profile JSON of HARDENING.md §2; the
// protocol carries it opaquely — the agent's hardening module validates
// it (the Profile type lives with the module, which imports this
// package, so the dependency cannot point the other way).
const (
	// DesiredFieldHardening is the DesiredV2 JSON key carrying the
	// hardening Profile document.
	DesiredFieldHardening = "hardening"
	// DesiredFieldHardeningTimeoutSec is the optional safe-apply window
	// in seconds (module default and minimum: 120).
	DesiredFieldHardeningTimeoutSec = "hardening_timeout_sec"
)

// Hardening desired-state is transported opaquely so the Profile schema
// can evolve with the module (version field inside the document, §2).
// A v2 desired payload example:
//
//	{"revision": "42", "hardening": {...Profile...}, "hardening_timeout_sec": 120}
//
// The ack answers with the journal reference so the panel UI can show
// the ARMED state and its confirm banner (fields added to Ack below).

// TargetGroup names a balancing group of tunnels: every ENABLED tunnel
// of the agent whose TopologyID matches, optionally filtered to one
// remote server. Numbers are variable by design — N Iran servers per
// datacenter, M foreign servers, K tunnels per pair, each tunnel free to
// use a different engine — so a group is a selector, never a list.
type TargetGroup struct {
	ID           string `json:"id"`
	TopologyID   string `json:"topology_id"`
	RemoteServer string `json:"remote_server,omitempty"` // empty = whole foreign pool of the topology
}

// ForwardRule publishes one service port on an Iran agent and
// load-balances it across the tunnels of its target group (see
// TargetGroup). The agent enforces it locally with a kernel path
// (nftables) and keeps it working when the panel is dead.
type ForwardRule struct {
	ID          string `json:"id"`
	ListenPort  int    `json:"listen_port"`
	Proto       string `json:"proto"` // "tcp" | "udp" | "both"
	TargetGroup string `json:"target_group"`
	TargetPort  int    `json:"target_port"` // port on the foreign side; 0 = same as ListenPort
}

// ValidForwardProto reports whether proto is one of the accepted values.
func ValidForwardProto(p string) bool {
	return p == "tcp" || p == "udp" || p == "both"
}
