package protocol

import "encoding/json"

// Hello is the first message the agent sends after connecting.
type Hello struct {
	ID       string   `json:"id"` // agent id from enrollment ("agt_…")
	Version  string   `json:"version"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Caps     []string `json:"caps,omitempty"`
}

// Welcome is the controller's answer to hello.
type Welcome struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Server string `json:"server,omitempty"` // controller version
}

// Heartbeat is sent periodically and on demand; it carries the
// latest full state report so a controller that just (re)connected gets
// everything in one message.
type Heartbeat struct {
	TS      int64        `json:"ts"`
	UptimeS int64        `json:"uptime_s"`
	State   *StateReport `json:"state,omitempty"`
}

// StateReport is the agent's complete picture of its host: what is
// applied, what health it measured, and what traffic it counted. It is
// also what the controller persists per agent for the dashboards.
type StateReport struct {
	AppliedRevision string          `json:"applied_revision,omitempty"`
	Matrix          []MatrixStatus  `json:"matrix,omitempty"`
	Health          []TunnelHealth  `json:"health,omitempty"`
	Traffic         *TrafficReport  `json:"traffic,omitempty"`
	Resources       *ResourceReport `json:"resources,omitempty"`
	UpdateProgress  *UpdateProgress `json:"update_progress,omitempty"`
	NodeDetect      *NodeDetect     `json:"node_detect,omitempty"`
	Errors          []string        `json:"errors,omitempty"`
}

// ResourceReport is the lightweight host snapshot for the controller
// dashboards: CPU/RAM/disk/virt plus the listening-port inventory with
// ownership hints. Measured values only — nothing is estimated here.
type ResourceReport struct {
	CPUModel    string       `json:"cpu_model,omitempty"`
	CPUCores    int          `json:"cpu_cores"`
	CPUPercent  float64      `json:"cpu_percent"` // sampled over ~200ms
	LoadAvg1    float64      `json:"load_avg_1"`
	MemTotalMB  uint64       `json:"mem_total_mb"`
	MemUsedMB   uint64       `json:"mem_used_mb"` // total - available
	DiskTotalGB uint64       `json:"disk_total_gb"`
	DiskUsedGB  uint64       `json:"disk_used_gb"` // root filesystem
	UptimeS     uint64       `json:"uptime_s"`
	Virt        string       `json:"virt,omitempty"` // systemd-detect-virt
	Listening   []ListenPort `json:"listening,omitempty"`
}

// ListenPort is one listening socket with an ownership hint.
type ListenPort struct {
	Proto string `json:"proto"` // "tcp" | "udp"
	Port  int    `json:"port"`
	Addr  string `json:"addr"`           // bind address as reported
	Proc  string `json:"proc,omitempty"` // process name(s), comma-joined
}

// MatrixStatus is one local Matrix instance as seen by the agent.
// Secrets (tinc token, keys) never cross this interface.
type MatrixStatus struct {
	Instance   string     `json:"instance"` // "matrix", "matrix2", …
	Role       string     `json:"role"`     // "hub" (Iran) | "node" (foreign)
	Network    string     `json:"network,omitempty"`
	Enabled    bool       `json:"enabled"`
	Service    bool       `json:"service"`            // systemd unit active
	Iface      string     `json:"iface"`              // qmx0, qmx2, …
	IfaceUp    bool       `json:"iface_up"`           // interface exists & up
	Port       int        `json:"port"`               // mesh port
	MeshIP     string     `json:"mesh_ip"`            // own /30 address
	Peers      []PeerPing `json:"peers"`              // mesh reachability right now
	Registered bool       `json:"registered"`         // hub: a node is paired; node: hub accepted us
	Revision   string     `json:"revision,omitempty"` // last applied desired revision
}

// PeerPing is one mesh peer's instantaneous reachability.
type PeerPing struct {
	Name      string  `json:"name"`
	IP        string  `json:"ip"`
	OK        bool    `json:"ok"`
	LatencyMs float64 `json:"latency_ms"`
}

// TunnelHealth is the rolling 60-second quality window for one
// Matrix instance: low-bandwidth ICMP probes only, never a bandwidth
// test. Quality buckets: "good" | "fair" | "poor" | "down".
type TunnelHealth struct {
	Instance  string  `json:"instance"`
	WindowS   int     `json:"window_s"`
	Samples   int     `json:"samples"`
	LatencyMs float64 `json:"latency_ms"` // window average
	JitterMs  float64 `json:"jitter_ms"`  // mean absolute delta between probes
	LossPct   float64 `json:"loss_pct"`   // 0-100
	Reachable bool    `json:"reachable"`
	Service   bool    `json:"service"`
	IfaceUp   bool    `json:"iface_up"`
	Quality   string  `json:"quality"`
}

// TrafficReport carries per-interface cumulative counters. The
// agent reports raw counters; the controller derives deltas so a missed
// heartbeat never loses bytes (counters are monotonic between reports).
type TrafficReport struct {
	TS     int64           `json:"ts"`
	Ifaces []IfaceCounters `json:"ifaces"`
}

// IfaceCounters is one interface's cumulative RX/TX bytes. Kind is
// "physical" (billable NIC accounting) or "tunnel" (Matrix overlay,
// e.g. qmx0). Known=false means the counter could not be read — the
// controller must then show UNKNOWN instead of inventing a number.
type IfaceCounters struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"` // "physical" | "tunnel"
	Rx    uint64 `json:"rx"`
	Tx    uint64 `json:"tx"`
	Known bool   `json:"known"`
}

// NodeDetect is the read-only PasarGuard Node signal. The agent
// never touches the containers, Docker config, API keys or units.
type NodeDetect struct {
	Detected bool   `json:"detected"`
	Kind     string `json:"kind,omitempty"` // e.g. "docker-container"
	Detail   string `json:"detail,omitempty"`
}

// UpdateRequest is the payload of the agent.update command. Every
// field is mandatory: the agent refuses partial requests. The artifact must
// be HTTPS, carry the exact sha256 and an ed25519 signature made with the
// update public key pinned in the binary; without a pinned key the agent
// refuses all updates (fail closed).
type UpdateRequest struct {
	Version   string `json:"version"`   // target version marker, e.g. v1.28.1
	URL       string `json:"url"`       // https:// artifact URL (agent-authenticated)
	SHA256Hex string `json:"sha256"`    // sha256 of the artifact bytes
	Signature string `json:"signature"` // base64 std ed25519 signature over the artifact bytes
}

// UpdateProgress rides the heartbeat state so the controller UI can
// show live update phases and the final verdict.
type UpdateProgress struct {
	Phase   string `json:"phase"` // requested|downloading|verifying|swapped|restarting|completed|failed
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
	At      int64  `json:"at"`
}

// Desired is the full desired state the controller hands one agent.
// Revision must be strictly newer than what the agent has applied.
type Desired struct {
	Revision string         `json:"revision"`
	Matrix   *DesiredMatrix `json:"matrix,omitempty"`
}

// DesiredMatrix describes the Matrix work an agent should do.
// Action "apply" provisions/updates the instance; "remove" tears it down.
// Hub payloads are structured; node payloads reuse the existing
// hmx1_ pairing bundle verbatim so the proven node path is reused.
type DesiredMatrix struct {
	Instance string      `json:"instance"` // "matrix", "matrix2", …
	Action   string      `json:"action"`   // "apply" | "remove"
	Hub      *DesiredHub `json:"hub,omitempty"`
	Bundle   string      `json:"bundle,omitempty"` // "hmx1_…" (node side)
}

// DesiredHub is the hub-side Matrix configuration.
type DesiredHub struct {
	Family string `json:"family"` // "ipv4" | "ipv6"
	Port   int    `json:"port"`   // mesh port; 0 = agent auto-picks
	Addr   string `json:"addr"`   // hub public address
	Ports  []int  `json:"ports"`  // forwarded user ports
	Token  string `json:"token"`  // pairing token (controller-generated)
}

// Ack answers a desired revision. Detail may carry extra artifacts
// the controller needs to drive the other side (e.g. the hub's tinc
// host file under key "main_host").
type Ack struct {
	Revision string            `json:"revision"`
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`

	// Hardening desired-state ack additions (HARDENING.md §5a). All
	// fields are optional; v1 panels decode this struct and silently
	// drop what they do not know, so the wire stays compatible.
	Kind string `json:"kind,omitempty"` // e.g. "hardening"
	// JournalID references the safe-apply journal entry ("hp_…").
	JournalID string `json:"journal_id,omitempty"`
	// Armed reports that safe-apply is pending confirmation (the panel
	// UI must show the confirm banner; no confirm ⇒ automatic rollback).
	Armed bool `json:"armed,omitempty"`
	// TimerUnit is the systemd unit that will roll the change back.
	TimerUnit string          `json:"timer_unit,omitempty"`
	Plan      json.RawMessage `json:"plan,omitempty"` // the applied plan, for the UI diff
}

// Command is one allowlisted remote operation.
type Command struct {
	ID     string            `json:"id"`
	Op     string            `json:"op"`
	Params map[string]string `json:"params,omitempty"`
}

// CommandResult answers a command.
type CommandResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"` // short diagnostic text only
	// Data carries the structured result of typed ops that return more
	// than text (HARDENING.md §5b: hardening.detect/plan/status answer
	// with {state}, {plan}, {journal, armed, state}; apply answers with
	// {journal, armed, timer_unit, verify}). Optional; v1 panels never
	// see it because the ops are v2-gated by capabilities.
	Data json.RawMessage `json:"data,omitempty"`
}

// RegisterMsg is sent by a node agent after it applied its bundle:
// the hub needs the node's tinc host file to finish pairing. The
// controller relays it to the hub agent as a matrix register command.
type RegisterMsg struct {
	Instance string `json:"instance"` // instance on the node
	TunnelID string `json:"tunnel_id,omitempty"`
	Token    string `json:"token"`
	Name     string `json:"name"`
	HostFile string `json:"host_file"` // node hosts/<name> content (PEM included)
	Revision string `json:"revision,omitempty"`
}

// RegisterResult is the controller's answer to register.
type RegisterResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ErrorMsg is a soft failure notice (agent -> ctrl) that does not
// close the session.
type ErrorMsg struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// Compile-time guard that Data stays raw JSON on the wire.
var _ json.RawMessage = Envelope{}.Data
