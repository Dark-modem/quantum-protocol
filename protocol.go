// Package protocol is the wire contract between the Quantum agent
// ("quantum-agent run") and the central controller (the Quantum panel
// running the agent hub). Both sides speak JSON envelopes over one
// outbound WebSocket the agent dials to the controller; the controller
// never dials the agent, so an endpoint behind NAT/firewall works and no
// inbound management port is opened on endpoints.
//
// Message flow:
//
//	agent   -> hello                      (right after the WS is up)
//	ctrl    -> welcome                    (ok:true or ok:false + close)
//	ctrl    -> desired                    (whenever a desired state is pending)
//	agent   -> ack                        (one per desired, applied or failed)
//	agent   -> heartbeat                  (every ~30s, carries latest state)
//	ctrl    -> command                    (allowlisted ops only)
//	agent   -> result                     (one per command)
//	agent   -> register                   (node announces itself to the hub)
//	ctrl    -> register_result            (after relaying to the hub agent)
//
// Every desired state carries a monotonically increasing revision; the
// agent rejects stale (older than applied) and duplicate (equal to
// applied) revisions, and applies the rest idempotently. The tunnel runs
// under its own systemd unit, so losing the controller connection never
// stops user traffic.
//
// This package is intentionally dependency-free (stdlib only): the agent
// side, the controller side and their tests all share these exact types.
//
// Lineage: extracted verbatim from the shared agentproto.go of the panel
// monolith (canonical-repository.git @ a1e999c); identifiers were
// exported without changing any wire value. The panel and agent trees
// keep unexported aliases of these names so their historical call sites
// are unchanged.
package protocol

import (
	"encoding/json"
	"strconv"
)

// ProtoVersion is bumped on incompatible protocol changes; both
// sides include it in hello/welcome and refuse mismatches.
const ProtoVersion = 1

// HTTP headers used for agent authentication and enrollment.
const (
	HeaderAgentID     = "X-Agent-Id"
	HeaderAgentKey    = "X-Agent-Key"
	HeaderEnrollToken = "X-Enroll-Token"
)

// Agent capability strings. v1 ships the Matrix engine only; future
// engines add their own caps without breaking old agents.
const (
	CapMatrix     = "matrix"
	CapTraffic    = "traffic"
	CapHealth     = "health"
	CapNodeDetect = "node-detect" // read-only PasarGuard Node detection
	// CapHardening is advertised in hello only when the agent's
	// hardening module is wired (HARDENING.md §5c); the panel must not
	// push hardening desired state to agents without it.
	CapHardening = "hardening"
)

// Envelope types.
const (
	MsgHello          = "hello"
	MsgWelcome        = "welcome"
	MsgHeartbeat      = "heartbeat"
	MsgDesired        = "desired"
	MsgAck            = "ack"
	MsgCommand        = "command"
	MsgResult         = "result"
	MsgRegister       = "register"
	MsgRegisterResult = "register_result"
	MsgError          = "error"
)

// Allowlisted remote commands. Anything else the controller sends is
// rejected with an error result — the agent never runs shell commands.
const (
	CmdMatrixRestart  = "matrix.restart"
	CmdMatrixStart    = "matrix.start"
	CmdMatrixStop     = "matrix.stop"
	CmdMatrixRegister = "matrix.register" // hub side: pair a node host file
	CmdDiagPing       = "diag.ping"
	CmdAgentUpdate    = "agent.update" // self-update from a signed artifact

	// Typed firewall/port operations (Session 1 handlers) and network
	// optimization operations (Session 2 handlers). Params carry one JSON
	// "payload" field per op; results return as JSON in Output. Mutating
	// ops additionally require payload.confirm == "yes".
	CmdFwDetect   = "firewall.detect"
	CmdFwSnapshot = "firewall.snapshot"
	CmdFwPlan     = "firewall.plan"
	CmdFwApply    = "firewall.apply"
	CmdFwTeardown = "firewall.teardown"
	CmdPortCheck  = "port.check"
	CmdPortList   = "port.list"
	CmdNetDetect  = "netopt.detect"
	CmdNetPlan    = "netopt.plan"
	CmdNetApply   = "netopt.apply"
	CmdNetStatus  = "netopt.status"
	CmdNetRB      = "netopt.rollback"
	CmdNetRevert  = "netopt.revert"

	// v2 hardening commands (HARDENING.md §5b): the imperative path.
	// apply arms the safe-apply journal (returns ARMED, not done); the
	// panel must confirm within the rollback window or the agent rolls
	// back automatically. MutatingOps gates apply/confirm/rollback with
	// params["confirm"] == "yes" as in v1; the module's own safe-apply
	// is a second, independent gate. Params per §5b: apply
	// {profile, safe_apply, rollback_timeout_sec}, confirm
	// {journal_id}, rollback {journal_id}, detect/plan/status as
	// documented there.
	CmdHardeningDetect   = "hardening.detect"
	CmdHardeningPlan     = "hardening.plan"
	CmdHardeningApply    = "hardening.apply"
	CmdHardeningConfirm  = "hardening.confirm"
	CmdHardeningRollback = "hardening.rollback"
	CmdHardeningStatus   = "hardening.status"

	// v2 netopt profile commands. Mutating applies and rollbacks require
	// params["confirm"] == "yes" and carry params["rollback_timer_s"];
	// see v2.go.
	CmdNetProfileApply    = "netopt.profile.apply"
	CmdNetProfileRollback = "netopt.profile.rollback"
)

// ValidCommands is the complete remote-operation allowlist.
var ValidCommands = map[string]bool{
	CmdMatrixRestart:      true,
	CmdMatrixStart:        true,
	CmdMatrixStop:         true,
	CmdMatrixRegister:     true,
	CmdDiagPing:           true,
	CmdAgentUpdate:        true,
	CmdFwDetect:           true,
	CmdFwSnapshot:         true,
	CmdFwPlan:             true,
	CmdFwApply:            true,
	CmdFwTeardown:         true,
	CmdPortCheck:          true,
	CmdPortList:           true,
	CmdNetDetect:          true,
	CmdNetPlan:            true,
	CmdNetApply:           true,
	CmdNetStatus:          true,
	CmdNetRB:              true,
	CmdNetRevert:          true,
	CmdHardeningDetect:    true,
	CmdHardeningPlan:      true,
	CmdHardeningApply:     true,
	CmdHardeningConfirm:   true,
	CmdHardeningRollback:  true,
	CmdHardeningStatus:    true,
	CmdNetProfileApply:    true,
	CmdNetProfileRollback: true,
}

// MutatingOps require payload.confirm == "yes" on the agent and are
// audit-logged on both sides.
var MutatingOps = map[string]bool{
	CmdFwApply:            true,
	CmdFwTeardown:         true,
	CmdNetApply:           true,
	CmdNetRB:              true,
	CmdNetRevert:          true,
	CmdHardeningApply:     true,
	CmdHardeningConfirm:   true,
	CmdHardeningRollback:  true,
	CmdNetProfileApply:    true,
	CmdNetProfileRollback: true,
}

// Envelope wraps every message in both directions.
type Envelope struct {
	V    int             `json:"v"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Encode wraps a payload into an envelope.
func Encode(typ string, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{V: ProtoVersion, Type: typ, Data: data})
}

// Decode unwraps an envelope, checking the protocol version.
func Decode(raw []byte) (string, json.RawMessage, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", nil, err
	}
	if env.V != ProtoVersion {
		return env.Type, nil, &ProtoMismatchError{Got: env.V}
	}
	return env.Type, env.Data, nil
}

// ProtoMismatchError signals a version mismatch on the wire.
type ProtoMismatchError struct{ Got int }

func (e *ProtoMismatchError) Error() string {
	return "agent protocol version mismatch: got " + strconv.Itoa(e.Got) +
		", supported " + strconv.Itoa(MinSupportedVersion) + ".." + strconv.Itoa(MaxSupportedVersion)
}
