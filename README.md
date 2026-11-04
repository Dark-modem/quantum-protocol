# quantum-protocol

Wire contract shared by the Quantum panel (controller) and the Quantum
agent: JSON envelope messages over one outbound WebSocket the agent dials
to the controller. Stdlib-only, no dependencies.

Extracted verbatim from the monolith's `agentproto.go` (canonical
repository @ `a1e999c`); identifiers were exported without changing any
wire value.

## API surface

- `ProtoVersion` (currently `1`) and `Encode` / `Decode` — envelope
  framing with version checking (`*ProtoMismatchError` on mismatch).
- Message kind constants `MsgHello` … `MsgError`, HTTP auth headers
  (`HeaderAgentID`, `HeaderAgentKey`, `HeaderEnrollToken`), capability
  strings (`CapMatrix` …), and the allowlisted remote commands
  (`CmdMatrixRestart` … `CmdNetRevert`) with `ValidCommands` /
  `MutatingOps`.
- Typed payloads: `Hello`, `Welcome`, `Heartbeat`, `StateReport`,
  `ResourceReport`, `ListenPort`, `MatrixStatus`, `PeerPing`,
  `TunnelHealth`, `TrafficReport`, `IfaceCounters`, `NodeDetect`,
  `UpdateRequest`, `UpdateProgress`, `Desired`, `DesiredMatrix`,
  `DesiredHub`, `Ack`, `Command`, `CommandResult`, `RegisterMsg`,
  `RegisterResult`, `ErrorMsg`.
- `RevisionNewer` — desired-state revision ordering.

## Compatibility guarantee

`fixtures/*.json` are golden wire documents. `protocol_test.go` decodes
every fixture, re-encodes it, and requires semantic identity, plus a
pinned-string test over every constant. If you need to change the wire,
bump `ProtoVersion` and add new fixtures — never edit old ones.

## Consuming

Until the repos are pushed, panel and agent use a `replace` directive:

```
require github.com/Dark-modem/quantum-protocol v0.0.0
replace github.com/Dark-modem/quantum-protocol => ../quantum-protocol
```

## CI

`.github/workflows/ci.yml` runs `go build ./...`, `go vet ./...`,
`gofmt -l` check and `go test ./...` on every push/PR.
