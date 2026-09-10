# OpenCode frame corpus

Three files, and the split between them is the provenance. Read `../README.md`
first for what a fixture is and what the corpus does and does not prove.

| File | Provenance | Frame classes it carries |
|---|---|---|
| `session-live.jsonl` | live | initialize response with `agentInfo.version`, `session/new` response with a `sessionId`, `agent_message_chunk`, `usage_update`, and the `session/prompt` result carrying `stopReason` |
| `tool-call-live.jsonl` | live | `tool_call`, and two `tool_call_update` frames (`in_progress`, then terminal) |
| `permission-request.jsonl` | synthesized | `session/request_permission`, plus the completed `tool_call_update` an approval would produce |

Captured off `opencode acp` 1.18.30 driving a local Ollama model, agent-to-client
lines verbatim, with the recording user's home directory replaced by `~`.
`tool-call-live.jsonl` is a **slice**: the 430 `agent_message_chunk` frames the
model emitted around the tool call are omitted for length, and the fixture's own
`_meta.note` says so.

## Why one class is synthesized

`session/request_permission` was never captured, and the reason is a model-quality
limit rather than a gap in OpenCode or in Kiro Crew.

The recording host has no GPU. The local models it can serve in reasonable time
are small, and the one that did emit a tool call — `llama3.2:3b` — shaped the
`bash` tool's arguments wrongly: `timeout` as a string on one attempt, `command`
as an array on the next. OpenCode validated those arguments against its own tool
schema and rejected the call. **Nothing executed, and the rejection happens before
any permission check**, so no permission frame exists anywhere on that path — not
for Crew to capture, and not for OpenCode to send.

Two things this does *not* mean:

- It is not evidence that OpenCode fails to ask. A wire proxy in front of the
  model recorded OpenCode advertising all ten of its tools, `bash` among them, on
  every `/v1/chat/completions` request, so the harness side behaved correctly
  throughout.
- It is not evidence that Kiro Crew's gate is unproven. What routes a tool call to
  that gate is the harness's own `permission` setting, and that precondition is
  established by observation rather than by this corpus: the session seeds the
  setting into the child's environment and reads the harness's own resolved
  configuration back before the first prompt, refusing the session when the
  required value is not in force (`agent_sdk/tool_gate.py`,
  `AcpClient._verify_opencode_routing`).

Replacing `permission-request.jsonl` with a capture is a strict improvement and
needs no test change: record it on a host that can drive a tool-calling model,
set `recorded` to `live`, and update this table and `../README.md`.
