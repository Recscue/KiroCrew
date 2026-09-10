"""Codex's agent-config mirror (``codex-acp``).

The wire face only. ``codex-acp`` loads its own ``~/.codex/config.toml`` and Kiro
Crew never writes there (create-or-decline: that file is the operator's), so the
``session/new`` / ``session/load`` ``mcpServers`` array is the ONLY channel Crew
has onto a codex session. An empty array is therefore not a neutral default but
the whole defect ``providers/mirrors/README.md`` exists for: codex is in
``BASELINE_SELECTABLE_BACKENDS``, so a public build would serve a harness with no
``spawn_run``, no ``cron_add`` and no ``send_message`` — working in every visible
respect, with every Crew tool silently absent.

The translation is claude's (:func:`kiro_crew.acp.session_mcp.session_mcp_servers`):
the agent spec is the single source of truth, the ``tools`` allowlist decides
which servers enter the array, and the registry ceiling and control-plane
re-derivation apply unchanged. What is codex-specific is what this module adds on
top, and both rules were MEASURED against a real ``codex-acp`` rather than
inferred (``test/test_codex_session_mcp.py::test_real_codex_acp_accepts_the_crew_stdio_element``):

1. **An ``sse`` element fails the WHOLE request.** ``codex-acp`` 1.11.0 answers
   ``session/new`` with ``-32600 Invalid request`` / *"Codex doesn't support MCP
   SSE transport protocol"*, so one such entry costs the session every other
   server too. Its ``initialize`` says so up front — the measured
   ``mcpCapabilities`` is ``{"acp": false, "http": true, "sse": false}`` — and the
   filter is keyed on that, not on a hardcoded transport list.
2. **The child MCP process inherits almost nothing.** ``codex-rs``'s stdio
   launcher runs ``Command::env_clear()`` and then re-adds an ALLOWLIST
   (``rmcp-client/src/stdio_server_launcher.rs``, ``utils.rs::DEFAULT_ENV_VARS``:
   ``HOME``, ``LOGNAME``, ``PATH``, ``SHELL``, ``USER``, ``LANG``, ``LC_ALL``,
   ``TERM``, ``TMPDIR``, ``TZ``, plus the custom-CA keys) on top of the entry's
   own ``env`` map. So ``KIROCREW_SESSION_KEY`` does NOT reach the child by
   process inheritance the way it does under claude-agent-acp: it has to ride the
   element, or Crew's own control plane comes up unable to name the session it
   belongs to.

The SCOPE of that first rule is as load-bearing as the rule, because the wide
reading of it argues for projecting nothing at all. A malformed stdio element —
one missing ``command``, or an array member that is not an object — does NOT fail
``session/new``: the request succeeds and the bad element is dropped. ``sse`` is
the only fatal shape, and it fails with ``-32600`` rather than the ``-32602`` an
unadvertised transport invites you to assume.
"""

from __future__ import annotations

import logging
from collections.abc import Collection
from typing import Any, Mapping

from kiro_crew.acp.session_mcp import CONTROL_PLANE_SERVERS, session_mcp_servers
from kiro_crew.acp_backends import ACP_BACKEND_CODEX
from kiro_crew.providers.mirrors.base import (
    AgentConfigMirror,
    Concern,
    Disposition,
    Ruling,
)

logger = logging.getLogger(__name__)

_D = Disposition

#: Transports ``codex-acp`` refuses. Named as the transports it does NOT
#: advertise (``mcpCapabilities.sse`` is ``false``, ``http`` is ``true``, and
#: stdio is the ACP baseline every agent must support) rather than as "everything
#: but stdio": ``http`` IS accepted, and dropping a remote server the adapter
#: would have mounted removes capability from the session with no error to explain
#: it — the same direction of mistake as delivering one it refuses.
CODEX_UNSUPPORTED_TRANSPORTS = frozenset({"sse"})


def _identity_env(session_key: str, channel_id: str) -> dict[str, str]:
    """The env Crew's OWN managed servers need, resolved for this session.

    Every value here is something a claude MCP child gets for free by inheriting
    the adapter's process environment and a codex one does not (``env_clear`` +
    allowlist, see the module docstring). Resolved live rather than read from the
    spec, exactly as ``managed_mcp_spec_entry`` resolves the command.

    ``KIROCREW_BOUND_PORT`` for the same reason ``members.member_dispatch_session_server``
    carries it: without the port the child falls through to the run marker, whose
    check needs ``find_listening_pids`` (``lsof``), which sees no listener from
    inside a sandbox's user namespace — so the child dials the default port and
    every call is a connection refused on a gateway bound anywhere else.
    """
    # circular import: agent's module graph is heavy (it imports config), and
    # port_resolution reaches config.loader, whose provider-backend path imports
    # members. Both resolved at call time, the same way session_mcp.py and
    # members.py resolve them.
    from kiro_crew.agent import _managed_mcp_env
    from kiro_crew.port_resolution import resolve_serving_port

    env: dict[str, str] = {}
    try:
        env.update(_managed_mcp_env())
    except Exception:  # pragma: no cover - defensive; the helper is fail-soft
        logger.warning("codex session MCP: could not resolve the managed home", exc_info=True)
    if session_key:
        env["KIROCREW_SESSION_KEY"] = session_key
    if channel_id:
        env["KIROCREW_CHANNEL_ID"] = channel_id
    try:
        env["KIROCREW_BOUND_PORT"] = str(resolve_serving_port())
    except Exception:  # pragma: no cover - defensive
        logger.warning("codex session MCP: could not resolve the serving port", exc_info=True)
    return env


def _with_env(element: dict[str, Any], extra: Mapping[str, str]) -> dict[str, Any]:
    """*element* with *extra* merged into its ACP array-of-pairs ``env``.

    Later wins, so a value resolved here replaces a stale one the spec carried —
    the same precedence ``managed_mcp_spec_entry`` applies to the command.
    """
    pairs: list[dict[str, str]] = [
        p for p in element.get("env") or [] if isinstance(p, dict) and p.get("name") not in extra
    ]
    pairs.extend({"name": k, "value": v} for k, v in extra.items())
    out = dict(element)
    out["env"] = pairs
    return out


def codex_elements(
    elements: list[dict[str, Any]],
    *,
    session_key: str = "",
    channel_id: str = "",
) -> list[dict[str, Any]]:
    """Narrow a translated ``mcpServers`` array to what codex-acp accepts.

    Two rules, both measured (module docstring): drop a transport the adapter does
    not advertise, and carry Crew's own identity env on Crew's own servers.

    The identity env goes on the CONTROL PLANE ONLY, never on a third-party
    server: ``KIROCREW_SESSION_KEY`` is the credential Crew's internal API
    authenticates a directive claim with, and handing it to whatever server a spec
    happens to declare would let that server drive the session it was mounted
    into. A claude child sees the key only because it inherits the adapter's
    environment; that is an inheritance nobody chose, and re-creating it
    deliberately here would be choosing it.

    Names are folded the way codex folds them (whitespace to ``_``) so the roster
    Crew puts on the wire is the roster codex registers. ``kirocrew-core`` and
    ``kirocrew-cron`` are unaffected; a user-declared ``my server`` is not, and
    leaving the fold to codex alone would make the session report name a server
    that does not exist under that spelling.
    """
    identity = _identity_env(session_key, channel_id) if session_key or channel_id else {}
    out: list[dict[str, Any]] = []
    for element in elements:
        if not isinstance(element, dict):
            continue
        transport = str(element.get("type") or "")
        if transport in CODEX_UNSUPPORTED_TRANSPORTS:
            logger.warning(
                "codex session MCP: dropping server %r -- codex-acp does not advertise the %r "
                "transport and answers session/new with -32600 for the WHOLE request, so "
                "forwarding it would cost this session every other server too",
                element.get("name"),
                transport,
            )
            continue
        name = str(element.get("name") or "")
        folded = "_".join(name.split()) if name.split() != [name] else name
        element = dict(element)
        element["name"] = folded
        if identity and folded in CONTROL_PLANE_SERVERS:
            element = _with_env(element, identity)
        out.append(element)
    return out


class CodexMirror(AgentConfigMirror):
    """Projects the agent spec onto codex-acp."""

    backend = ACP_BACKEND_CODEX

    def rulings(self) -> Mapping[Concern, Ruling]:
        return {
            Concern.MCP_SERVERS: Ruling(
                _D.DELIVERED,
                "the session/new + session/load mcpServers array, translated by "
                "acp.session_mcp.session_mcp_servers and then narrowed by this "
                "module's codex_elements: an `sse` entry is dropped because "
                "codex-acp answers -32600 for the WHOLE request rather than "
                "skipping that one server, and Crew's own control-plane entries "
                "carry KIROCREW_SESSION_KEY explicitly because codex-rs launches "
                "a stdio server with env_clear() plus an allowlist, so nothing is "
                "inherited. Unlike claude this array is NOT conditional on Crew "
                "owning a permission file: codex's routing is `Routing.SESSION_CONFIG`, "
                "the one mechanism in tool_gate.ENFORCED_ROUTINGS, so a session "
                "that cannot arm mode=read-only is refused before its first prompt "
                "rather than running unasked",
            ),
            Concern.TOOL_ALLOWLIST: Ruling(
                _D.TRANSLATED,
                "`tools` is not sent; it is applied during translation as the "
                "allowlist deciding which servers enter the array, so a server the "
                "spec declares but never references is not mounted here either -- "
                "kiro-cli parity. It carries the same residual claude has: an "
                "`@server/tool` grant narrows to one tool on kiro-cli but mounts "
                "the whole server here, because the tool set is not knowable "
                "without connecting",
            ),
            Concern.DENIED_TOOLS: Ruling(
                _D.NO_CHANNEL,
                "codex-rs HAS per-server tool narrowing -- McpServerConfig carries "
                "`disabled_tools` -- but codex-acp's build_session_config hardcodes "
                "it to None for every client-provided server, so the ACP element "
                "has no slot the restriction can ride in. The tool therefore stays "
                "reachable on this backend where kiro-cli would not offer it at "
                "all. What keeps that from being ungated is Crew's own PreToolUse "
                "gate, which is verified before it is trusted here (ENFORCED_ROUTINGS) "
                "-- a wider surface, not an unguarded one",
                channel="McpServerConfig.disabled_tools, which codex-rs already "
                "honours and codex-acp would have to carry from the ACP element; "
                "failing that, a Crew-owned CODEX_HOME overlay, which does not "
                "exist today because Crew never writes the operator's config.toml",
            ),
            Concern.AUTO_APPROVE: Ruling(
                _D.WITHHELD,
                "codex's nearest equivalents -- McpServerConfig's "
                "`default_tools_approval_mode` and a trusted entry in the "
                "operator's own config.toml -- both pre-approve the call INSIDE "
                "codex, which then never sends session/request_permission. That "
                "would skip Crew's permission gate, its governance ceiling and its "
                "SEL audit, and this is the harness whose asking is the reason it "
                "is offered at all. Every MCP call must reach the host gate",
            ),
            Concern.MODEL: Ruling(
                _D.DELIVERED,
                "not through this mirror: codex is in "
                "ACP_BACKENDS_MODEL_VIA_CONFIG_OPTION, so the resolved model is "
                "pushed with session/set_config_option('model', ...) after "
                "session/new. Named here rather than left out so a reader does not "
                "read this mirror's silence as the model being dropped",
            ),
            Concern.MODEL_ALLOWLIST: Ruling(
                _D.WITHHELD,
                "the direction is reversed on this backend: codex-acp advertises "
                "its own model list as a session/new configOptions select, and that "
                "list is the ONLY source of ids set_config_option accepts -- the "
                "static registry has no codex provider, and kiro's catalog names "
                "models codex refuses with a bare -32602. So Crew CAPTURES the "
                "advertised set into the `codex` registry namespace "
                "(ACP_BACKENDS_ADVERTISED_MODEL_SELECTION) instead of sending one. "
                "Projecting the spec's availableModels here would offer ids that "
                "kill the session",
            ),
            Concern.PERMISSION_MODE: Ruling(
                _D.WITHHELD,
                "codex-acp has a `mode` selector and Crew writes it -- but it "
                "writes the FIXED value tool_gate demands (mode=read-only), not the "
                "mode the spec asked for. Honouring a spec-requested mode would let "
                "an agent file widen a codex session past the one boundary that "
                "makes this harness offerable, and the assertion is per session "
                "rather than seeded to a file precisely so nothing can inherit a "
                "looser one. A deliberate override, not a dropped setting",
            ),
            Concern.PROMPT: Ruling(
                _D.WITHHELD,
                "not a mirror concern on any backend: the prompt reaches every "
                "harness as ordinary prompt text in the [AGENT SYSTEM PROMPT] "
                "context block, which is backend-agnostic and already works",
            ),
            Concern.RESOURCES: Ruling(
                _D.WITHHELD,
                "same as PROMPT -- steering files are injected as context text, not "
                "projected into a backend's config",
            ),
            Concern.HOOKS: Ruling(
                _D.NO_CHANNEL,
                "codex runs hooks natively (codex-rs app-server-protocol ships "
                "HookEventName, ConfiguredHookMatcherGroup and hooks/list), and "
                "codex-acp's build_session_config carries no hooks field -- so a "
                "user's per-agent hooks block reaches kiro-cli and no other "
                "backend, exactly the gap claude records. Crew's OWN hooks "
                "(hooks.py, fired on ACP tool events) are unaffected and work on "
                "this backend already; this gap is only the spec block",
                channel="a hooks field on the codex-acp session/new element set, or "
                "a Crew-owned CODEX_HOME overlay under create-or-decline -- Crew "
                "writes no codex file today, which is why this needs a decision "
                "rather than a writer",
            ),
        }

    def session_params(
        self,
        agent: str | None,
        *,
        stub_server_names: Collection[str] = (),
        work_dir: object = None,
        session_key: str = "",
        channel_id: str = "",
        **kwargs: object,
    ) -> dict[str, object]:
        """The wire face: the ``mcpServers`` array for this codex session.

        ``permission_surface_owned`` is accepted and IGNORED (it arrives in
        ``kwargs``), which is the documented behaviour for a mirror outside
        claude's class. The flag exists because claude's permission surface is a
        file Crew may not own, so a pre-approved tool there never sends
        ``session/request_permission`` and Crew's gate never fires. Codex has no
        such file in play: its routing is asserted per session over
        ``session/set_config_option`` and is the one mechanism in
        ``tool_gate.ENFORCED_ROUTINGS``, so a session that cannot arm
        ``mode=read-only`` is REFUSED rather than run. Failing closed on the flag
        here would withhold every Crew tool from every codex session on the
        strength of a condition that does not describe this backend.

        ``session_key`` and ``channel_id`` are the caller's, because a mirror
        cannot discover them, and they are not decoration: a codex stdio child
        starts from ``env_clear()`` plus an allowlist, so without them Crew's own
        control plane comes up with no session to act on, and the out-of-band
        session-directive path (``dashboard/directive_queue``) -- the one that
        carries ``monitor_start`` and friends on a backend emitting no
        ``_meta.kiro`` -- has nothing to claim against.

        ``work_dir`` is the session's project checkout and is required for
        CORRECTNESS, not convenience: kiro-cli resolves ``--agent`` against
        ``<work_dir>/.kiro/agents`` as well as the user level, so omitting it makes
        a project-only agent read as "no spec" and drops the ``tools`` allowlist
        that spec declared.

        Blocking -- it reads the agent spec. The caller warms this on the codex
        spawn path and serves the shared ``session/new`` call site from that cache
        (H13).
        """
        return {
            "mcpServers": codex_elements(
                session_mcp_servers(
                    agent,
                    stub_server_names=stub_server_names,
                    work_dir=work_dir,  # type: ignore[arg-type]
                ),
                session_key=session_key,
                channel_id=channel_id,
            )
        }
