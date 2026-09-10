"""Codex's spec projection: the agent spec -> a codex ``session/new`` array.

``providers/mirrors/codex.py`` reuses claude's translation and adds two rules of
its own. Both are properties of the ADAPTER rather than of Crew, so both are
measured against a real ``codex-acp`` here and asserted as unit behaviour above:

* an ``sse`` element is dropped, because codex-acp fails the WHOLE ``session/new``
  on one -- so forwarding it costs the session every other server;
* Crew's own control-plane entries carry ``KIROCREW_SESSION_KEY`` on the element,
  because ``codex-rs`` launches a stdio MCP server with ``env_clear()`` plus a
  fixed allowlist and inherits nothing else.

``test_real_codex_acp_accepts_the_crew_stdio_element`` is the anti-drift guard for
both: an adapter fact a projection depends on is measured against the adapter, and
this is where the measurement lives.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from kiro_crew import agent as agent_mod
from kiro_crew.acp import session_mcp
from kiro_crew.acp.client import AcpClient
from kiro_crew.acp_backends import (
    ACP_BACKEND_CLAUDE,
    ACP_BACKEND_CODEX,
    ACP_BACKENDS_MEMBER_DISPATCH,
    ACP_BACKENDS_SESSION_MCP_ARRAY,
)
from kiro_crew.providers.mirrors import Concern, Disposition, mirror_for
from kiro_crew.providers.mirrors.codex import CodexMirror, codex_elements

_CORE = {"command": "/opt/kirocrew", "args": ["mcp-core"]}
_CRON = {"command": "/opt/kirocrew", "args": ["mcp-cron"]}


@pytest.fixture
def agents_dir(tmp_path, monkeypatch):
    """Point the agent-spec resolver at a temp agents directory.

    Same seam as ``test_acp_session_mcp.py``: materialization would rebuild the
    managed default from bundled defaults, and these tests supply the spec.
    """
    d = tmp_path / "agents"
    d.mkdir()
    monkeypatch.setattr(agent_mod, "KIRO_AGENTS_DIR", d)
    monkeypatch.setattr(session_mcp, "ensure_agent_materialized", lambda _a: True)
    monkeypatch.setattr(
        session_mcp,
        "managed_mcp_spec_entry",
        lambda name: {"kirocrew-core": dict(_CORE), "kirocrew-cron": dict(_CRON)}.get(name),
    )
    monkeypatch.setattr(session_mcp, "_mcp_registry_mode", lambda: False)
    return d


def _write_spec(agents_dir: Path, *, servers: dict, tools: list | None) -> None:
    spec: dict = {"name": "kirocrew", "mcpServers": servers}
    if tools is not None:
        spec["tools"] = tools
    (agents_dir / "kirocrew.json").write_text(json.dumps(spec), encoding="utf-8")


def _by_name(elements: list[dict]) -> dict[str, dict]:
    return {e["name"]: e for e in elements}


def _env(element: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in element.get("env") or []}


# ── the transport filter ────────────────────────────────────────────────────


class TestTransportFilter:
    def test_an_sse_element_is_dropped_and_the_rest_survive(self):
        """One bad entry must not be allowed to cost the whole session.

        codex-acp answers ``session/new`` with ``-32600`` for the entire request
        when it meets an ``sse`` element, so dropping it here is what keeps the
        other servers. Withholding the whole array instead would be the same loss
        by another route.
        """
        kept = codex_elements(
            [
                {"name": "remote", "type": "sse", "url": "https://x/sse", "headers": []},
                {"name": "local", "type": "stdio", "command": "/bin/x", "args": [], "env": []},
            ]
        )
        assert [e["name"] for e in kept] == ["local"]

    def test_an_http_element_is_KEPT(self):
        """Measured: codex-acp advertises ``mcpCapabilities.http: true``.

        "stdio only" would have been the easy rule and the wrong one -- dropping a
        remote server the adapter would have mounted removes capability from the
        session with no error to explain it, which is the same class of mistake as
        delivering one it refuses.
        """
        kept = codex_elements(
            [{"name": "r", "type": "http", "url": "https://x/mcp", "headers": []}]
        )
        assert [e["name"] for e in kept] == ["r"]

    def test_a_stdio_element_keeps_its_type_tag_unchanged(self):
        """The tag is measured-good, so nothing is adapted away.

        ACP v1 spells ``McpServer`` as ``serde(tag = "type")`` with the stdio
        variant as the UNTAGGED fallback, so ``type: "stdio"`` matches no named
        variant and falls through to it -- and a real adapter accepts it. Rewriting
        the element for codex would have been a fix for a problem that is not there,
        and would have put two element shapes into one translator.
        """
        el = codex_elements(
            [{"name": "local", "type": "stdio", "command": "/bin/x", "args": [], "env": []}]
        )[0]
        assert el["type"] == "stdio"

    def test_a_whitespace_name_is_folded_the_way_codex_folds_it(self):
        """codex replaces whitespace with ``_``; the wire roster must agree.

        Leaving the fold to codex alone makes Crew's own session report name a
        server that does not exist under that spelling.
        """
        el = codex_elements(
            [{"name": "my server", "type": "stdio", "command": "/bin/x", "args": [], "env": []}]
        )[0]
        assert el["name"] == "my_server"

    def test_the_input_elements_are_not_mutated(self):
        """The caller's list is the translator's output, cached per spawn."""
        src = [{"name": "a b", "type": "stdio", "command": "/bin/x", "args": [], "env": []}]
        codex_elements(src, session_key="sk")
        assert src[0]["name"] == "a b"


# ── identity env carriage ───────────────────────────────────────────────────


class TestIdentityEnvCarriage:
    """Why any of this is here: ``codex-rs``'s stdio launcher runs
    ``Command::env_clear()`` and then re-adds only ``DEFAULT_ENV_VARS``
    (``HOME``/``PATH``/``SHELL``/``USER``/``LANG``/...) plus the entry's own ``env``
    map. So the process inheritance claude's MCP children rely on does not exist
    here, and an entry without ``KIROCREW_SESSION_KEY`` yields a control plane that
    cannot name the session it belongs to -- which is also what the #755 out-of-band
    directive path claims against (``dashboard/directive_queue``).
    """

    def test_the_control_plane_carries_the_session_key(self):
        el = codex_elements(
            [{"name": "kirocrew-core", "type": "stdio", "command": "/x", "args": [], "env": []}],
            session_key="chat-7-123",
        )[0]
        assert _env(el)["KIROCREW_SESSION_KEY"] == "chat-7-123"

    def test_the_control_plane_carries_the_bound_port(self):
        """``members.member_dispatch_session_server``'s reason, same mechanism.

        Without the port the child falls through to the run marker, whose check
        needs ``lsof``, which sees no listener from inside a sandbox's user
        namespace -- so the child dials the default port and every call is a
        connection refused on a gateway bound anywhere else.
        """
        el = codex_elements(
            [{"name": "kirocrew-cron", "type": "stdio", "command": "/x", "args": [], "env": []}],
            session_key="chat-7-123",
        )[0]
        assert _env(el)["KIROCREW_BOUND_PORT"].isdigit()

    def test_the_channel_id_rides_along_when_there_is_one(self):
        """``mcp_cron`` reads ``KIROCREW_CHANNEL_ID`` to place a cron's output."""
        el = codex_elements(
            [{"name": "kirocrew-cron", "type": "stdio", "command": "/x", "args": [], "env": []}],
            session_key="chat-7-123",
            channel_id="C123",
        )[0]
        assert _env(el)["KIROCREW_CHANNEL_ID"] == "C123"

    def test_a_THIRD_PARTY_server_gets_no_crew_identity(self):
        """The security half of the carriage, and the reason it is a filter.

        ``KIROCREW_SESSION_KEY`` is the credential Crew's internal API
        authenticates a directive claim with. A claude MCP child sees it only
        because it inherits the adapter's whole environment -- an inheritance
        nobody chose. Re-creating that deliberately for every spec-declared server
        would be choosing it, and would let any server a spec happens to name
        drive the session it was mounted into.
        """
        el = codex_elements(
            [{"name": "somebody-else", "type": "stdio", "command": "/x", "args": [], "env": []}],
            session_key="chat-7-123",
        )[0]
        assert _env(el) == {}

    def test_a_stale_spec_value_is_replaced_not_duplicated(self):
        """Resolved-live beats spec-declared, and the array holds one pair per name.

        Two pairs with one name is a shape whose winner is the consumer's choice,
        which is not a thing to leave to the consumer for an identity value.
        """
        el = codex_elements(
            [
                {
                    "name": "kirocrew-core",
                    "type": "stdio",
                    "command": "/x",
                    "args": [],
                    "env": [{"name": "KIROCREW_SESSION_KEY", "value": "stale"}],
                }
            ],
            session_key="fresh",
        )[0]
        names = [p["name"] for p in el["env"]]
        assert names.count("KIROCREW_SESSION_KEY") == 1
        assert _env(el)["KIROCREW_SESSION_KEY"] == "fresh"

    def test_no_session_key_means_no_env_work_at_all(self):
        """A keyless client (a worker pool, a probe) must not gain a bogus identity."""
        el = codex_elements(
            [{"name": "kirocrew-core", "type": "stdio", "command": "/x", "args": [], "env": []}]
        )[0]
        assert _env(el) == {}


# ── the mirror's declared rulings ───────────────────────────────────────────


class TestCodexRulings:
    def test_the_mcp_ruling_names_both_codex_specific_rules(self):
        """The folder is the inventory, so the rules have to be readable there.

        A ruling that said only "delivered" would let the next backend copy the
        delivery and drop the two conditions that make it work at all.
        """
        ruling = mirror_for(ACP_BACKEND_CODEX).rulings()[Concern.MCP_SERVERS]
        assert ruling.disposition is Disposition.DELIVERED
        assert "sse" in ruling.reason
        assert "KIROCREW_SESSION_KEY" in ruling.reason

    def test_disabled_tools_is_an_addressed_gap_not_a_decision(self):
        """codex-rs HAS ``disabled_tools``; codex-acp hardcodes it to None.

        That is the definition of ``no-channel`` -- the capability exists and this
        transport cannot carry it -- and conflating it with ``withheld`` is the
        documented cause of the hooks regression.
        """
        ruling = mirror_for(ACP_BACKEND_CODEX).rulings()[Concern.DENIED_TOOLS]
        assert ruling.disposition is Disposition.NO_CHANNEL
        assert "disabled_tools" in ruling.channel

    def test_auto_approve_is_withheld_because_of_the_gate(self):
        ruling = mirror_for(ACP_BACKEND_CODEX).rulings()[Concern.AUTO_APPROVE]
        assert ruling.disposition is Disposition.WITHHELD
        assert "gate" in ruling.reason

    def test_hooks_is_the_second_open_gap_and_it_is_addressed(self):
        ruling = mirror_for(ACP_BACKEND_CODEX).rulings()[Concern.HOOKS]
        assert ruling.disposition is Disposition.NO_CHANNEL
        assert ruling.channel.strip()

    def test_the_wire_face_does_not_fail_closed_on_claudes_precondition(self, tmp_path, agents_dir):
        """Copying claude's gate here would have withheld every codex tool.

        ``permission_surface_owned`` describes claude's ``settings.local.json``, a
        file no codex session has. Codex's routing is ``SESSION_CONFIG`` -- the one
        mechanism in ``ENFORCED_ROUTINGS`` -- so a session that cannot arm
        ``mode=read-only`` is refused rather than run, and there is no file to own.
        """
        _write_spec(agents_dir, servers={}, tools=["@kirocrew-core"])
        params = CodexMirror().session_params("kirocrew", permission_surface_owned=False)
        assert [e["name"] for e in params["mcpServers"]] == ["kirocrew-core"]


# ── the client seam ─────────────────────────────────────────────────────────


class TestClientSeam:
    def test_codex_is_in_both_capability_sets(self):
        """The two sets this projection needed, pinned so neither is dropped alone.

        Without the array set the hook returns ``[]`` however good the mirror is;
        without member dispatch a codex DM thread stays plain chat.
        """
        assert ACP_BACKEND_CODEX in ACP_BACKENDS_SESSION_MCP_ARRAY
        assert ACP_BACKEND_CODEX in ACP_BACKENDS_MEMBER_DISPATCH

    def test_the_codex_hook_returns_the_projection(self, tmp_path, agents_dir):
        """The one assertion the whole mirror exists to make true.

        An empty array on a selectable backend is a session with no Crew tools and
        no error, so this is the seam's contract rather than a detail of it.
        """
        _write_spec(
            agents_dir,
            servers={"foo": {"command": "/bin/foo"}},
            # The control plane is NOT exempt from the allowlist -- kiro-cli drops
            # kirocrew-core from a spec whose `tools` stops naming it, and this
            # backend must not re-grant what kiro-cli would drop -- so a spec that
            # wants both has to name both.
            tools=["@foo", "@kirocrew-core"],
        )
        client = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CODEX)
        names = set(_by_name(client._codex_session_mcp_servers()))
        assert "foo" in names
        assert "kirocrew-core" in names

    def test_the_hook_carries_this_clients_session_key(self, tmp_path, agents_dir):
        """The mirror cannot discover it; the client passes it down."""
        _write_spec(agents_dir, servers={}, tools=["@kirocrew-core"])
        client = AcpClient(
            work_dir=tmp_path,
            agent="kirocrew",
            acp_backend=ACP_BACKEND_CODEX,
            session_key="chat-9-42",
        )
        core = _by_name(client._codex_session_mcp_servers())["kirocrew-core"]
        assert _env(core)["KIROCREW_SESSION_KEY"] == "chat-9-42"

    def test_an_sse_spec_entry_never_reaches_a_codex_session(self, tmp_path, agents_dir):
        """End to end through the client, not just through the filter helper."""
        _write_spec(
            agents_dir,
            servers={
                "remote": {"url": "https://x/sse", "type": "sse"},
                "local": {"command": "/bin/foo"},
            },
            tools=["@remote", "@local"],
        )
        client = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CODEX)
        names = set(_by_name(client._codex_session_mcp_servers()))
        assert "remote" not in names
        assert "local" in names

    def test_a_codex_session_needs_no_claude_settings_file(self, tmp_path, agents_dir):
        """The precondition property, which is the whole reason membership is safe.

        Codex answers YES structurally (its routing is enforced, so a session that
        cannot arm ``mode=read-only`` never prompts); claude answers only as far as
        file ownership goes, and still does.
        """
        codex = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CODEX)
        assert codex._permission_surface_governed is True
        assert codex._claude_settings_authored is False
        claude = AcpClient(work_dir=tmp_path, agent="kirocrew", acp_backend=ACP_BACKEND_CLAUDE)
        assert claude._permission_surface_governed is False
        claude._write_claude_local_settings()
        assert claude._permission_surface_governed is True

    def test_the_spawn_path_warms_the_cache_off_the_loop(self):
        """H13: the shared ``session/new`` site must stay a pure in-memory read.

        Pinned at the source, in this file's neighbour's idiom, because the warm
        sits inside an async spawn path with no unit-level seam. The claude arm
        already does this; a codex arm that skipped it would move the disk read
        onto the loop for every codex session.
        """
        import inspect

        source = inspect.getsource(AcpClient._spawn)
        codex_arm = source.split("elif self._is_codex:", 1)
        assert len(codex_arm) == 2, "the codex spawn arm has moved"
        assert "self._session_mcp_cache = await asyncio.to_thread" in codex_arm[1]


# ── the real adapter ────────────────────────────────────────────────────────

# The driver runs OUT OF PROCESS on purpose: it spawns a real Node adapter, and a
# stalled readline in the test process would surface as a pytest timeout kill
# rather than the clean assertion failures below.
_DRIVER = r"""
import json, os, subprocess, sys, time

root, entry, stub, node = sys.argv[1:5]
report = os.path.join(root, "report.json")
env = dict(os.environ)
env["CODEX_HOME"] = os.path.join(root, "codex_home")
env["NO_BROWSER"] = "1"


def drive(element):
    p = subprocess.Popen(
        [node, entry], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, cwd=os.path.join(root, "work"), env=env,
        text=True, bufsize=1,
    )

    def send(o):
        p.stdin.write(json.dumps(o) + "\n")
        p.stdin.flush()

    send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
          "params": {"protocolVersion": 1, "clientCapabilities": {"fs": {}}}})
    send({"jsonrpc": "2.0", "id": 2, "method": "session/new",
          "params": {"cwd": os.path.join(root, "work"), "mcpServers": [element]}})
    got, deadline = {}, time.time() + 90
    while time.time() < deadline and 2 not in got:
        line = p.stdout.readline()
        if not line:
            break
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg.get("id"), int):
            got[msg["id"]] = msg
    if 2 in got and "result" in got[2]:
        # The child MCP server is launched and queried after session/new answers.
        for _ in range(120):
            if os.path.exists(report):
                break
            time.sleep(0.25)
    p.terminate()
    try:
        p.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
    return got.get(1) or {}, got.get(2) or {}


stdio_el = {
    "name": "kirocrew-core", "type": "stdio", "command": sys.executable,
    "args": [stub],
    "env": [{"name": "STUB_MCP_REPORT", "value": report},
            {"name": "KIROCREW_SESSION_KEY", "value": "probe-session-key"}],
}
init, new = drive(stdio_el)
out = {
    "mcp_capabilities": (init.get("result") or {}).get("agentCapabilities", {}).get(
        "mcpCapabilities"),
    "stdio_error": new.get("error"),
    "stdio_ok": bool(new.get("result")),
    "child": json.load(open(report)) if os.path.exists(report) else None,
}
if os.path.exists(report):
    os.unlink(report)
_, sse = drive({"name": "remote", "type": "sse", "url": "http://127.0.0.1:1/sse",
                "headers": []})
out["sse_error"] = sse.get("error")
out["sse_ok"] = bool(sse.get("result"))
_, bad = drive({"name": "no-command", "args": [], "env": []})
out["malformed_error"] = bad.get("error")
out["malformed_ok"] = bool(bad.get("result"))
print(json.dumps(out))
"""

# A stdio MCP server small enough to read: it records the environment it was
# LAUNCHED with (which is the measurement) and answers the two methods codex sends.
_STUB_MCP = r"""
import json, os, sys

REPORT = os.environ["STUB_MCP_REPORT"]
seen = []


def dump():
    tmp = REPORT + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"methods": seen, "env": dict(os.environ)}, fh)
    os.replace(tmp, REPORT)


def send(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    seen.append(msg.get("method") or "")
    dump()
    if "id" not in msg:
        continue
    if msg.get("method") == "initialize":
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
            "serverInfo": {"name": "stub", "version": "0"}}})
    elif msg.get("method") == "tools/list":
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
            {"name": "stub_echo", "description": "echo",
             "inputSchema": {"type": "object", "properties": {}}}]}})
    else:
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
"""


def _codex_acp_entry() -> Path | None:
    """The installed adapter's entry script, through the SPAWN's own resolver.

    Asking ``_resolve_codex_acp_bin`` rather than ``shutil.which`` is deliberate:
    what this test must exercise is the adapter a real session would spawn, on the
    same ladder (``CODEX_ACP_BIN``, project ``node_modules``, mise, PATH).
    """
    from kiro_crew.acp.client import _resolve_codex_acp_bin

    argv, _search = _resolve_codex_acp_bin()
    if not argv:
        return None
    return Path(argv[-1])


_ENTRY = _codex_acp_entry()


@pytest.mark.skipif(_ENTRY is None, reason="codex-acp not installed")
@pytest.mark.skipif(shutil.which("node") is None, reason="node not on PATH")
def test_real_codex_acp_accepts_the_crew_stdio_element():
    """ANTI-DRIFT GUARD, and the measurement the old docstring lacked.

    Four facts, all of which the projection depends on and none of which is
    documented by the adapter:

    1. The element Crew already emits -- ``{"name", "command", "args", "env",
       "type": "stdio"}``, the claude shape unchanged -- is ACCEPTED. ACP v1 spells
       ``McpServer`` as ``serde(tag = "type")`` with stdio as the untagged
       fallback, so nothing guaranteed a ``"stdio"`` tag would fall through to it.
    2. The server is really LAUNCHED and its tools listed: the child answers
       ``initialize`` and then ``tools/list``.
    3. The child inherits ALMOST NOTHING. ``codex-rs`` runs ``env_clear()`` and
       re-adds an allowlist, so ``KIROCREW_SESSION_KEY`` arrives only because the
       element carried it -- which is why ``codex_elements`` carries it.
    4. ``sse`` fails the WHOLE ``session/new``, while a MALFORMED stdio element
       does not. Both halves are load-bearing: the first is why ``codex_elements``
       filters, and the second is why it filters rather than withholding the whole
       array -- a wide reading (``-32602`` for anything unadvertised) argues for
       projecting nothing, and the adapter answers ``-32600``, only for ``sse``.

    A fabricated API key in a throwaway ``CODEX_HOME`` is what gets past the
    adapter's auth check, which fires BEFORE it looks at ``mcpServers`` (verified:
    without it every shape above answers ``-32000 Authentication required``
    identically, so the run would prove nothing). ``session/new`` performs no
    model call, so nothing is sent anywhere and the key never leaves the temp
    directory.
    """
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as w:
        root = Path(w)
        (root / "work").mkdir()
        (root / "codex_home").mkdir()
        (root / "codex_home" / "auth.json").write_text(
            json.dumps({"OPENAI_API_KEY": "sk-not-a-real-key-" + "0" * 24}), encoding="utf-8"
        )
        stub = root / "stub_mcp.py"
        stub.write_text(_STUB_MCP, encoding="utf-8")
        driver = root / "drive.py"
        driver.write_text(_DRIVER, encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(driver),
                str(root),
                str(_ENTRY),
                str(stub),
                shutil.which("node") or "node",
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
            check=False,
        )
        context = (
            f"driver exit: {result.returncode}\n"
            f"stdout: {result.stdout[-3000:]}\nstderr: {result.stderr[-3000:]}"
        )
        try:
            measured = json.loads(result.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            pytest.fail("the codex-acp driver produced no measurement\n" + context)

        if (measured.get("stdio_error") or {}).get("code") == -32000:
            pytest.skip("codex-acp refused the fabricated credential; nothing to measure")

        # 1 + 2: the shape is accepted and the server really runs.
        assert measured["stdio_ok"], (
            "codex-acp rejected the mcpServers element Crew emits, so the codex "
            "projection cannot be delivered in this shape at all\n" + context
        )
        child = measured.get("child")
        assert child, "the stdio MCP server was never launched\n" + context
        assert "tools/list" in child["methods"], (
            "codex-acp launched the server but never listed its tools, so the "
            "session would hold a mounted server with no usable tool\n" + context
        )

        # 3: the env allowlist, which is the whole reason for the carriage rule.
        assert child["env"].get("KIROCREW_SESSION_KEY") == "probe-session-key"
        assert "PATH" in child["env"]
        assert "STUB_MCP_REPORT" in child["env"]

        # 4: what actually costs a session, and what does not.
        assert not measured["sse_ok"], (
            "codex-acp now ACCEPTS an sse element. The drop in codex_elements is "
            "no longer required and should be reconsidered rather than kept as "
            "folklore.\n" + context
        )
        assert measured["sse_error"], "an sse element failed with no error\n" + context
        assert measured["malformed_ok"], (
            "a malformed stdio element now fails the whole session/new. The "
            "translator degrades on a bad spec entry rather than raising, so this "
            "would turn one hand-edited spec line into a dead session.\n" + context
        )
        assert measured["mcp_capabilities"]["sse"] is False
        assert measured["mcp_capabilities"]["http"] is True


def test_the_real_adapter_guard_is_reachable_at_all():
    """A skip-only guard is a guard nobody notices has stopped running.

    This does not assert the adapter is installed -- CI has no codex-acp. It
    asserts the RESOLVER the guard skips on is the spawn's own, so a rename there
    turns the guard permanently green without anyone seeing it.
    """
    from kiro_crew.acp.client import _resolve_codex_acp_bin

    argv, search = _resolve_codex_acp_bin()
    assert argv is None or isinstance(argv, list)
    assert isinstance(search, str)
    assert os.environ.get("CODEX_ACP_BIN") is None or _ENTRY is not None
