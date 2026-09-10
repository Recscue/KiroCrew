"""Tests for operator-registered OAuth clients (``connections/oauth_clients``).

Pure-function coverage: the three-source precedence for the client id and the
secret, the two validators, the dashboard view (which must never carry a secret
value), the surgical wire-shape writer, and the slug+URL binding that keeps an
operator's client off a stranger's endpoint. No config file, no vault, no HTTP:
every input is passed in explicitly.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from kiro_crew.connections import get_provider
from kiro_crew.connections.oauth_clients import (
    CONFIG_CLIENTS_KEY,
    CONFIG_ROOT_KEY,
    ResolvedOAuthClient,
    apply_preregistered_oauth_client,
    client_id_env_name,
    client_secret_env_name,
    client_secret_name,
    managed_client_secret_names,
    oauth_client_view,
    provider_for_server,
    resolve_oauth_client,
    validate_client_id,
    validate_client_secret,
)
from kiro_crew.mcp_utils import KIRO_OAUTH_KEY

GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"
GITHUB_REDIRECT_URI = "http://127.0.0.1:48101/callback"
ENV_ID = "KIROCREW_CONNECTIONS_GITHUB_CLIENT_ID"
ENV_SECRET = "KIROCREW_CONNECTIONS_GITHUB_CLIENT_SECRET"
VAULT_NAME = "CONNECTIONS_GITHUB_CLIENT_SECRET"


def _provider(slug: str = "github", *, confidential: bool = True, client_id: str | None = None):
    """A pre-registered provider copied from the shipped registry, then adjusted."""
    item = deepcopy(get_provider(slug))
    assert item is not None
    item["auth"] = dict(item["auth"])
    item["auth"]["confidential"] = confidential
    if client_id is None:
        item.pop("client_id", None)
    else:
        item["client_id"] = client_id
    return item


def _config(slug: str, client_id: object) -> dict:
    return {CONFIG_ROOT_KEY: {CONFIG_CLIENTS_KEY: {slug: {"client_id": client_id}}}}


class _Held:
    """The shape ``SecretVault.get`` hands back: a value behind ``reveal()``."""

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value


class _Vault:
    def __init__(self, entries: dict[str, object] | None = None) -> None:
        self.entries = entries or {}
        self.asked: list[str] = []

    def get(self, name: str):
        self.asked.append(name)
        return self.entries.get(name)


class _BrokenVault:
    def get(self, name: str):
        raise OSError("vault unreadable")


# ── naming ──


@pytest.mark.parametrize(
    ("slug", "token"),
    [("github", "GITHUB"), ("google-drive", "GOOGLE_DRIVE"), ("microsoft-365", "MICROSOFT_365")],
)
def test_env_and_vault_names_upper_case_the_slug_and_swap_hyphens(slug, token):
    assert client_id_env_name(slug) == f"KIROCREW_CONNECTIONS_{token}_CLIENT_ID"
    assert client_secret_env_name(slug) == f"KIROCREW_CONNECTIONS_{token}_CLIENT_SECRET"
    assert client_secret_name(slug) == f"CONNECTIONS_{token}_CLIENT_SECRET"


def test_managed_secret_names_cover_every_shipped_preregistered_provider():
    names = managed_client_secret_names()
    assert names["CONNECTIONS_GITHUB_CLIENT_SECRET"] == "github"
    assert names["CONNECTIONS_ASANA_CLIENT_SECRET"] == "asana"
    assert set(names.values()) == {"github", "asana"}


# ── validators ──


def test_client_id_is_trimmed_and_returned():
    assert validate_client_id("  Iv1.abc123  ") == "Iv1.abc123"
    assert validate_client_id("Iv1.abc123") == "Iv1.abc123"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "has space",
        "tab\tinside",
        "ctrl\x01char",
        "\x7fdel",
        "caf\u00e9",
        "a" * 513,
        None,
        42,
        ["Iv1.abc"],
        {"client_id": "x"},
    ],
)
def test_unusable_client_ids_are_refused(bad):
    assert validate_client_id(bad) is None


def test_client_id_length_bound_is_inclusive():
    assert validate_client_id("a" * 512) == "a" * 512
    assert validate_client_id("a" * 513) is None


def test_client_id_accepts_the_full_printable_ascii_range():
    assert validate_client_id("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~") is not None


def test_client_secret_is_returned_verbatim_not_trimmed():
    """A vendor secret may carry surrounding whitespace; trimming would corrupt it."""
    assert validate_client_secret("  s3cr3t  ") == "  s3cr3t  "
    assert validate_client_secret("a\tb") == "a\tb"
    assert validate_client_secret("caf\u00e9") == "caf\u00e9"


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "\t\n", "line\nbreak", "carriage\rreturn", "nul\x00byte", "x" * 4097, None, 7, []],
)
def test_unusable_client_secrets_are_refused(bad):
    assert validate_client_secret(bad) is None


def test_client_secret_length_bound_is_inclusive():
    assert validate_client_secret("x" * 4096) == "x" * 4096


# ── resolve_oauth_client: client id precedence ──


def test_env_client_id_outranks_config_and_registry():
    provider = _provider(confidential=False, client_id="from-registry")
    resolved = resolve_oauth_client(
        provider,
        config=_config("github", "from-config"),
        vault=_Vault(),
        environ={ENV_ID: "from-env"},
    )
    assert resolved is not None
    assert (resolved.client_id, resolved.client_id_source) == ("from-env", "env")


def test_config_client_id_outranks_registry_when_env_is_unset():
    provider = _provider(confidential=False, client_id="from-registry")
    resolved = resolve_oauth_client(
        provider, config=_config("github", "from-config"), vault=_Vault(), environ={}
    )
    assert resolved is not None
    assert (resolved.client_id, resolved.client_id_source) == ("from-config", "config")


def test_registry_client_id_is_the_last_resort():
    provider = _provider(confidential=False, client_id="from-registry")
    resolved = resolve_oauth_client(provider, config={}, vault=_Vault(), environ={})
    assert resolved is not None
    assert (resolved.client_id, resolved.client_id_source) == ("from-registry", "registry")


def test_an_unusable_env_client_id_falls_through_to_config():
    provider = _provider(confidential=False)
    resolved = resolve_oauth_client(
        provider,
        config=_config("github", "from-config"),
        vault=_Vault(),
        environ={ENV_ID: "has a space"},
    )
    assert resolved is not None
    assert resolved.client_id_source == "config"


def test_env_client_id_is_trimmed_on_the_way_in():
    provider = _provider(confidential=False)
    resolved = resolve_oauth_client(
        provider, config=None, vault=_Vault(), environ={ENV_ID: "  padded  "}
    )
    assert resolved is not None
    assert resolved.client_id == "padded"


@pytest.mark.parametrize(
    "config",
    [
        None,
        {},
        {CONFIG_ROOT_KEY: "not-a-mapping"},
        {CONFIG_ROOT_KEY: {CONFIG_CLIENTS_KEY: []}},
        {CONFIG_ROOT_KEY: {CONFIG_CLIENTS_KEY: {"github": "not-a-record"}}},
        {CONFIG_ROOT_KEY: {CONFIG_CLIENTS_KEY: {"github": {"client_id": "   "}}}},
        {CONFIG_ROOT_KEY: {CONFIG_CLIENTS_KEY: {"asana": {"client_id": "other-slug"}}}},
    ],
)
def test_no_client_id_anywhere_resolves_to_none(config):
    provider = _provider(confidential=False)
    assert resolve_oauth_client(provider, config=config, vault=_Vault(), environ={}) is None


def test_a_dcr_provider_never_resolves_even_with_values_present():
    notion = deepcopy(get_provider("notion"))
    assert notion is not None and "auth" not in notion
    resolved = resolve_oauth_client(
        notion,
        config=_config("notion", "cfg"),
        vault=_Vault({"CONNECTIONS_NOTION_CLIENT_SECRET": _Held("s")}),
        environ={"KIROCREW_CONNECTIONS_NOTION_CLIENT_ID": "env"},
    )
    assert resolved is None


# ── resolve_oauth_client: secret precedence ──


def test_env_secret_outranks_the_vault():
    vault = _Vault({VAULT_NAME: _Held("from-vault")})
    resolved = resolve_oauth_client(
        _provider(),
        config=_config("github", "cid"),
        vault=vault,
        environ={ENV_SECRET: "from-env"},
    )
    assert resolved is not None
    assert (resolved.client_secret, resolved.client_secret_source) == ("from-env", "env")


def test_vault_secret_is_used_when_env_is_unset():
    vault = _Vault({VAULT_NAME: _Held("from-vault")})
    resolved = resolve_oauth_client(
        _provider(), config=_config("github", "cid"), vault=vault, environ={}
    )
    assert resolved is not None
    assert (resolved.client_secret, resolved.client_secret_source) == ("from-vault", "vault")
    assert vault.asked == [VAULT_NAME]


def test_vault_secret_is_read_verbatim():
    vault = _Vault({VAULT_NAME: _Held("  spaced  ")})
    resolved = resolve_oauth_client(
        _provider(), config=_config("github", "cid"), vault=vault, environ={}
    )
    assert resolved is not None
    assert resolved.client_secret == "  spaced  "


def test_a_vault_returning_a_bare_string_is_accepted():
    """Duck-typed: a dict-backed stub without ``reveal()`` still works."""
    vault = _Vault({VAULT_NAME: "plain"})
    resolved = resolve_oauth_client(
        _provider(), config=_config("github", "cid"), vault=vault, environ={}
    )
    assert resolved is not None
    assert resolved.client_secret == "plain"


def test_confidential_client_without_a_secret_resolves_to_none():
    resolved = resolve_oauth_client(
        _provider(confidential=True), config=_config("github", "cid"), vault=_Vault(), environ={}
    )
    assert resolved is None


def test_confidential_client_with_an_unusable_env_secret_and_empty_vault_is_none():
    resolved = resolve_oauth_client(
        _provider(confidential=True),
        config=_config("github", "cid"),
        vault=_Vault(),
        environ={ENV_SECRET: "multi\nline"},
    )
    assert resolved is None


def test_a_raising_vault_reads_as_no_secret():
    resolved = resolve_oauth_client(
        _provider(confidential=True),
        config=_config("github", "cid"),
        vault=_BrokenVault(),
        environ={},
    )
    assert resolved is None


def test_a_none_vault_reads_as_no_secret():
    resolved = resolve_oauth_client(
        _provider(confidential=True), config=_config("github", "cid"), vault=None, environ={}
    )
    assert resolved is None


def test_public_client_without_a_secret_resolves_with_secret_none():
    resolved = resolve_oauth_client(
        _provider(confidential=False), config=_config("github", "cid"), vault=_Vault(), environ={}
    )
    assert resolved == ResolvedOAuthClient(
        slug="github",
        client_id="cid",
        client_id_source="config",
        client_secret=None,
        client_secret_source=None,
        redirect_uri=GITHUB_REDIRECT_URI,
    )


def test_public_client_still_carries_a_secret_when_one_is_stored():
    vault = _Vault({VAULT_NAME: _Held("optional")})
    resolved = resolve_oauth_client(
        _provider(confidential=False), config=_config("github", "cid"), vault=vault, environ={}
    )
    assert resolved is not None
    assert resolved.client_secret == "optional"


def test_resolved_redirect_uri_is_derived_from_the_registry():
    resolved = resolve_oauth_client(
        _provider(confidential=False), config=_config("github", "cid"), vault=_Vault(), environ={}
    )
    assert resolved is not None
    assert resolved.redirect_uri == GITHUB_REDIRECT_URI


def test_hyphenated_slug_reads_its_own_env_and_vault_names():
    provider = _provider(confidential=True)
    provider["slug"] = "google-drive"
    vault = _Vault({"CONNECTIONS_GOOGLE_DRIVE_CLIENT_SECRET": _Held("gd-secret")})
    resolved = resolve_oauth_client(
        provider,
        config=None,
        vault=vault,
        environ={"KIROCREW_CONNECTIONS_GOOGLE_DRIVE_CLIENT_ID": "gd-id"},
    )
    assert resolved is not None
    assert resolved.slug == "google-drive"
    assert (resolved.client_id, resolved.client_id_source) == ("gd-id", "env")
    assert (resolved.client_secret, resolved.client_secret_source) == ("gd-secret", "vault")
    assert vault.asked == ["CONNECTIONS_GOOGLE_DRIVE_CLIENT_SECRET"]


# ── oauth_client_view ──


def _flat_values(view: dict) -> list[str]:
    return [str(v) for v in view.values()]


def test_view_never_carries_a_secret_value():
    view = oauth_client_view(
        _provider(),
        config=_config("github", "cid"),
        vault_names={VAULT_NAME},
        environ={ENV_SECRET: "ENV-SECRET-VALUE"},
    )
    assert "ENV-SECRET-VALUE" not in " ".join(_flat_values(view))
    assert set(view) == {
        "slug",
        "confidential",
        "redirect_uri",
        "registration_guide",
        "client_id",
        "client_id_source",
        "client_secret_set",
        "client_secret_source",
        "configured",
    }
    assert view["client_secret_set"] is True
    assert view["client_secret_source"] == "env"


def test_view_reports_static_provider_facts():
    view = oauth_client_view(_provider(), config=None, vault_names=set(), environ={})
    assert view["slug"] == "github"
    assert view["confidential"] is True
    assert view["redirect_uri"] == GITHUB_REDIRECT_URI
    assert view["registration_guide"] == "oauth-app-registration/github.md"


def test_view_with_nothing_stored_is_unconfigured():
    view = oauth_client_view(_provider(), config=None, vault_names=set(), environ={})
    assert view["client_id"] is None
    assert view["client_id_source"] is None
    assert view["client_secret_set"] is False
    assert view["client_secret_source"] is None
    assert view["configured"] is False


def test_view_client_id_precedence_matches_resolve():
    provider = _provider(client_id="from-registry")
    env_view = oauth_client_view(
        provider,
        config=_config("github", "from-config"),
        vault_names=set(),
        environ={ENV_ID: "from-env"},
    )
    cfg_view = oauth_client_view(
        provider, config=_config("github", "from-config"), vault_names=set(), environ={}
    )
    reg_view = oauth_client_view(provider, config=None, vault_names=set(), environ={})
    assert (env_view["client_id"], env_view["client_id_source"]) == ("from-env", "env")
    assert (cfg_view["client_id"], cfg_view["client_id_source"]) == ("from-config", "config")
    assert (reg_view["client_id"], reg_view["client_id_source"]) == ("from-registry", "registry")


def test_view_secret_source_prefers_env_over_vault_name():
    view = oauth_client_view(
        _provider(),
        config=None,
        vault_names={VAULT_NAME},
        environ={ENV_SECRET: "x"},
    )
    assert view["client_secret_source"] == "env"


def test_view_vault_name_presence_marks_the_secret_set():
    view = oauth_client_view(_provider(), config=None, vault_names={VAULT_NAME}, environ={})
    assert view["client_secret_set"] is True
    assert view["client_secret_source"] == "vault"


def test_view_ignores_vault_names_belonging_to_other_providers():
    view = oauth_client_view(
        _provider(), config=None, vault_names={"CONNECTIONS_ASANA_CLIENT_SECRET"}, environ={}
    )
    assert view["client_secret_set"] is False


def test_view_ignores_an_unusable_env_secret():
    view = oauth_client_view(
        _provider(), config=None, vault_names=set(), environ={ENV_SECRET: "bad\nsecret"}
    )
    assert view["client_secret_set"] is False


@pytest.mark.parametrize(
    ("confidential", "has_id", "has_secret", "configured"),
    [
        (True, True, True, True),
        (True, True, False, False),
        (True, False, True, False),
        (True, False, False, False),
        (False, True, True, True),
        (False, True, False, True),
        (False, False, True, False),
        (False, False, False, False),
    ],
)
def test_view_configured_needs_an_id_and_for_confidential_a_secret(
    confidential, has_id, has_secret, configured
):
    view = oauth_client_view(
        _provider(confidential=confidential),
        config=_config("github", "cid") if has_id else None,
        vault_names={VAULT_NAME} if has_secret else set(),
        environ={},
    )
    assert view["configured"] is configured


# ── apply_preregistered_oauth_client ──


def _resolved(secret: str | None = "s3cr3t") -> ResolvedOAuthClient:
    return ResolvedOAuthClient(
        slug="github",
        client_id="operator-id",
        client_id_source="config",
        client_secret=secret,
        client_secret_source="vault" if secret is not None else None,
        redirect_uri=GITHUB_REDIRECT_URI,
    )


def test_apply_writes_the_three_owned_keys_in_wire_shape():
    entry = {"url": GITHUB_MCP_URL}
    out = apply_preregistered_oauth_client(entry, _resolved())
    assert out[KIRO_OAUTH_KEY] == {
        "clientId": "operator-id",
        "clientSecret": "s3cr3t",
        "redirectUri": GITHUB_REDIRECT_URI,
    }
    assert out["url"] == GITHUB_MCP_URL


def test_apply_is_surgical_on_the_oauth_block():
    entry = {
        "url": GITHUB_MCP_URL,
        "scopes": ["read:user"],
        KIRO_OAUTH_KEY: {
            "issuer": "https://github.com/login/oauth",
            "scopes": ["read:user"],
            "clientId": "stale-store-id",
        },
    }
    out = apply_preregistered_oauth_client(entry, _resolved())
    oauth = out[KIRO_OAUTH_KEY]
    assert oauth["issuer"] == "https://github.com/login/oauth"
    assert oauth["scopes"] == ["read:user"]
    assert oauth["clientId"] == "operator-id"  # the operator's record outranks the store
    assert oauth["clientSecret"] == "s3cr3t"
    assert oauth["redirectUri"] == GITHUB_REDIRECT_URI
    assert out["scopes"] == ["read:user"]


def test_apply_pops_a_stale_client_secret_for_a_public_client():
    entry = {
        "url": GITHUB_MCP_URL,
        KIRO_OAUTH_KEY: {"issuer": "https://github.com/login/oauth", "clientSecret": "old"},
    }
    out = apply_preregistered_oauth_client(entry, _resolved(secret=None))
    oauth = out[KIRO_OAUTH_KEY]
    assert "clientSecret" not in oauth
    assert oauth["issuer"] == "https://github.com/login/oauth"
    assert oauth["clientId"] == "operator-id"
    assert oauth["redirectUri"] == GITHUB_REDIRECT_URI


def test_apply_does_not_mutate_its_input():
    oauth = {"issuer": "https://github.com/login/oauth", "clientId": "stale"}
    entry = {"url": GITHUB_MCP_URL, KIRO_OAUTH_KEY: oauth}
    out = apply_preregistered_oauth_client(entry, _resolved())
    assert entry[KIRO_OAUTH_KEY] is oauth
    assert oauth == {"issuer": "https://github.com/login/oauth", "clientId": "stale"}
    assert out is not entry
    assert out[KIRO_OAUTH_KEY] is not oauth


def test_apply_replaces_a_non_object_oauth_value():
    entry = {"url": GITHUB_MCP_URL, KIRO_OAUTH_KEY: "garbage"}
    out = apply_preregistered_oauth_client(entry, _resolved())
    assert out[KIRO_OAUTH_KEY]["clientId"] == "operator-id"


# ── provider_for_server ──


def test_provider_for_server_requires_slug_and_url_to_match():
    match = provider_for_server("github", {"url": GITHUB_MCP_URL})
    assert match is not None and match["slug"] == "github"


@pytest.mark.parametrize(
    "entry",
    [
        {"url": "https://api.githubcopilot.com/mcp"},  # trailing slash differs
        {"url": "https://mcp.example.com/mcp"},
        {"url": "HTTPS://API.GITHUBCOPILOT.COM/mcp/"},
        {},
        None,
        "https://api.githubcopilot.com/mcp/",
    ],
)
def test_provider_for_server_refuses_a_same_name_server_pointing_elsewhere(entry):
    assert provider_for_server("github", entry) is None


def test_provider_for_server_refuses_a_dcr_provider_even_on_its_own_url():
    notion = get_provider("notion")
    assert notion is not None
    assert provider_for_server("notion", {"url": notion["mcp_url"]}) is None


def test_provider_for_server_refuses_an_unknown_name():
    assert provider_for_server("not-a-provider", {"url": GITHUB_MCP_URL}) is None
    assert provider_for_server("", {"url": GITHUB_MCP_URL}) is None


def test_provider_for_server_returns_a_copy_not_the_registry_object():
    first = provider_for_server("github", {"url": GITHUB_MCP_URL})
    second = provider_for_server("github", {"url": GITHUB_MCP_URL})
    assert first is not None and second is not None
    assert first == second and first is not second
