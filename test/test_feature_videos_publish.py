"""The feature-videos publishing tool must produce a folder the runtime trusts.

Three properties carry this suite:

* **The manifest describes the bytes.** Every hash and size in ``manifest.json``
  is recomputed from the files on disk, so a manifest that agrees with itself but
  not with its media is a failure, not a pass.
* **Tampering is detected.** Each way a published folder can be altered — a
  media byte, a manifest field, a signature from another key, an unsigned extra
  file — is exercised and must be rejected.
* **The tool's copy of the rules matches the runtime's.** The tool owns its own
  canonical-JSON encoder and its own copy of nothing else: the doc allowlist is
  parsed from the runtime's source, and a signature the tool produces is fed to
  the runtime's own verifier. Those two cross-checks are what make a local copy
  safe, so a drift fails here rather than on a CDN.

The clip fixture is the recorded placeholder already in the tree rather than a
synthesized container: a hand-built MP4 would hash and size fine while being
something no browser plays, which is the one thing a publishing tool must not
ship.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from kiro_crew.platform import feed_trust
from kiro_crew.tips_allowlist import TIP_DOC_ALLOWLIST

ROOT = Path(__file__).resolve().parents[1]
TOOL_DIR = ROOT / "scripts" / "feature-videos"
PLACEHOLDER_CLIP = ROOT / "website" / "capture" / "assets" / "placeholder.mp4"
PLACEHOLDER_POSTER = ROOT / "website" / "capture" / "assets" / "placeholder.jpg"

#: A doc that is really in the tips allowlist, so the allowlist gate passes for
#: the happy path and a made-up name can test the refusal.
ALLOWED_DOC = "monitor-loops.md"


def _load(name: str) -> Any:
    """Import one of the tool's modules by path.

    The tool lives under ``scripts/`` and is not an importable package, which is
    deliberate — it must run from a checkout with no install.
    """
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, TOOL_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


manifest_mod = _load("_manifest")
publish_mod = _load("publish")
verify_mod = _load("verify")
ManifestError = manifest_mod.ManifestError


#: The consumer module whose limits this tool must stay under. Read as source,
#: never imported: it does not exist until the consuming side lands, and a test
#: that imports it would fail rather than skip.
CONSUMER_SOURCE = ROOT / "src" / "kiro_crew" / "feature_videos_manifest.py"


def _int_literal(node: ast.expr) -> int | None:
    """Evaluate an int constant or a product/sum of them, e.g. ``64 * 1024``.

    Deliberately narrow: the consumer writes its limits as plain arithmetic, and
    anything else should read as "cannot determine" rather than be executed.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add, ast.Sub)):
        left = _int_literal(node.left)
        right = _int_literal(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Mult):
            return left * right
        return left + right if isinstance(node.op, ast.Add) else left - right
    return None


def _consumer_limits() -> dict[str, int] | None:
    """The consumer's module-level integer limits, or None when it has not landed."""
    if not CONSUMER_SOURCE.is_file():
        return None
    tree = ast.parse(CONSUMER_SOURCE.read_text(encoding="utf-8"))
    limits: dict[str, int] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        value = _int_literal(node.value)
        if value is not None:
            limits[target.id] = value
    return limits


def _load_cli_manifest_signer() -> Any:
    """The CLI feed's signer, loaded by path — its filename is not importable."""
    path = ROOT / "packaging" / "signing" / "cli-manifest.py"
    if not path.is_file():  # pragma: no cover - present in every checkout
        pytest.skip(f"{path} is missing")
    spec = importlib.util.spec_from_file_location("cli_manifest_signer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _openssl() -> str:
    found = shutil.which("openssl")
    if found is None:
        pytest.skip("openssl not available")
    return found


def _genkey(path: Path) -> Path:
    subprocess.run(
        [
            _openssl(),
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:3072",
            "-out",
            str(path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return path


@pytest.fixture(scope="module")
def key_pair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A throwaway RSA-3072 pair. Module-scoped: keygen is the slow part.

    3072 bits rather than 2048 because the tool refuses a weaker release key,
    the same floor the CLI manifest signer enforces. A development key, never
    the production one — the production private half lives in KMS and cannot be
    read by anyone.
    """
    scratch = tmp_path_factory.mktemp("feature-videos-key")
    private = _genkey(scratch / "private.pem")
    public = scratch / "public.pem"
    subprocess.run(
        [_openssl(), "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return private, public


@pytest.fixture(scope="module")
def second_key(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A second RSA-3072 private key, for forging a signature by the wrong key."""
    return _genkey(tmp_path_factory.mktemp("feature-videos-second-key") / "private.pem")


@pytest.fixture()
def no_ffprobe(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take ffprobe out of play so a host with or without it behaves identically.

    The codec path is exercised separately with a canned report, which is the
    only way to test both verdicts without shipping a deliberately broken clip.
    """
    monkeypatch.setattr(publish_mod, "_ffprobe_path", lambda: None)


def _entry(**overrides: Any) -> dict[str, Any]:
    entry = {
        "id": "monitor-loops",
        "feature": "monitor-loops",
        "title": "Let one session watch a pull request",
        "description": "A monitor loop re-injects your check instructions on an interval.",
        "doc": ALLOWED_DOC,
        "used_when": ["sel_event_seen:monitor_start"],
        "min_version": "",
        "duration_s": 22.0,
    }
    entry.update(overrides)
    return entry


@pytest.fixture()
def input_dir(tmp_path: Path) -> Path:
    """An input directory holding one real clip, its poster and a catalog."""
    source = tmp_path / "input"
    source.mkdir()
    shutil.copyfile(PLACEHOLDER_CLIP, source / "monitor-loops.mp4")
    shutil.copyfile(PLACEHOLDER_POSTER, source / "monitor-loops.jpg")
    (source / "catalog.json").write_text(
        json.dumps({"entries": [_entry()]}, indent=2) + "\n", encoding="utf-8"
    )
    return source


def _rewrite_catalog(input_dir: Path, entry: dict[str, Any]) -> None:
    (input_dir / "catalog.json").write_text(
        json.dumps({"entries": [entry]}, indent=2) + "\n", encoding="utf-8"
    )


def _publish(
    input_dir: Path, out_root: Path, private_key: Path, *extra: str, release: str = "0.7.0"
) -> Path:
    exit_code = publish_mod.main(
        [
            "--input",
            str(input_dir),
            "--cdn-host",
            "videos.example.com",
            "--release",
            release,
            "--output",
            str(out_root),
            "--signing-key",
            str(private_key),
            *extra,
        ]
    )
    assert exit_code == 0
    return out_root / release


def _read(folder: Path) -> dict[str, Any]:
    return json.loads((folder / "manifest.json").read_text(encoding="utf-8"))


def _rewrite(folder: Path, manifest: dict[str, Any]) -> None:
    (folder / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _sign_bytes(payload: bytes, private_key: Path, tmp_path: Path) -> str:
    path = tmp_path / "payload-to-sign.json"
    path.write_bytes(payload)
    signature = subprocess.run(
        [_openssl(), "dgst", "-sha256", "-sign", str(private_key), str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout
    return base64.b64encode(signature).decode("ascii")


@pytest.mark.usefixtures("no_ffprobe")
class TestProducedFolder:
    def test_manifest_has_the_contract_shape(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        private, _ = key_pair
        manifest = _read(_publish(input_dir, tmp_path / "dist", private))

        # key_id is absent for a local key: it is a hint about which PINNED key
        # signed, and a staging key is not one.
        assert set(manifest) == {
            "schema",
            "release",
            "cdn_base",
            "generated_at",
            "entries",
            "signature",
        }
        assert manifest["schema"] == "kirocrew-feature-videos-manifest-v1"
        assert manifest["release"] == "0.7.0"
        assert manifest["cdn_base"] == "https://videos.example.com/feature-videos/0.7.0/"
        assert manifest["generated_at"].endswith("Z")
        assert isinstance(manifest["signature"], str) and manifest["signature"]
        assert set(manifest["entries"][0]) == {
            "id",
            "feature",
            "title",
            "description",
            "file",
            "poster",
            "sha256",
            "poster_sha256",
            "bytes",
            "duration_s",
            "doc",
            "used_when",
            "min_version",
        }
        entry = manifest["entries"][0]
        assert entry["file"] == "monitor-loops.mp4"
        assert entry["poster"] == "monitor-loops.jpg"
        assert entry["used_when"] == ["sel_event_seen:monitor_start"]
        assert entry["min_version"] == ""
        assert entry["duration_s"] == 22.0

    def test_folder_carries_the_media_and_a_complete_sha256sums(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        folder = _publish(input_dir, tmp_path / "dist", key_pair[0])
        names = {path.name for path in folder.iterdir()}
        assert names == {"monitor-loops.mp4", "monitor-loops.jpg", "manifest.json", "SHA256SUMS"}

        listed = {
            line.split("  ", 1)[1]: line.split("  ", 1)[0]
            for line in (folder / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        }
        assert set(listed) == {"monitor-loops.mp4", "monitor-loops.jpg", "manifest.json"}
        for name, digest in listed.items():
            assert digest == hashlib.sha256((folder / name).read_bytes()).hexdigest()

    def test_hashes_and_size_describe_the_real_bytes(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        folder = _publish(input_dir, tmp_path / "dist", key_pair[0])
        entry = _read(folder)["entries"][0]
        clip = folder / "monitor-loops.mp4"
        poster = folder / "monitor-loops.jpg"
        assert entry["sha256"] == hashlib.sha256(clip.read_bytes()).hexdigest()
        assert entry["poster_sha256"] == hashlib.sha256(poster.read_bytes()).hexdigest()
        assert entry["bytes"] == clip.stat().st_size

    def test_the_upload_is_printed_and_never_run(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Credentials stay with the human: the tool may only print the commands."""

        def _refuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("publish.py must never invoke the AWS CLI")

        monkeypatch.setattr(publish_mod, "_run_aws_json", _refuse)
        _publish(
            input_dir,
            tmp_path / "dist",
            key_pair[0],
            "--s3-bucket",
            "example-bucket",
            "--distribution-id",
            "E123456789",
        )
        out = capsys.readouterr().out
        assert "aws s3 sync --dryrun" in out
        assert "s3://example-bucket/feature-videos/0.7.0/" in out
        assert "aws cloudfront create-invalidation --distribution-id E123456789" in out
        assert "'/feature-videos/0.7.0/*'" in out

    def test_a_local_key_says_the_artifact_is_not_a_release(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Separate keys for staging and production, and the output must say which."""
        _publish(input_dir, tmp_path / "dist", key_pair[0])
        assert "staging artifact" in capsys.readouterr().err

    def test_the_signing_key_is_never_printed(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """No signing-tool output may carry key material or its bytes."""
        private, _ = key_pair
        _publish(input_dir, tmp_path / "dist", private)
        captured = capsys.readouterr()
        secret = private.read_text(encoding="utf-8")
        body = "".join(secret.splitlines()[1:-1])[:64]
        for stream in (captured.out, captured.err):
            assert "PRIVATE KEY" not in stream
            assert body not in stream


@pytest.mark.usefixtures("no_ffprobe")
class TestRulesMatchTheRuntime:
    """The tool's local copies must not drift from what the runtime does."""

    def test_every_publisher_cap_sits_under_the_runtime_limit(self) -> None:
        """A publishing ceiling above the runtime's would ship an unreadable release.

        The runtime's numbers are read from its source rather than restated here,
        so tightening one on that side fails this test instead of silently making
        this tool the looser of the two. Equality is allowed; exceeding is not.
        """
        limits = _consumer_limits()
        if limits is None:
            pytest.skip(
                "src/kiro_crew/feature_videos_manifest.py has not landed yet; "
                "this assertion binds once the consumer is on main"
            )
        pairs = (
            ("payload", manifest_mod.DEFAULT_MAX_PAYLOAD_BYTES, "_SIGNED_PAYLOAD_MAX_BYTES"),
            ("document", manifest_mod.DEFAULT_MAX_DOCUMENT_BYTES, "_MANIFEST_MAX_BYTES"),
            ("entries", manifest_mod.DEFAULT_MAX_ENTRIES, "_MAX_ENTRIES"),
            ("media file", manifest_mod.DEFAULT_MAX_BYTES, "_MAX_ENTRY_BYTES"),
        )
        for label, publisher, constant in pairs:
            runtime = limits.get(constant)
            assert runtime is not None, f"{constant} is missing from the consumer"
            assert publisher <= runtime, (
                f"the {label} publishing cap ({publisher}) exceeds the runtime's "
                f"{constant} ({runtime})"
            )

    def test_a_duplicate_id_is_refused(self, input_dir: Path) -> None:
        (input_dir / "catalog.json").write_text(
            json.dumps({"entries": [_entry(), _entry()]}, indent=2) + "\n", encoding="utf-8"
        )
        with pytest.raises(ManifestError, match="duplicate id"):
            publish_mod._load_catalog(input_dir)

    def test_an_unknown_catalog_field_is_refused(self, input_dir: Path) -> None:
        _rewrite_catalog(input_dir, _entry(src="/app-assets/feature-videos/x.mp4"))
        with pytest.raises(ManifestError, match="unknown field"):
            publish_mod._load_catalog(input_dir)

    def test_a_non_finite_duration_is_refused(self, input_dir: Path) -> None:
        """`> 0` admits infinity, and json.dumps writes the bare token Infinity.

        The signature over those bytes verifies perfectly while the document is
        not JSON, so the check has to be finiteness, not positivity.
        """
        _rewrite_catalog(input_dir, _entry(duration_s=1e999))
        with pytest.raises(ManifestError, match="must be finite"):
            publish_mod._load_catalog(input_dir)

    def test_a_non_finite_probe_duration_is_not_trusted(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unusable ffprobe duration reads as unknown, never as a value to sign."""
        _rewrite_catalog(input_dir, _entry(duration_s=None))
        monkeypatch.setattr(publish_mod, "_ffprobe_path", lambda: "/usr/bin/ffprobe")
        monkeypatch.setattr(
            publish_mod,
            "_ffprobe_json",
            lambda _p: {
                "streams": [{"codec_type": "video", "codec_name": "h264"}],
                "format": {"duration": "inf"},
            },
        )
        with pytest.raises(ManifestError, match="duration is unknown"):
            _publish(input_dir, tmp_path / "dist", key_pair[0])

    def test_a_prerelease_min_version_is_refused(self, input_dir: Path) -> None:
        _rewrite_catalog(input_dir, _entry(min_version="0.8.0rc1"))
        with pytest.raises(ManifestError, match="bare release"):
            publish_mod._load_catalog(input_dir)

    def test_a_non_https_cdn_base_is_refused(self) -> None:
        with pytest.raises(ManifestError, match="must be an https URL"):
            manifest_mod.validate_cdn_base("http://videos.example.com/feature-videos/0.7.0/")

    def test_a_cdn_base_without_a_trailing_slash_is_refused(self) -> None:
        with pytest.raises(ManifestError, match="must end with a slash"):
            manifest_mod.validate_cdn_base("https://videos.example.com/feature-videos/0.7.0")

    def test_a_weak_signing_key_is_refused(self, tmp_path: Path) -> None:
        """Below 3072 bits is not a release key, the CLI signer's own floor."""
        private = tmp_path / "weak.pem"
        subprocess.run(
            [
                _openssl(),
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(private),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public = tmp_path / "weak-public.pem"
        subprocess.run(
            [_openssl(), "pkey", "-in", str(private), "-pubout", "-out", str(public)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with pytest.raises(ManifestError, match="at least 3072 bits"):
            manifest_mod.key_id_of(public)

    def test_the_canonical_form_matches_the_cli_manifest_signer(self) -> None:
        """The sibling signer's canonicalization is the same rule, so pin it.

        `packaging/signing/cli-manifest.py` signs the CLI feed with the same key
        and the same encoding. Two independent copies of one rule drift silently,
        and a drift here means a release this tool signs verifies nowhere — so the
        two are compared byte-for-byte rather than trusted to stay identical.
        """
        signer = _load_cli_manifest_signer()
        for payload in (
            {"schema": "x", "version": "1"},
            {"b": "2", "a": "1"},
            {"unicode": "caf\u00e9", "quote": 'a"b'},
        ):
            assert manifest_mod.canonical_bytes(payload) == signer._canonical_json(payload)

    def test_the_key_id_derivation_matches_the_cli_manifest_signer(
        self, key_pair: tuple[Path, Path]
    ) -> None:
        """One key, one identity: both tools must name it the same way."""
        signer = _load_cli_manifest_signer()
        _, public = key_pair
        assert manifest_mod.key_id_of(public) == signer.public_key_id(public)

    def test_the_algorithm_matches_the_cli_manifest_signer(self) -> None:
        signer = _load_cli_manifest_signer()
        assert manifest_mod.ALGORITHM == signer.ALGORITHM

    def test_the_parsed_doc_allowlist_equals_the_runtime_one(self) -> None:
        """Parsed from source, never imported — but it must be the same set."""
        assert publish_mod.read_tip_doc_allowlist() == TIP_DOC_ALLOWLIST

    def test_the_runtime_verifier_accepts_what_the_tool_signs(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The canonical-JSON copy is pinned to the runtime's own verifier.

        Skipped until the runtime grows ``verify_document_signature``; once it
        lands, a divergence in the tool's encoder fails here instead of shipping
        a manifest every dashboard silently refuses.
        """
        verifier = getattr(feed_trust, "verify_document_signature", None)
        if verifier is None:
            pytest.skip(
                "runtime verify_document_signature has not landed yet; once it has, "
                "this can use the shared helpers in test/feature_video_fixture.py"
            )

        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)

        der = subprocess.run(
            [_openssl(), "pkey", "-pubin", "-in", str(public), "-outform", "DER"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
        monkeypatch.setattr(feed_trust, "trusted_system_bin", lambda _name: _openssl())
        monkeypatch.setattr(
            feed_trust,
            "PINNED_PUBLIC_KEY_B64",
            base64.b64encode(public.read_bytes()).decode("ascii"),
        )
        monkeypatch.setattr(
            feed_trust, "PINNED_KEY_ID", f"sha256:{hashlib.sha256(der).hexdigest()}"
        )

        assert verifier(manifest, max_payload_bytes=manifest_mod.DEFAULT_MAX_PAYLOAD_BYTES) is True

        manifest["entries"][0]["title"] = "A title nobody signed"
        assert verifier(manifest, max_payload_bytes=manifest_mod.DEFAULT_MAX_PAYLOAD_BYTES) is False

    def test_the_canonical_form_sorts_nested_keys(self) -> None:
        """Nested payloads are allowed, so nested key order must not matter."""
        one = manifest_mod.canonical_bytes({"a": [{"y": 1, "x": 2}], "b": 3})
        two = manifest_mod.canonical_bytes({"b": 3, "a": [{"x": 2, "y": 1}]})
        assert one == two
        assert one == b'{"a":[{"x":2,"y":1}],"b":3}\n'


@pytest.mark.usefixtures("no_ffprobe")
class TestTamperDetection:
    def test_verify_passes_on_a_freshly_produced_folder(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        report = verify_mod.verify_folder(folder, public_key=public)
        assert report["release"] == "0.7.0"
        assert report["entries"] == 1
        assert report["claims_key_id"] is False

    def test_a_flipped_media_byte_is_caught(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        clip = folder / "monitor-loops.mp4"
        raw = bytearray(clip.read_bytes())
        raw[-1] ^= 0xFF
        clip.write_bytes(bytes(raw))
        with pytest.raises(ManifestError, match="hash to"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_an_edited_manifest_field_is_caught(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """The signature covers every top-level field, so any edit breaks it."""
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        manifest["entries"][0]["title"] = "A title nobody signed"
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="does not verify against the release key"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_a_redirected_cdn_base_is_caught(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        manifest["cdn_base"] = "https://evil.example.com/feature-videos/0.7.0/"
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="does not verify against the release key"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_a_signature_from_another_key_is_refused(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        second_key: Path,
    ) -> None:
        """A well-formed signature over the right bytes, by the wrong key."""
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        payload = manifest_mod.canonical_bytes(manifest_mod.signed_payload(manifest))
        manifest["signature"] = _sign_bytes(payload, second_key, tmp_path)
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="does not verify against the release key"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_a_stripped_signature_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        del manifest["signature"]
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="missing its signature"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_an_added_top_level_field_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """A field outside the schema is refused, not ignored and left unsigned."""
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        manifest["extra"] = "smuggled"
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="unknown field"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_a_key_id_naming_another_key_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """key_id is optional, but a present one must name the verifying key."""
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        manifest["key_id"] = f"sha256:{'0' * 64}"
        payload = manifest_mod.canonical_bytes(manifest_mod.signed_payload(manifest))
        manifest["signature"] = _sign_bytes(payload, private, tmp_path)
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="but the verifying key is"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_a_key_id_naming_the_verifying_key_is_accepted(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """The production shape: key_id present, inside the signed payload."""
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        manifest["key_id"] = manifest_mod.key_id_of(public)
        payload = manifest_mod.canonical_bytes(manifest_mod.signed_payload(manifest))
        manifest["signature"] = _sign_bytes(payload, private, tmp_path)
        _rewrite(folder, manifest)

        # SHA256SUMS covers manifest.json, so it has to be refreshed alongside.
        sums = folder / "SHA256SUMS"
        digest = manifest_mod.file_sha256(folder / "manifest.json")
        lines = [
            line
            for line in sums.read_text(encoding="utf-8").splitlines()
            if not line.endswith("  manifest.json")
        ]
        sums.write_text("\n".join(sorted([*lines, f"{digest}  manifest.json"])) + "\n", "utf-8")

        report = verify_mod.verify_folder(folder, public_key=public)
        assert report["claims_key_id"] is True

    def test_a_dropped_required_field_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """A validly signed but incomplete manifest is still refused.

        Re-signing after dropping a field makes the signature correct over what
        remains, so the schema's required-field set is the only thing left to
        catch it.
        """
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        manifest = _read(folder)
        del manifest["generated_at"]
        payload = manifest_mod.canonical_bytes(manifest_mod.signed_payload(manifest))
        manifest["signature"] = _sign_bytes(payload, private, tmp_path)
        _rewrite(folder, manifest)
        with pytest.raises(ManifestError, match="missing field"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_an_unsigned_extra_file_is_caught(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        (folder / "extra.mp4").write_bytes(b"not part of this release")
        with pytest.raises(ManifestError, match="unsigned path"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_an_unsigned_file_nested_in_a_subdirectory_is_caught(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """aws s3 sync uploads the whole tree, so a nested file reaches the CDN.

        A top-level-only scan sees a directory, not a file, and passes — which
        would serve unsigned bytes from the release prefix.
        """
        private, public = key_pair
        folder = _publish(input_dir, tmp_path / "dist", private)
        nested = folder / "assets" / "deep"
        nested.mkdir(parents=True)
        (nested / "payload.js").write_bytes(b"nobody signed this")
        with pytest.raises(ManifestError, match="assets/deep/payload.js"):
            verify_mod.verify_folder(folder, public_key=public)

    def test_republishing_over_a_stale_release_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """A release folder is immutable, and the tool must not delete anyone's bytes.

        Republishing after an entry is dropped would otherwise leave the previous
        clip in the folder, unnamed by the new manifest, and `aws s3 sync` without
        --delete would upload it under a signature that never covered it.
        """
        private, _ = key_pair
        out = tmp_path / "dist"
        folder = _publish(input_dir, out, private)
        (folder / "retired-clip.mp4").write_bytes(b"a previous release's clip")
        with pytest.raises(ManifestError, match="release folder is immutable"):
            _publish(input_dir, out, private)
        # Refused, not deleted: the stale bytes are still there for the operator.
        assert (folder / "retired-clip.mp4").is_file()

    def test_republishing_the_same_entries_is_allowed(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """Re-running with the same catalog is a no-op rewrite, not a stale folder."""
        private, public = key_pair
        out = tmp_path / "dist"
        _publish(input_dir, out, private)
        folder = _publish(input_dir, out, private)
        assert verify_mod.verify_folder(folder, public_key=public)["entries"] == 1


@pytest.mark.usefixtures("no_ffprobe")
class TestValidationRefusals:
    def test_a_non_slug_id_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        _rewrite_catalog(input_dir, _entry(id="Monitor_Loops"))
        with pytest.raises(ManifestError, match="not a lowercase hyphenated slug"):
            _publish(input_dir, tmp_path / "dist", key_pair[0])

    def test_a_missing_poster_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        (input_dir / "monitor-loops.jpg").unlink()
        with pytest.raises(ManifestError, match="missing asset: monitor-loops.jpg"):
            _publish(input_dir, tmp_path / "dist", key_pair[0])

    def test_a_doc_outside_the_tips_allowlist_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        _rewrite_catalog(input_dir, _entry(doc="internal-design-note.md"))
        with pytest.raises(ManifestError, match="not in the tips doc allowlist"):
            _publish(input_dir, tmp_path / "dist", key_pair[0])

    def test_an_oversize_file_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        cap = PLACEHOLDER_CLIP.stat().st_size - 1
        with pytest.raises(ManifestError, match="over the .* byte cap"):
            _publish(input_dir, tmp_path / "dist", key_pair[0], "--max-bytes", str(cap))

    def test_a_payload_over_the_signed_cap_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """An over-cap release must fail while publishing, not on a client."""
        out = tmp_path / "dist"
        with pytest.raises(ManifestError, match="over this tool's 200 byte publishing cap"):
            _publish(input_dir, out, key_pair[0], "--max-payload-bytes", "200")
        assert not out.exists(), "a refused release must leave no folder behind"

    def test_an_oversize_manifest_document_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """The published file has its own cap: it is indented, the signed bytes are not."""
        out = tmp_path / "dist"
        with pytest.raises(ManifestError, match="over this tool's 200 byte publishing cap"):
            _publish(input_dir, out, key_pair[0], "--max-document-bytes", "200")
        assert not out.exists(), "a refused release must leave no folder behind"

    def test_too_many_entries_is_refused(
        self, input_dir: Path, tmp_path: Path, key_pair: tuple[Path, Path]
    ) -> None:
        """The runtime refuses an over-long list whole, so it must not be published."""
        shutil.copyfile(PLACEHOLDER_CLIP, input_dir / "feature-tips.mp4")
        shutil.copyfile(PLACEHOLDER_POSTER, input_dir / "feature-tips.jpg")
        (input_dir / "catalog.json").write_text(
            json.dumps(
                {
                    "entries": [
                        _entry(),
                        _entry(id="feature-tips", feature="feature-tips", doc="feature-tips.md"),
                    ]
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        out = tmp_path / "dist"
        with pytest.raises(ManifestError, match="over this tool's 1 entry publishing cap"):
            _publish(input_dir, out, key_pair[0], "--max-entries", "1")
        assert not out.exists(), "a refused release must leave no folder behind"

        # The same two-entry catalog publishes fine under the real default.
        folder = _publish(input_dir, tmp_path / "ok", key_pair[0])
        assert len(_read(folder)["entries"]) == 2


class TestCodecGate:
    """ffprobe's verdict, exercised through a canned report.

    A real non-H.264 clip would have to be committed to test the refusal, and a
    host without ffmpeg could not produce one — so the report is the seam.
    """

    def _report(self, video_codec: str, audio_codecs: list[str]) -> dict[str, Any]:
        streams: list[dict[str, Any]] = [{"codec_type": "video", "codec_name": video_codec}]
        streams += [{"codec_type": "audio", "codec_name": name} for name in audio_codecs]
        return {"streams": streams, "format": {"duration": "22.0"}}

    def test_h264_with_aac_passes(self) -> None:
        publish_mod._check_media_codecs(Path("clip.mp4"), self._report("h264", ["aac"]))

    def test_a_silent_clip_passes(self) -> None:
        publish_mod._check_media_codecs(Path("clip.mp4"), self._report("h264", []))

    def test_a_non_h264_video_is_refused(self) -> None:
        with pytest.raises(ManifestError, match="video codec is 'vp9'"):
            publish_mod._check_media_codecs(Path("clip.mp4"), self._report("vp9", ["aac"]))

    def test_a_non_aac_audio_track_is_refused(self) -> None:
        with pytest.raises(ManifestError, match="audio codec is 'opus'"):
            publish_mod._check_media_codecs(Path("clip.mp4"), self._report("h264", ["opus"]))

    def test_a_missing_probe_only_warns_on_the_staging_path(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        publish_mod._check_media_codecs(Path("clip.mp4"), None)
        assert "codec check skipped" in capsys.readouterr().err

    def test_a_missing_probe_refuses_on_the_release_path(self) -> None:
        """A release-key folder is trusted everywhere, so its media must be checked.

        VP9 hashes and verifies exactly as well as H.264, so "could not inspect"
        must not become "signed with the key every dashboard trusts".
        """
        with pytest.raises(ManifestError, match="ffprobe is required"):
            publish_mod._check_media_codecs(Path("clip.mp4"), None, require_probe=True)

    def test_a_streamless_report_refuses_on_the_release_path(self) -> None:
        with pytest.raises(ManifestError, match="no streams to check"):
            publish_mod._check_media_codecs(
                Path("clip.mp4"), {"format": {"duration": "22.0"}}, require_probe=True
            )

    def test_duration_is_read_from_the_probe_when_the_catalog_omits_it(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _rewrite_catalog(input_dir, _entry(duration_s=None))
        monkeypatch.setattr(publish_mod, "_ffprobe_path", lambda: "/usr/bin/ffprobe")
        monkeypatch.setattr(
            publish_mod, "_ffprobe_json", lambda _path: self._report("h264", ["aac"])
        )
        folder = _publish(input_dir, tmp_path / "dist", key_pair[0])
        assert _read(folder)["entries"][0]["duration_s"] == 22.0

    def test_an_unknown_duration_is_refused(
        self,
        input_dir: Path,
        tmp_path: Path,
        key_pair: tuple[Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _rewrite_catalog(input_dir, _entry(duration_s=None))
        monkeypatch.setattr(publish_mod, "_ffprobe_path", lambda: None)
        with pytest.raises(ManifestError, match="duration is unknown"):
            _publish(input_dir, tmp_path / "dist", key_pair[0])
