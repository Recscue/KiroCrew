# Feature Videos

Kiro Crew plays a short intro clip for a feature this install has not used yet. Unlike [Feature Tips](feature-tips.md), which are written by a model, a feature video is a recorded clip picked by a fixed rule set — the same install state always selects the same video.

## How It Works

- The catalog is a static list in `feature_videos.py`. There is no generation step and no model call.
- Selection walks the catalog in order and returns the first entry that is enabled, has both its clip and poster shipped on disk, is not yet recorded as seen or dismissed, is satisfied by the running version, and is not withdrawn by a "you already use this" signal.
- An entry whose media is not shipped is withheld, not shown. The dialog opens on the JSON answer alone and fetches nothing until the user presses play, so it cannot detect a missing clip itself -- it would open around a blank player, and the verdict a user then records is permanent. Withholding keeps the entry on offer for the launch after its clip lands.
- Clips and posters are same-origin paths under `/app-assets/feature-videos/`. A path carrying a scheme, `//`, `..`, a percent sign, or a backslash is refused, so a catalog entry can never point the browser off this origin. Remote clip downloads are a separate future change.
- Seen and dismissed are both permanent. There is no snooze: a feature intro that comes back is noise.
- Temporary and incognito sessions get no video, because the state a video records is permanent and instance-wide.
- A clip whose `min_version` is above the running version is skipped, so a video recorded ahead of a release never plays on an older build.

## Controls

| Action | Effect |
|--------|--------|
| Watch a clip to the end | Records `seen`; that video is never offered again. |
| Close the modal | Records `dismissed`; same permanence. |
| `dashboard.feature_videos_enabled: true` in config | Turns the feature ON. It is OFF by default until real clips ship. |

## Adding a Catalog Entry

Append a `VideoEntry` to `CATALOG` in `src/kiro_crew/feature_videos.py`. Order is offer order, so a new entry goes where you want it shown.

```python
VideoEntry(
    id="knowledge-library",
    feature="knowledge-library",
    title="Search your own documents",
    description="One or two plain sentences on what the feature does.",
    src="/app-assets/feature-videos/knowledge-library.mp4",
    poster="/app-assets/feature-videos/knowledge-library.jpg",
    duration_s=20.0,
    doc="knowledge-library-how-it-works.md",
    used_when=("config_key_set:knowledge.enabled",),
    min_version="",
)
```

Rules the catalog enforces, each of which drops the entry with a logged warning rather than breaking the endpoint:

- `id` is a slug and doubles as the state key and the asset basename; keep `src` and `poster` as `<id>.mp4` and `<id>.jpg`.
- `doc` must be listed in `tips_allowlist.py`, the same allowlist tips use — a video cannot point at an internal design note.
- `src` and `poster` must pass `validate_asset_path`.
- `min_version` is optional and must parse as a version when present.

Place the clip and its poster in `website/public/app-assets/feature-videos/`.

## Publishing a Release of Videos

The shipped runtime plays the clips bundled with it, described above. A hosted
release is the other half: `scripts/feature-videos/publish.py` builds the signed
folder a CDN serves, and the runtime side that fetches it is a separate change.
Until that lands, publishing a release folder is a no-op for a running dashboard
— build and verify one, but nothing reads it yet.

Clips ship as a signed release folder. One command builds it, a second checks
it, and a human uploads it. Neither command touches the network, so the
credentials that can write to a public origin stay with the person who owns
them.

Put the media and a `catalog.json` in one directory. Each entry needs an
`<id>.mp4` and an `<id>.jpg` beside it, both named after the entry's `id`.

```json
{
  "entries": [
    {
      "id": "monitor-loops",
      "feature": "monitor-loops",
      "title": "Let one session watch a pull request",
      "description": "One or two plain sentences on what the feature does.",
      "doc": "monitor-loops.md",
      "used_when": ["sel_event_seen:monitor_start"],
      "min_version": "",
      "duration_s": 22.0
    }
  ]
}
```

`duration_s` is optional when ffprobe is installed; without it, set the value or
publishing stops.

### Produce

```bash
python3 scripts/feature-videos/publish.py \
  --input ~/feature-videos-input \
  --cdn-host videos.example.com \
  --kms-key-arn "$RELEASE_SIGNING_KEY_ARN"
```

That writes `dist/feature-videos/<release>/` holding the media, a signed
`manifest.json` and a `SHA256SUMS`. `--release` defaults to the version in
`pyproject.toml`.

The manifest is signed with the same offline key `cli.sh` pins for the CLI
artifact manifest, so a release carries one trust root rather than two.

Keys are separated by purpose. A production release is signed with
`--kms-key-arn`: the private half is a non-exportable AWS KMS key held by the
release workflow, no human can read it, and the tool checks the KMS key's public
half against the committed one before it signs. The manifest then records
`key_id` as a hint about which pinned key was used.

`--signing-key <path>` signs with a local private key for staging and for tests.
It omits `key_id`, because that field names a pinned key and a staging key is not
one, and it prints a warning that the folder is not a release. The dashboard
verifies against the pinned key either way, so a staging folder is a staging
folder no matter where it is uploaded.

`signature` is base64 at the top level of the manifest and covers canonical JSON
of every other top-level field, nested values included. Editing one byte of the
manifest breaks it.

The canonical-JSON rule lives in the tool rather than being imported from the
runtime: publishing has to work from a bare checkout, and a build tool must not
execute the code it produces input for. A test signs with the tool's rule and
verifies with the runtime's own verifier, so the two cannot drift apart
unnoticed.

What publishing refuses, each with its reason on stderr:

| Refused | Why |
|---------|-----|
| An `id` that is not a lowercase hyphenated slug | The id becomes the asset basename and the display-state key. |
| A missing `<id>.mp4` or `<id>.jpg` | A release folder with a hole in it is not publishable. |
| A `doc` outside `src/kiro_crew/tips_allowlist.py` | The allowlist tips use, so a clip cannot point at an internal design note. |
| A file over the cap, 25 MB by default and set by `--max-bytes` | Every dashboard that has not seen a clip fetches it once. |
| Video that is not H.264, or an audio track that is not AAC | Checked with ffprobe when it is installed, skipped with a warning when it is not. A silent clip passes. |
| A duration nobody knows | Set `duration_s`, or install ffprobe. |
| A signed payload over 64 KiB (`--max-payload-bytes`) | A publishing limit under what the runtime accepts, so a release keeps headroom. |
| A `manifest.json` over 256 KiB (`--max-document-bytes`) | Same idea for the published file, which is indented and so larger than the signed bytes. |
| More than 500 entries (`--max-entries`) | The runtime refuses an over-long list whole rather than reading the first few. |

### Verify

```bash
python3 scripts/feature-videos/verify.py dist/feature-videos/0.7.0
```

This recomputes every hash from the bytes on disk, verifies the signature
against the committed release key, and refuses a folder carrying a file nobody
signed. It only reads. Run it before every upload.

Pass `--public-key <pem>` to check a folder signed with a staging key.

### Upload

Publishing prints the commands and stops. Run them yourself:

```bash
aws s3 sync --dryrun dist/feature-videos/0.7.0/ s3://BUCKET/feature-videos/0.7.0/
aws s3 sync dist/feature-videos/0.7.0/ s3://BUCKET/feature-videos/0.7.0/
aws cloudfront create-invalidation --distribution-id DISTRIBUTION \
  --paths '/feature-videos/0.7.0/*'
```

A release folder is immutable. Changing a clip means cutting a new release, not
overwriting a published one. The invalidation is for `manifest.json`, the one
file a consumer re-reads.

Every size refusal exits non-zero and leaves no folder behind, so the failure
lands while a person is watching. These ceilings are this tool's own and each sits
under the runtime's; `scripts/feature-videos/README.md` lists both columns. Raise
a flag when a release genuinely needs the headroom.

## Declaring a `used_when` Signal

`used_when` names deterministic probes. Any one of them firing withdraws the video, because an intro for a feature already in use is worse than no intro. A probe that raises, or a signal nobody registered, counts as "not used" — the clip still plays, and the reason is logged.

Shipped signals:

| Signal | Fires when |
|--------|-----------|
| `tips_feedback_exists` | The user has reacted to a feature tip in any way. |
| `artifacts_nonempty` | The artifact library holds at least one artifact. |
| `sel_event_seen:<tool_name>` | A recent audit-log row names that tool, e.g. `sel_event_seen:monitor_start`. |
| `config_key_set:<dotted.path>` | The user set that key in `config.json` or `config.local.json`. Presence in the file, not the effective value, so a shipped default never fires it. |

To add one, register a function in `_PROBES` (no argument) or `_PARAM_PROBES` (the part after the first `:` is passed in). Keep it cheap: probes run on a polled route, at most once per `/api/feature-videos/next` request, and only for entries no earlier check has already ruled out.

## Configuration

```yaml
dashboard:
  feature_videos_enabled: true   # instance-wide switch; DEFAULT false
```

Display state lives in `feature_videos_state.json` beside `tips_state.json`, written with owner-only permissions.

See [Configuration Reference](configuration.md) for the full list.
