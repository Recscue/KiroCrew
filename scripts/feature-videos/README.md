# feature-videos

Build and check a signed release folder of feature-intro clips for the CDN.

| File | Does |
|------|------|
| `publish.py` | Turns an input directory into `dist/feature-videos/<release>/` with the media, a signed `manifest.json` and a `SHA256SUMS`. |
| `verify.py` | Re-checks a produced folder: every hash against the bytes on disk, and the signature through the dashboard's own verifier. |
| `_manifest.py` | The shared schema, the canonical byte form both signing and verification hash, and the validation rules. |

Neither script uploads anything or reaches the network. `publish.py` prints the
`aws s3 sync` and CloudFront invalidation commands and stops, so the credentials
that can write to a public origin stay with the human running them.

```bash
python3 scripts/feature-videos/publish.py \
  --input ~/feature-videos-input \
  --cdn-host videos.example.com \
  --kms-key-arn "$RELEASE_SIGNING_KEY_ARN"

python3 scripts/feature-videos/verify.py dist/feature-videos/0.7.0
```

Signing reuses the CLI artifact manifest's trust root: the same offline key,
`RSASSA_PKCS1_V1_5_SHA_256`, and the same canonical JSON. Keys are separated by
purpose. `--kms-key-arn` is the production path — the private half is a
non-exportable AWS KMS key held by the release workflow, so it exists on no disk
— and the manifest then records `key_id`. `--signing-key` signs with a local key
for staging and tests, omits `key_id`, and warns that the result is not a
release.

`signature` is base64 at the manifest's top level and covers canonical JSON of
every other top-level field. That rule is copied into `_manifest.py` rather than
imported, so the tool runs from a bare checkout and never executes runtime code;
`test/test_feature_videos_publish.py` pins the copy by signing with it and
verifying with the runtime's own verifier.

## Size caps

These are PUBLISHER limits, and every one is deliberately stricter than what the
runtime accepts. A release that only just fits today's consumer has no headroom
for a consumer that tightens. Publishing refuses and exits non-zero on any of
them, leaving no folder behind, so the failure lands while a person is watching.

| Cap | Publisher default | Runtime accepts | Flag |
|-----|-------------------|-----------------|------|
| Signed payload — the canonical JSON the signature covers, compact | 65536 (64 KiB) | 262144 (256 KiB) | `--max-payload-bytes` |
| Manifest document — `manifest.json` as published, indented so larger than the payload | 262144 (256 KiB) | 1048576 (1 MiB) | `--max-document-bytes` |
| Entry count | 500 | 1000 | `--max-entries` |
| Per media file — one clip or poster | 26214400 (25 MB) | 67108864 (64 MiB) | `--max-bytes` |

The runtime column is `_SIGNED_PAYLOAD_MAX_BYTES`, `_MANIFEST_MAX_BYTES`,
`_MAX_ENTRIES` and `_MAX_ENTRY_BYTES` in `src/kiro_crew/feature_videos_manifest.py`.
Raise a flag when a release genuinely needs the headroom; the runtime is the hard
limit, this tool's default is the safe one.

`verify.py` takes the same two manifest flags, so a folder can be re-checked
against a different ceiling without republishing.

The input directory holds `catalog.json` plus an `<id>.mp4` and `<id>.jpg` per
entry. The catalog fields, every refusal and the upload steps are in
[feature-videos](../../src/kiro_crew/docs/feature-videos.md).
