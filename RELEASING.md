# Releasing

The Tyler ships release artifacts automatically. Cutting a release is a single
action: **push a version tag**. Everything else — building the binaries,
generating checksums, writing the changelog, and creating the GitHub Release —
is handled by CI.

## How it works

Pushing a tag that matches `v*` triggers `.github/workflows/release.yml`, which
runs [GoReleaser](https://goreleaser.com/) (`goreleaser release --clean`). That
one command:

- builds both binaries (`thetyler` and `nftables-sync-client`) for
  `linux/amd64` and `linux/arm64`,
- bundles each OS/arch pair into a `.tar.gz` archive named
  `the-tyler_<version>_linux_<arch>.tar.gz`,
- writes a `checksums.txt` with the SHA-256 of every archive,
- generates a changelog from commit messages since the previous tag, and
- **creates the GitHub Release** and uploads the archives and checksums to it.

You do not build or upload anything by hand.

## Cutting a release

1. Make sure `main` is green and holds everything you want in the release.

2. Choose the next version following [semantic versioning](https://semver.org/)
   (`vMAJOR.MINOR.PATCH`).

3. Tag and push:

   ```bash
   git checkout main
   git pull
   git tag v1.2.3
   git push origin v1.2.3
   ```

4. Watch the **Release** workflow in the Actions tab. When it finishes, the new
   release appears on the Releases page with the two per-arch archives and
   `checksums.txt` attached.

That's it — the tag push is the entire trigger.

## Versioning notes

- **The git tag is the source of truth for the version.** There is no `VERSION`
  file or hardcoded version string to bump; GoReleaser derives the version
  (`{{ .Version }}`) from the tag.
- Tags must start with `v` to match the workflow filter (`v*`). GoReleaser
  strips the leading `v` in archive names, so `v1.2.3` produces
  `the-tyler_1.2.3_linux_amd64.tar.gz`.

## Changelog

GoReleaser builds the release changelog from commit subjects since the last tag,
sorted ascending. Commits with the following prefixes are excluded (see the
`changelog` block in `.goreleaser.yaml`):

- `docs:`
- `test:`
- `chore:`
- merge commits (`Merge pull request`, `Merge branch`)

Writing commit messages with these conventional prefixes keeps the generated
changelog focused on user-facing changes.

## Pre-releases

To publish a build for testing without promoting it to the "latest" release,
tag it as a pre-release, e.g. `v1.2.3-rc1`. GoReleaser marks releases with a
pre-release suffix accordingly, and GitHub's "latest release" continues to point
at the most recent stable tag.

This matters for any consumer that fetches the *latest* release rather than a
specific tag: a pre-release is skipped until you cut a normal `vX.Y.Z`, which
makes `-rcN` tags a safe way to stage and verify a build first.

## Testing the release build locally

You can exercise the GoReleaser pipeline without pushing a tag or publishing
anything:

```bash
# Build archives for a fake snapshot version into ./dist (no publish)
goreleaser release --snapshot --clean

# Or just validate the config
goreleaser check
```

Inspect `./dist` to confirm the archives and `checksums.txt` look right before
cutting the real tag.

## If a release goes wrong

- **Bad tag / broken build:** delete the tag locally and on the remote
  (`git tag -d v1.2.3 && git push origin :refs/tags/v1.2.3`), delete the draft/
  release on GitHub if one was created, fix the issue on `main`, then re-tag.
- **Wrong version number:** tags are cheap — just cut the next correct version.
  Avoid re-pointing an existing tag at new commits, as that breaks anyone who
  already pulled the old artifact.
