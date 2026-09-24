# tiamat-updates

The host installed copies of Tiamat ask about updates. It serves

```
https://updates.tiamatengine.com/<channel>/manifest.json
https://updates.tiamatengine.com/<channel>/manifest.json.sig
```

and nothing else worth reading. A push to `main` is a deploy. The engine
repository's [`docs/hosting.md`](https://github.com/IridesiumResearch/Tiamat-Voxel-Game/blob/main/docs/hosting.md)
is the authority on why it is shaped this way; this file is the day-to-day.

## What is here

| Path | What |
|---|---|
| `Dockerfile`, `Caddyfile` | Caddy serving `site/` byte for byte, plain HTTP behind Dokploy's proxy. Heads are `Cache-Control: no-cache`; kept copies are immutable. |
| `site/index.html` | The one page a person might land on. |
| `site/<channel>/manifest.json` + `.sig` | The head of a channel: what clients fetch. `test` now; `stable` later. |
| `site/<channel>/releases/<version>/` | The same two files, kept forever, one directory per release. |
| `scripts/check_manifests.py` | Refuses a manifest an installed client would refuse. Runs in CI on every push. |

## Publishing a release

Everything before this happens in the engine repository and on the machine that
holds the signing key (`docs/hosting.md` §7): tag, let CI build the archives,
`relman manifest`, `relman sign`, `relman verify`, and **publish the GitHub
release first**, because the manifest's download links only work once it is
public. Then, here:

```sh
V=0.2.0                              # the release
mkdir -p site/test/releases/$V
cp ~/path/to/dist/manifest.json      site/test/releases/$V/
cp ~/path/to/dist/manifest.json.sig  site/test/releases/$V/
cp site/test/releases/$V/manifest.json      site/test/
cp site/test/releases/$V/manifest.json.sig  site/test/
git add site
git commit -m "test: $V"
git push
```

CI checks the tree, Dokploy redeploys within a minute, and then from anywhere:

```sh
curl -sI https://updates.tiamatengine.com/test/manifest.json      # 200, cache-control: no-cache
curl -sO https://updates.tiamatengine.com/test/manifest.json
curl -sO https://updates.tiamatengine.com/test/manifest.json.sig
# in the engine repository:
cargo run -p relman -- verify --manifest manifest.json \
  --key "$(grep -v '^#' release-key.pub | tr -d '[:space:]')"
```

## Two rules

- **Copy, never edit.** The signature is over the exact bytes `relman` wrote.
  An editor that adds a newline, a pretty-printer, anything that touches the
  file after `relman sign`, makes a manifest every installed copy refuses. CI
  catches it; do not rely on that.
- **Keep every release.** `site/<channel>/releases/<version>/` is the record
  of what was signed. Nothing is ever deleted from it.

## What CI checks

`scripts/check_manifests.py` reads every head and every kept copy and checks
what the client checks: the 64 KiB cap, schema 1, a plain `major.minor.patch`
version, at most 16 artefacts with 1 to 4 `https://` URLs each, sizes under
1 GiB, hashes and keys as 64 hex characters, a `.sig` of exactly 64 raw bytes,
and the Ed25519 signature over the file as committed. The signing key must be
the one the engine compiles in — read from `release-key.pub` on the engine
repository's `main`, so there is no second copy of the trust root here. A head
must be byte-identical to its kept copy. Then the image is built and started,
and each head is fetched back and compared with the file in the tree.

It needs nothing but Python 3. To run it before pushing, with a copy of the
engine's `release-key.pub` so it does not have to fetch one:

```sh
RELEASE_KEY_FILE=../Tiamat/release-key.pub python3 scripts/check_manifests.py
```

## Dokploy

One application, built from this repository:

| Setting | Value |
|---|---|
| Provider | GitHub, this repository, branch `main` |
| Build type | Dockerfile (`Dockerfile` at the root) |
| Auto deploy | on |
| Domain | `updates.tiamatengine.com`, path `/`, container port `80` |
| HTTPS | on, certificate from Let's Encrypt |

The DNS record for `updates` points at the Dokploy machine and is set before
the domain is added, so the certificate can be issued. Details and the
alternatives (GitHub Pages, the Apache box) are in `docs/hosting.md` §4 and §5.
