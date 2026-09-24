#!/usr/bin/env python3
"""Refuses to publish a manifest an installed client would refuse.

Every ``site/<channel>/manifest.json`` (the head a client fetches) and every
``site/<channel>/releases/<version>/manifest.json`` (the kept record) is
checked the way the client checks it — the caps, the shape, the detached
Ed25519 signature over the exact bytes — against the key the engine
compiles in, read from ``release-key.pub`` on the engine repository's main
branch so this never holds a second copy of the trust root.

The one failure that has ever needed a re-release is a manifest edited after
it was signed. A head must therefore be byte-identical to its kept copy, and
the signature must hold over the file as it sits in the tree.
"""

import json
import os
import re
import sys
import time
from pathlib import Path

ENGINE_KEY_URL = (
    "https://raw.githubusercontent.com/IridesiumResearch/Tiamat-Voxel-Game/main/release-key.pub"
)
SITE = Path("site")

# The client's caps, from the engine's crates/core/src/release.rs.
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARTIFACTS = 16
MAX_URLS = 4
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
SCHEMA = 1

HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def fail(path, what):
    print(f"FAIL {path}: {what}")
    return 1


def key_in(text, source):
    """The first key line of a release-key.pub: 64 hex characters."""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            if not HEX32.match(line):
                sys.exit(f"{source} holds no 64-character hex key: {line!r}")
            return line.lower()
    sys.exit(f"{source} has no key line")


def engine_key():
    """The key installed builds trust.

    From the engine repository's main branch, so this never holds a second
    copy of the trust root — or, for a check on a machine without the network,
    from the file `RELEASE_KEY_FILE` names (a copy of the engine's
    `release-key.pub`).
    """
    local = os.environ.get("RELEASE_KEY_FILE")
    if local:
        return key_in(Path(local).read_text(encoding="utf-8"), local)
    import urllib.request

    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(ENGINE_KEY_URL, timeout=20) as response:
                return key_in(response.read().decode("utf-8", "replace"), ENGINE_KEY_URL)
        except OSError as err:
            last = err
            time.sleep(3 * (attempt + 1))
    sys.exit(f"could not read the engine's release-key.pub: {last}")


# ---- Ed25519, RFC 8032 §5.1, in the standard library alone -----------------
#
# Written out rather than imported so the check needs nothing installed and
# runs the same on a laptop as in CI. Affine coordinates and a plain
# double-and-add: slow by a cryptographer's standards and instant for four
# manifests. `--self-test` runs it against the RFC's first test vector.

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _recover_x(y, sign):
    if y >= _Q:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _Q - 2, _Q) % _Q
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_Q + 3) // 8, _Q)
    if (x * x - x2) % _Q != 0:
        x = x * _I % _Q
    if (x * x - x2) % _Q != 0:
        return None
    if (x & 1) != sign:
        x = _Q - x
    return x


def _decode(raw):
    value = int.from_bytes(raw, "little")
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, value >> 255)
    return None if x is None else (x, y)


def _encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    cross = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + cross, _Q - 2, _Q) % _Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - cross, _Q - 2, _Q) % _Q
    return (x3, y3)


def _mul(k, point):
    result = (0, 1)
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_B = (_recover_x(_BY, 0), _BY)


def verify(key_hex, signature, data):
    """Whether `signature` is `key_hex`'s Ed25519 signature over `data`."""
    import hashlib

    public = bytes.fromhex(key_hex)
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decode(public)
    r = _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + data).digest(), "little") % _L
    return _encode(_mul(s, _B)) == _encode(_add(r, _mul(h, a)))


def self_test():
    """RFC 8032 §7.1, test 1: the empty message."""
    public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert verify(public, signature, b""), "RFC 8032 test 1 should verify"
    assert not verify(public, signature, b"x"), "a different message must not"
    assert not verify(public, signature[:-1] + bytes([signature[-1] ^ 1]), b""), "a flipped bit must not"
    print("self-test ok: RFC 8032 test 1 verifies, and two corruptions do not")


def check_manifest(path, channel, kept_version, trusted):
    """Everything the client checks, plus the rules of this tree. Returns a
    failure count and the parsed manifest (or None)."""
    failures = 0
    data = path.read_bytes()
    if len(data) > MAX_MANIFEST_BYTES:
        return fail(path, f"{len(data)} bytes, over the client's {MAX_MANIFEST_BYTES}-byte cap"), None

    sig_path = path.with_name(path.name + ".sig")
    if not sig_path.exists():
        failures += fail(path, "no manifest.json.sig beside it")
        signature = None
    else:
        signature = sig_path.read_bytes()
        if len(signature) != 64:
            failures += fail(sig_path, f"{len(signature)} bytes; a detached Ed25519 signature is exactly 64 raw bytes (not hex, not base64)")
            signature = None

    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        return failures + fail(path, f"not JSON: {err}"), None
    if not isinstance(manifest, dict):
        return failures + fail(path, "not a JSON object"), None

    def field(name, kind, optional=False):
        nonlocal failures
        value = manifest.get(name)
        if value is None:
            if not optional:
                failures += fail(path, f"missing `{name}`")
            return None
        if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
            failures += fail(path, f"`{name}` should be {kind.__name__}, got {type(value).__name__}")
            return None
        return value

    if field("schema", int) != SCHEMA:
        failures += fail(path, f"schema {manifest.get('schema')!r}; the client reads {SCHEMA}")
    if field("channel", str) != channel:
        failures += fail(path, f"channel {manifest.get('channel')!r} but it sits under site/{channel}/")
    version = field("version", str)
    if version is not None and not VERSION.match(version):
        failures += fail(path, f"`{version}` is not major.minor.patch")
    if kept_version is not None and version != kept_version:
        failures += fail(path, f"version {version!r} kept under releases/{kept_version}/")
    field("commit", str, optional=True)
    field("released", str)
    protocol = field("protocol", int)
    if protocol is not None and protocol <= 0:
        failures += fail(path, f"protocol {protocol}")
    key = field("key", str)
    if key is not None and not HEX32.match(key):
        failures += fail(path, "`key` is not 32 hex bytes")
        key = None
    next_key = field("next_key", str, optional=True)
    if next_key is not None and not HEX32.match(next_key):
        failures += fail(path, "`next_key` is not 32 hex bytes")
    field("notes", str, optional=True)

    artifacts = field("artifacts", list)
    if artifacts is not None:
        if not 1 <= len(artifacts) <= MAX_ARTIFACTS:
            failures += fail(path, f"{len(artifacts)} artifacts; 1 to {MAX_ARTIFACTS} are allowed")
        for index, artifact in enumerate(artifacts):
            where = f"artifacts[{index}]"
            if not isinstance(artifact, dict):
                failures += fail(path, f"{where} is not an object")
                continue
            name = artifact.get("name")
            if not isinstance(name, str) or not name or "/" in name or "\\" in name or ".." in name:
                failures += fail(path, f"{where}.name {name!r} is not a plain file name")
            if not isinstance(artifact.get("target"), str) or not artifact["target"]:
                failures += fail(path, f"{where}.target missing")
            size = artifact.get("size")
            if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_ARTIFACT_BYTES:
                failures += fail(path, f"{where}.size {size!r}; 1 to {MAX_ARTIFACT_BYTES} bytes")
            if not isinstance(artifact.get("hash"), str) or not HEX32.match(artifact["hash"]):
                failures += fail(path, f"{where}.hash is not a BLAKE3 hash in hex")
            urls = artifact.get("urls")
            if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_URLS:
                failures += fail(path, f"{where}.urls: 1 to {MAX_URLS} are allowed")
            else:
                for url in urls:
                    if not isinstance(url, str) or not url.startswith("https://"):
                        failures += fail(path, f"{where}: `{url}` is not an https URL")

    if key is not None and signature is not None:
        if not verify(key, signature, data):
            failures += fail(path, "the signature is not this key's signature over these exact bytes — was the file edited or reformatted after `relman sign`?")
        elif key.lower() != trusted:
            failures += fail(path, f"signed by {key[:8]}…, but installed builds trust {trusted[:8]}… (the engine's release-key.pub). A rotation lands in the engine repository first.")
    return failures, manifest


def main():
    heads = sorted(SITE.glob("*/manifest.json"))
    kept = sorted(SITE.glob("*/releases/*/manifest.json"))
    if not heads and not kept:
        print("no manifests yet; nothing to check")
        return 0
    trusted = engine_key()
    print(f"installed builds trust {trusted[:8]}…")
    failures = 0

    for path in kept:
        channel = path.parts[1]
        version_dir = path.parts[3]
        count, manifest = check_manifest(path, channel, version_dir, trusted)
        failures += count
        if manifest and count == 0:
            print(f"ok   {path}: {manifest['channel']} {manifest['version']} protocol {manifest['protocol']}, {len(manifest['artifacts'])} artifacts")

    for path in heads:
        channel = path.parts[1]
        count, manifest = check_manifest(path, channel, None, trusted)
        if manifest is None:
            failures += count
            continue
        version = manifest.get("version")
        copy = SITE / channel / "releases" / str(version) / "manifest.json"
        if not copy.exists():
            count += fail(path, f"no kept copy at {copy}; every head is also kept under releases/<version>/")
        else:
            if copy.read_bytes() != path.read_bytes():
                count += fail(path, f"differs from its kept copy {copy}; the two are the same bytes or one of them was edited")
            head_sig = path.with_name("manifest.json.sig")
            copy_sig = copy.with_name("manifest.json.sig")
            if head_sig.exists() and copy_sig.exists() and head_sig.read_bytes() != copy_sig.read_bytes():
                count += fail(head_sig, f"differs from {copy_sig}")
        failures += count
        if count == 0:
            print(f"ok   {path}: head of `{channel}` is {version}")

    if failures:
        print(f"{failures} problem(s); nothing above may be served")
        return 1
    print("every manifest is one an installed client would accept")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        self_test()
        sys.exit(0)
    sys.exit(main())
