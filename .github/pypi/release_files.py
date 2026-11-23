"""Validate the GitHub release handoff and select the files still missing on PyPI."""

import argparse
import hashlib
import json
import os
import re
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

SCHEMAS = "eshieldq-gateway-schemas"
CLIENT = "eshieldq-gateway-client"
PACKAGES = (SCHEMAS, CLIENT)
INDEXES = {"pypi": "https://pypi.org", "testpypi": "https://test.pypi.org"}


def filenames(name, version):
    if name not in PACKAGES or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", version):
        raise ValueError(f"Expected a public SDK package and a stable version, got {name} {version}")
    stem = f"{name.replace('-', '_')}-{version}"
    return f"{stem}.tar.gz", f"{stem}-py3-none-any.whl"


def validate_release(release):
    files = filenames(release["name"], release["version"])
    if not re.fullmatch(r"[0-9a-f]{40}", release["commit"]):
        raise ValueError("Invalid gated Git commit SHA")
    hashes = release["files"]
    if set(hashes) != set(files) or any(not re.fullmatch(r"[0-9a-f]{64}", d) for d in hashes.values()):
        raise ValueError("Expected SHA-256 digests for exactly the public wheel and sdist")


def validate_workflow_context(release, repository, ref, commit):
    if repository != f"qemcorp/{release['name']}":
        raise ValueError("The publishing workflow must run in the package's own repository")
    if ref != f"refs/tags/v{release['version']}" or commit != release["commit"]:
        raise ValueError("The publishing workflow must run at the gated release tag and commit")


def get(url, *, allow_missing=False):
    request = Request(url, headers={"User-Agent": "qem-sdk-publisher", "Cache-Control": "no-cache"})
    try:
        with urlopen(request, timeout=30) as response:
            return response.read()
    except HTTPError as exc:
        if allow_missing and exc.code == 404:
            return None
        raise


def require_public_mirror(name):
    repo = get(f"https://api.github.com/repos/qemcorp/{name}", allow_missing=True)
    if repo is None or json.loads(repo)["visibility"] != "public":
        raise ValueError(f"qemcorp/{name} must be public before uploading distribution files")


def github_tag(release, *, allow_missing=False):
    name = release["name"]
    tag = f"v{release['version']}"
    require_public_mirror(name)
    api = f"https://api.github.com/repos/qemcorp/{name}"
    raw = get(f"{api}/git/ref/tags/{tag}", allow_missing=True)
    if raw is None:
        if allow_missing:
            return None
        raise ValueError(f"qemcorp/{name} is missing public tag {tag}")
    ref = json.loads(raw)["object"]
    if ref["type"] != "commit" or ref["sha"] != release["commit"]:
        raise ValueError(f"{name} {tag} does not point to the gated commit {release['commit']}")
    return tag


def github_file(release, tag, filename):
    url = f"https://github.com/qemcorp/{release['name']}/releases/download/{tag}/{filename}"
    data = get(url, allow_missing=True)
    if data is not None:
        check_hash(filename, data, release["files"][filename])
    return data


def check_hash(filename, data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"SHA-256 mismatch for {filename}")


def index_files(index, name, version):
    body = get(f"{INDEXES[index]}/pypi/{name}/{version}/json", allow_missing=True)
    return json.loads(body)["urls"] if body is not None else []


def missing_files(release, index):
    missing = dict(release["files"])
    for file in index_files(index, release["name"], release["version"]):
        filename = file["filename"]
        if filename not in missing or file["digests"]["sha256"] != missing[filename] or file["yanked"]:
            raise ValueError(f"{index} already has a conflicting or yanked file: {filename}")
        del missing[filename]
    return missing


def prepare(release, index, destination):
    tag = github_tag(release)
    missing = missing_files(release, index)
    destination.mkdir()
    for filename in release["files"]:
        data = github_file(release, tag, filename)
        if data is None:
            raise ValueError(f"GitHub release is missing {filename}")
        if filename in missing:
            (destination / filename).write_bytes(data)
    return bool(missing)


def confirm(release, index):
    for attempt in range(12):
        if not missing_files(release, index):
            print(f"{index} serves {release['name']} {release['version']} with the expected SHA-256 digests")
            return
        if attempt < 11:
            time.sleep(5)
    raise ValueError(f"{index} does not serve all expected files")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "confirm"))
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    release = json.loads(os.environ["SDK_RELEASE"])
    index = os.environ["PYPI_INDEX"]
    validate_release(release)
    validate_workflow_context(release, os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_REF"], os.environ["GITHUB_SHA"])
    if args.command == "prepare":
        missing = prepare(release, index, args.dist)
        with open(os.environ["GITHUB_OUTPUT"], "a") as out:
            print(f"upload={str(missing).lower()}", file=out)
            print(f"name={release['name']}", file=out)
            print(f"version={release['version']}", file=out)
    else:
        confirm(release, index)


if __name__ == "__main__":
    main()
