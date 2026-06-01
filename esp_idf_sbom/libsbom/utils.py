# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Miscellaneous helpers
"""

import os
import re
import subprocess
from pathlib import Path
from typing import AnyStr
from typing import Dict
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple
from urllib.parse import urlparse


def pjoin(*paths: str) -> str:
    """Join input paths and return resulting path with forward slashes."""
    return Path().joinpath(*paths).as_posix()


def pbasename(path: str) -> str:
    """Return final path component."""
    return Path(path).name


def pdirname(path: str) -> str:
    """Return the directory component of a path."""
    return Path(path).parents[0].as_posix()


def prelpath(path: str, base: str) -> str:
    """Return relative path to base with forward slashes.

    Both paths are resolved first so that symlinks and Windows directory
    junctions don't break the comparison when one side has already been
    resolved upstream (e.g. by `git rev-parse --show-toplevel`).
    """
    return Path(path).resolve().relative_to(Path(base).resolve()).as_posix()


def psubdir(path: str, base: str) -> bool:
    """Return True if path is subdir of base."""
    return Path(base).resolve() in Path(path).resolve().parents


def ppaths(paths: List[str]) -> List[str]:
    """Return paths with forward slashes."""
    return [str(Path(p).as_posix()) for p in paths]


def ppath(path: str) -> str:
    """Return path with forward slashes."""
    return ppaths([path])[0]


def psplit(path: str) -> Tuple[str, ...]:
    """Split path into tuple of components."""
    return Path(path).parts


def presolve(path: str) -> str:
    """Return resolved path with forward slashes."""
    return Path(path).resolve().as_posix()


def pwalk(path: str, exclude_dirs: Optional[List[str]] = None) -> Iterator[Tuple[str, List[str], List[str]]]:
    """Perform os.walk() and skip directories in exclude_dirs. Compare and
    return paths in posix format."""
    path = ppath(path)
    if exclude_dirs is None:
        exclude_dirs = []
    exclude_dirs = ppaths(exclude_dirs)

    for root, dirs, files in os.walk(path):
        root = ppath(root)
        if exclude_dirs and root in exclude_dirs:
            continue
        yield (root, dirs, files)


def is_remote_url(url: str = '') -> bool:
    """Check if url has git, http or https scheme and domain.
    This is just a very basic test."""
    res = urlparse(url)
    return bool(res.scheme in ['git', 'http', 'https'] and res.netloc)


# PURL: pkg:<type>/<namespace>?/<name>[@<version>][?<qualifiers>][#<subpath>]
# Reference: https://github.com/package-url/purl-spec
# The version part may still contain the "{}" placeholder at validate time;
# version substitution happens later in mft.fix().
_PURL_RE = re.compile(r'^pkg:[a-z][a-z0-9+\-.]*/.+', re.IGNORECASE)


def is_purl(purl: str = '') -> bool:
    """Minimal syntactic check for a Package URL (PURL).
    Validates only the leading "pkg:<type>/..." structure; full per-type
    rules are intentionally not enforced here."""
    return bool(_PURL_RE.match(purl))


# Matches a github.com or gitlab.com repository URL pointing at the repository
# root only -- with an optional trailing slash or ".git" suffix. URLs that go
# deeper (e.g. ".../tree/<branch>/<subpath>", which github uses to browse a
# subdirectory) intentionally do not match; the same suppression that applies
# to the auto-filled "<URL>@<sha>#<path>" form in guess_purl applies here, so
# auto-derivation never claims a subdirectory of a parent repo as its own
# package.
# Captures:
#   1: host ("github" or "gitlab")
#   2: owner (namespace)
#   3: repo name (".git" suffix stripped)
_GIT_HOST_RE = re.compile(
    r'^https?://(?:www\.)?(github|gitlab)\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
    re.IGNORECASE,
)


def derive_purl(url: str, version: str) -> str:
    """Derive a Package URL from a github.com or gitlab.com source URL.

    Recognises plain repository URLs at the repo root (with optional
    trailing slash or ".git" suffix). Subdirectory URLs such as
    ".../tree/<branch>/<subpath>" intentionally do not match -- a PURL
    derived from them would identify the parent repo at a version that
    does not exist there (e.g. the IDF Component Registry's "<ver>~<rev>"
    revision form for the bundling, which is not a github tag). The
    maintainer can set an explicit purl: in the manifest for such cases.

    Returns an empty string when the URL cannot be derived from (unknown
    host, subdirectory URL, missing version). The caller is expected to
    skip emission in that case rather than producing a partial PURL.
    """
    if not url or not version:
        return ''

    m = _GIT_HOST_RE.match(url)
    if not m:
        return ''

    host, owner, repo = m.group(1), m.group(2), m.group(3)
    return f'pkg:{host.lower()}/{owner}/{repo}@{version}'


def csv_escape(entries: Iterable) -> List[str]:
    """Return list of CSV escaped entries."""
    out = []
    for entry in entries:
        entry = entry.replace('"', '""')
        out.append(f'"{entry}"')
    return out


def run(
    cmd: List[str],
    stdin: Optional[AnyStr] = None,
    stdout: bool = True,
    stderr: bool = True,
    text: bool = True,
    env: Optional[Dict[str, str]] = None,
    strip: bool = True,
    die: bool = False,
) -> Tuple[int, AnyStr, AnyStr]:
    """Simple popen wrapper, which returns tuple of process
    return code, stdout and stderr.
    """

    if stdin and text:
        stdin = stdin.encode()  # type: ignore

    env_new = os.environ.copy()
    if env:
        env_new.update(env)
    p = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if stdin else None,
        stdout=subprocess.PIPE if stdout else None,
        stderr=subprocess.PIPE if stderr else None,
        env=env_new,
    )

    out, err = p.communicate(input=stdin)  # type: ignore
    if not stdout:
        out = b''
    if not stderr:
        err = b''

    if text:
        out = out.decode()  # type: ignore
        err = err.decode()  # type: ignore

    if die and p.returncode:
        if not text:
            err = err.decode()  # type: ignore

        raise RuntimeError(err)

    if strip:
        out = out.strip()
        err = err.strip()

    return (p.returncode, out, err)  # type: ignore
