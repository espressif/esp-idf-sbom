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

# Path inside an ESP-IDF tree to tools/cmake/version.cmake; presence of this
# file at a path is the marker that identifies the path as an IDF root.
IDF_VERSION_CMAKE = 'tools/cmake/version.cmake'

# Three CPEs that represent ESP-IDF in NVD. These are emitted on the framework
# package unconditionally regardless of target chip; NVD's CPE dictionary
# registers them as Espressif's catch-all identifiers (no variant-specific
# hardware or firmware CPEs exist for esp32-s2/s3/c3/c6/h2/p4 etc.).
IDF_FRAMEWORK_CPE_APP = 'cpe:2.3:a:espressif:esp-idf:{ver}:*:*:*:*:*:*:*'
IDF_FRAMEWORK_CPE_HW = 'cpe:2.3:h:espressif:esp32:-:*:*:*:*:*:*:*'
IDF_FRAMEWORK_CPE_OS = 'cpe:2.3:o:espressif:esp32_firmware:{ver}:*:*:*:*:*:*:*'


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


_IDF_VERSION_SET_RE = re.compile(r'set\s*\(\s*IDF_VERSION_(MAJOR|MINOR|PATCH)\s+(\d+)\s*\)')


def is_idf_root(path: str) -> bool:
    """Return True if `path` looks like the root of an ESP-IDF tree.

    The check is a single file probe: an ESP-IDF root carries
    ``tools/cmake/version.cmake``. The file is specific to ESP-IDF and has been
    present in every release for years, so its presence is a reliable marker.
    """
    return os.path.isfile(pjoin(path, IDF_VERSION_CMAKE))


def read_idf_version(idf_path: str) -> Optional[str]:
    """Read ESP-IDF major.minor.patch version from ``tools/cmake/version.cmake``.

    Returns the version string (e.g. ``"6.1.0"``) or None when the file is
    absent or unparseable. The value is intended for use in CPE construction,
    so it tracks the release-line version rather than ``git describe`` output;
    the latter can be obtained separately via :func:`git.get_remote_location`.
    """
    path = pjoin(idf_path, IDF_VERSION_CMAKE)
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None

    parts = {}
    for m in _IDF_VERSION_SET_RE.finditer(text):
        parts[m.group(1)] = m.group(2)

    if not all(k in parts for k in ('MAJOR', 'MINOR', 'PATCH')):
        return None

    return f'{parts["MAJOR"]}.{parts["MINOR"]}.{parts["PATCH"]}'


def build_idf_framework_cpes(version: str) -> List[str]:
    """Return the list of CPEs to attach to the ESP-IDF framework package.

    The three CPEs are emitted unconditionally; the ``hw`` and ``os`` ones are
    Espressif's NVD catch-alls and apply to any ESP-IDF build regardless of
    target chip (NVD has not registered variant-specific CPEs).
    """
    if not version:
        return []
    return [
        IDF_FRAMEWORK_CPE_APP.format(ver=version),
        IDF_FRAMEWORK_CPE_HW,
        IDF_FRAMEWORK_CPE_OS.format(ver=version),
    ]
