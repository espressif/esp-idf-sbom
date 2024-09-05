# SPDX-FileCopyrightText: 2023-2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Miscellaneous helpers
"""

import os
import subprocess
from pathlib import Path
from typing import AnyStr, Dict, Iterable, Iterator, List, Optional, Tuple
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
    """Return relative path to base with forward slashes."""
    return Path(path).relative_to(base).as_posix()


def psubdir(path: str, base: str) -> bool:
    """Return True if path is subdir of base."""
    return Path(base).resolve() in Path(path).resolve().parents


def ppaths(paths: List[str]) -> List[str]:
    """Return paths with forward slashes."""
    return [str(Path(p).as_posix()) for p in paths]


def ppath(path: str) -> str:
    """Return path with forward slashes."""
    return ppaths([path])[0]


def psplit(path: str) -> Tuple[str,...]:
    """Split path into tuple of components."""
    return Path(path).parts


def presolve(path:str) -> str:
    """Return resolved path with forward slashes."""
    return Path(path).resolve().as_posix()


def pwalk(path: str, exclude_dirs: Optional[List[str]]=None) -> Iterator[Tuple[str, List[str], List[str]]]:
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


def is_remote_url(url: str='') -> bool:
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


def run(cmd:    List[str],
        stdin:  Optional[AnyStr]=None,
        stdout: bool=True,
        stderr: bool=True,
        text:   bool=True,
        env:    Optional[Dict[str,str]] = None,
        strip:  bool=True,
        die:    bool=False) -> Tuple[int, AnyStr, AnyStr]:
    """Simple popen wrapper, which returns tuple of process
    return code, stdout and stderr.
    """

    if stdin and text:
        stdin = stdin.encode()  # type: ignore

    env_new = os.environ.copy()
    if env:
        env_new.update(env)
    p = subprocess.Popen(cmd,
                         stdin=subprocess.PIPE if stdin else None,
                         stdout=subprocess.PIPE if stdout else None,
                         stderr=subprocess.PIPE if stderr else None,
                         env=env_new)

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
