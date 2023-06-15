# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Miscellaneous helpers
"""

import os
import subprocess
from pathlib import Path
from typing import AnyStr, Dict, List, Optional, Tuple
from urllib.parse import urlparse


def pjoin(*paths: str) -> str:
    """Join input paths and return resulting path with forward slashes."""
    return Path().joinpath(*paths).as_posix()


def prelpath(path: str, base: str) -> str:
    """Return relative path to base with forward slashes."""
    return Path(path).relative_to(base).as_posix()


def psplit(path: str) -> Tuple[str,...]:
    """Split path into tuple of components."""
    return Path(path).parts


def is_remote_url(url: str='') -> bool:
    """Check if url has git, http or https scheme and domain.
    This is just a very basic test."""
    res = urlparse(url)
    return bool(res.scheme in ['git', 'http', 'https'] and res.netloc)


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
        err = out.strip()

    return (p.returncode, out, err)  # type: ignore
