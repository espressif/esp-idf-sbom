# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import IO, Any, Optional

from rich.console import Console

console_stderr = None
console_stdout = None
debug_on = False


def err(*args: Any) -> None:
    console_stderr.print('[red]error: ', *args)  # type: ignore


def warn(*args: Any) -> None:
    console_stderr.print('[yellow]warning: ', *args)  # type: ignore


def die(*args: Any) -> None:
    err(*args)
    sys.exit(128)


def debug(*args: Any) -> None:
    if debug_on:
        console_stderr.print('[bright_blue]debug: ', *args)  # type: ignore


def eprint(*args: Any) -> None:
    console_stderr.print(*args)  # type: ignore


def print(*args: Any) -> None:
    console_stdout.print(*args)  # type: ignore


def print_json(*args: Any) -> None:
    console_stdout.print_json(*args)  # type: ignore


def set_console(file: IO[str]=sys.stdout, quiet: bool=False, no_color: bool=False,
                force_terminal_stdout: Optional[bool]=None, force_terminal_stderr: Optional[bool]=None,
                debug: bool=False) -> None:
    global console_stderr
    global console_stdout
    global debug_on

    console_stderr = Console(stderr=True, quiet=quiet, no_color=no_color,
                             force_terminal=force_terminal_stderr, emoji=False,
                             soft_wrap=True)
    width = None
    if file is not sys.stdout:
        # https://rich.readthedocs.io/en/stable/console.html#file-output
        # Don't limit the output to console width if it dosn't go into stdout
        width = 10000
    console_stdout = Console(file=file, width=width, quiet=quiet, no_color=no_color,
                             force_terminal=force_terminal_stdout, emoji=False,
                             soft_wrap=True)

    debug_on = debug
