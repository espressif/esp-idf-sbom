# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""esp-idf-sbom logging, backed by the shared esp-pylib logger.

esp-idf-sbom emits machine-readable output (SPDX/JSON/CSV/YAML) on stdout, so it
keeps a tool-specific :class:`SbomLog` (an :class:`esp_pylib.logger.EspLog`
subclass) that owns its stdout/stderr Rich consoles. ``set_console`` configures
them from the CLI flags (output redirect to a file with a wide, soft-wrapped
console; ``--quiet``; ``--no-color``; ``--force-terminal``). Diagnostics
(``err``/``warn``/``debug``) and progress bars go to stderr to keep stdout clean.

The module-level helpers below preserve the historical ``log.err(...)`` API so
the rest of the package keeps importing ``from esp_idf_sbom.libsbom import log``
unchanged while all output is routed through esp-pylib.
"""

import sys
from typing import IO
from typing import Any
from typing import NoReturn
from typing import Optional

from esp_pylib.logger import EspLog
from esp_pylib.logger import Verbosity
from rich.console import Console


class SbomLog(EspLog):
    """Tool-specific esp-pylib logger for esp-idf-sbom.

    Overrides the stdout/stderr consoles so machine-readable output stays clean
    and configurable via :meth:`set_console`, keeps ``debug`` on stderr (gated by
    ``--debug`` rather than verbosity), adds ``print_json``/``eprint`` used by the
    reports, and exits with the historical code ``128`` on a fatal error.
    """

    @property
    def stdout(self) -> Console:
        return self._out

    @property
    def stderr(self) -> Console:
        return self._err

    def set_console(
        self,
        file: IO[str] = sys.stdout,
        quiet: bool = False,
        no_color: bool = False,
        force_terminal_stdout: Optional[bool] = None,
        force_terminal_stderr: Optional[bool] = None,
        debug: bool = False,
    ) -> None:
        self.no_color = no_color
        self._debug_on = debug
        self._err = Console(
            stderr=True,
            quiet=quiet,
            no_color=no_color,
            force_terminal=force_terminal_stderr,
            emoji=False,
            soft_wrap=True,
        )
        width = None
        if file is not sys.stdout:
            # https://rich.readthedocs.io/en/stable/console.html#file-output
            # Don't limit the output to console width if it doesn't go into stdout.
            width = 10000
        self._out = Console(
            file=file,
            width=width,
            quiet=quiet,
            no_color=no_color,
            force_terminal=force_terminal_stdout,
            emoji=False,
            soft_wrap=True,
        )
        self.set_verbosity(Verbosity.SILENT if quiet else Verbosity.NORMAL)

    def debug(self, *args: Any) -> None:
        if self._debug_on:
            self._err.print('[bright_blue]debug: ', *args)

    def eprint(self, *args: Any, **kwargs: Any) -> None:
        self._err.print(*args, **kwargs)

    def print_json(self, *args: Any, **kwargs: Any) -> None:
        self._out.print_json(*args, **kwargs)

    def die(self, *args: Any, exit_code: int = 128, suggestion: Optional[str] = None) -> NoReturn:
        self.err(*args, suggestion=suggestion)
        raise SystemExit(exit_code)


# Build the tool logger with default consoles (main() reconfigures them from the
# CLI flags via set_console). The module-level helpers below call this instance
# directly; set_logger also points the esp-pylib global ``log`` proxy at it, so a
# direct ``from esp_pylib.logger import log`` elsewhere resolves to SbomLog too.
_sbom_log = SbomLog()
_sbom_log.set_console()
EspLog.set_logger(_sbom_log)


def print(*args: Any, **kwargs: Any) -> None:
    _sbom_log.print(*args, **kwargs)


def err(*args: Any, **kwargs: Any) -> None:
    _sbom_log.err(*args, **kwargs)


def warn(*args: Any, **kwargs: Any) -> None:
    _sbom_log.warn(*args, **kwargs)


def note(*args: Any, **kwargs: Any) -> None:
    _sbom_log.note(*args, **kwargs)


def hint(*args: Any, **kwargs: Any) -> None:
    _sbom_log.hint(*args, **kwargs)


def debug(*args: Any, **kwargs: Any) -> None:
    _sbom_log.debug(*args, **kwargs)


def die(*args: Any, **kwargs: Any) -> None:
    _sbom_log.die(*args, **kwargs)


def eprint(*args: Any, **kwargs: Any) -> None:
    _sbom_log.eprint(*args, **kwargs)


def print_json(*args: Any, **kwargs: Any) -> None:
    _sbom_log.print_json(*args, **kwargs)


def set_console(
    file: IO[str] = sys.stdout,
    quiet: bool = False,
    no_color: bool = False,
    force_terminal_stdout: Optional[bool] = None,
    force_terminal_stderr: Optional[bool] = None,
    debug: bool = False,
) -> None:
    _sbom_log.set_console(file, quiet, no_color, force_terminal_stdout, force_terminal_stderr, debug)


def progress(*args: Any, **kwargs: Any) -> Any:
    return _sbom_log.progress(*args, **kwargs)
