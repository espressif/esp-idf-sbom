# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
"""esp-idf-sbom logging, backed by the shared esp-pylib logger.

esp-idf-sbom emits machine-readable output (SPDX/JSON/CSV/YAML) on stdout, so it
keeps a tool-specific :class:`SbomLog` (an :class:`esp_pylib.logger.EspLog`
subclass). ``set_console`` configures the shared esp-pylib consoles from the CLI
flags via ``set_console_options`` (redirect to a file with a wide, soft-wrapped
console; ``--quiet``; ``--no-color``; ``--force-terminal``) and routes the info
stream to stderr, so all diagnostics (``err``/``warn``/``note``/``hint``/
``debug``) and progress bars stay off stdout.

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


class SbomLog(EspLog):
    """Tool-specific esp-pylib logger for esp-idf-sbom.

    Configures the shared esp-pylib consoles via :meth:`set_console`, routes all
    informational output to stderr so the machine-readable reports on stdout stay
    clean, keeps ``debug`` behind ``--debug``, adds the ``print_json``/``eprint``
    helpers used by the reports, and exits with the historical code ``128`` on a
    fatal error.
    """

    # debug() may be called before set_console() runs; default to off.
    _debug_on: bool = False

    def set_console(
        self,
        file: IO[str] = sys.stdout,
        quiet: bool = False,
        no_color: bool = False,
        force_terminal: bool = False,
        debug: bool = False,
    ) -> None:
        self._debug_on = debug
        self.set_console_options(
            # A file target (e.g. --output-file) pins stdout and drops
            # force_terminal there so the written report stays ANSI-free; None
            # lets stdout follow the live sys.stdout. Reports can be wider than
            # the terminal, so widen the console for file output to avoid
            # wrapping tables to the default 80 columns (harmless on stderr,
            # whose plain soft-wrapped diagnostics ignore the width).
            file=None if file is sys.stdout else file,
            no_color=no_color,
            force_terminal=True if force_terminal else None,
            width=None if file is sys.stdout else 10000,
            soft_wrap=True,
            # Keep Rich's auto-highlight, which the previous hand-built consoles
            # used by default.
            highlight=True,
            quiet=quiet,
        )
        # Machine-readable reports go to stdout, so send note/hint/debug to
        # stderr to keep it clean.
        self.set_info_stream(sys.stderr)
        self.set_verbosity(Verbosity.SILENT if quiet else Verbosity.NORMAL)

    def debug(self, *args: Any) -> None:
        if self._debug_on:
            self.stderr.print('[bright_blue]debug: ', *args)

    def eprint(self, *args: Any, **kwargs: Any) -> None:
        self.stderr.print(*args, **kwargs)

    def print_json(self, *args: Any, **kwargs: Any) -> None:
        self.stdout.print_json(*args, **kwargs)

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
    force_terminal: bool = False,
    debug: bool = False,
) -> None:
    _sbom_log.set_console(file, quiet, no_color, force_terminal, debug)


def progress(*args: Any, **kwargs: Any) -> Any:
    return _sbom_log.progress(*args, **kwargs)
