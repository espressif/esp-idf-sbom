# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import TextIO

"""
Simple logger with colors support.
"""

ALWAYS = 0
DEBUG  = 1
INFO   = 2
WARN   = 3
ERROR  = 4
NEVER  = 5


class Log:
    """Abstract base class for loggers."""
    def __init__(self, colors: bool=True, level: int=ALWAYS) -> None:
        self.config(colors, level)

    def config(self, colors: bool=True, level: int=ALWAYS) -> None:
        self.colors = colors
        self.level = level

        self.colors_map = {
            'BLACK':   '\033[1;30m',
            'RED':     '\033[1;31m',
            'GREEN':   '\033[1;32m',
            'YELLOW':  '\033[1;33m',
            'BLUE':    '\033[1;34m',
            'MAGENTA': '\033[1;35m',
            'CYAN':    '\033[1;36m',
            'WHITE':   '\033[1;37m',
            'RESET':   '\033[0m',
        }

        if not colors:
            # Colors are not allowed. Replace all colors in colors_map
            # with empty string.
            for key in self.colors_map.keys():
                self.colors_map[key] = ''

    def __getattr__(self, key: str) -> str:
        # Color from colors_map
        return self.colors_map.get(key, '')

    def set_color(self, color: str) -> None:
        self.dump(color, '')

    def reset_color(self) -> None:
        self.dump(self.RESET, '')

    def dump(self, msg: str, end: str='\n') -> None:
        """Actual output implemented by subclasses."""
        raise NotImplementedError

    def log(self, msg: str, color: str='', level: int=ALWAYS, prefix: str='', end: str='\n') -> None:
        """Main generic log method. It's used by other methods with specific parameters set.

        :param msg: message to log
        :param color: message color
        :param level: message log level
        :param prefix: prefix, which will be added before every line in message
        :param end: string added to the end of message
        """
        if level < self.level:
            return

        if color:
            reset = self.RESET
        else:
            reset = ''

        msg = [f'{prefix}{color}{line}{reset}' for line in msg.splitlines(keepends=True)]  # type: ignore
        self.dump(''.join(msg), end=end)

    def debug(self, msg: str, end: str='\n') -> None:
        self.log(msg, '', DEBUG, 'D: ', end=end)

    def info(self, msg: str, end: str='\n') -> None:
        self.log(msg, '', INFO, 'I: ', end=end)

    def warn(self, msg: str, end: str='\n') -> None:
        self.log(msg, self.YELLOW, WARN, 'W: ', end=end)

    def err(self, msg: str, end: str='\n') -> None:
        self.log(msg, self.RED, ERROR, 'E: ', end=end)

    def die(self, msg: str, end: str='\n') -> None:
        self.err(msg, end=end)
        sys.exit(1)

    def echo(self, msg: str, end: str='\n') -> None:
        self.log(msg, '', ALWAYS, end=end)

    def red(self, msg: str, end: str='\n') -> None:
        self.log(msg, self.RED, ALWAYS, end=end)

    def green(self, msg: str, end: str='\n') -> None:
        self.log(msg, self.GREEN, ALWAYS, end=end)

    def yellow(self, msg: str, end: str='\n') -> None:
        self.log(msg, self.YELLOW, ALWAYS, end=end)

    def __iadd__(self, msg: str):
        # += operator
        self.echo(msg, end='')
        return self


class LogFile(Log):
    def __init__(self, fd: TextIO, colors: bool=True, level: int=ALWAYS, force_colors: bool=False) -> None:
        self.fd = fd
        self.config(colors, level, force_colors)

    def config(self, colors: bool=True, level: int=WARN, force_colors: bool=False) -> None:
        if colors and not self.fd.isatty() and not force_colors:
            colors = False
        super().config(colors, level)

    def dump(self, msg: str, end: str='\n') -> None:
        self.fd.write(msg + end)


class LogString(Log):
    def __init__(self, colors: bool=True, level: int=ALWAYS) -> None:
        self.str = ''
        super().__init__(colors, level)

    def dump(self, msg: str, end: str='\n') -> None:
        self.str += msg + end

    def __str__(self) -> str:
        return self.str


# default logger for stdout
out = LogFile(sys.stdout)
# default logger for stderr
err = LogFile(sys.stderr)
