# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Simple module for git interaction.
"""

import os
from typing import Any, Dict, List, Optional

from esp_idf_sbom.libsbom import utils


def _helper(cmd: List[str]) -> str:
    """Generic helper for git commands."""
    rv, out, err = utils.run(cmd)
    return out if not rv else ''


def get_gitwdir(path: str) -> str:
    """Return git working directory for specified path."""
    return _helper(['git', '-C', path, 'rev-parse', '--show-toplevel'])


def get_gitdir(path: str) -> str:
    """Return git directory for specified path. It may be outside git working
    tree if gitfile is present. This is particularly true for submodules."""
    return _helper(['git', '-C', path, 'rev-parse', '--absolute-git-dir'])


def get_gitpath(path: str) -> str:
    """Resolve path within gitdir."""
    return _helper(['git', 'rev-parse', '--git-path', path])


def submodule_foreach_enum(git_wdir: str, cache: Dict[str,List[Dict[str,str]]]={}) -> List[Dict[str,str]]:
    """Return list of dictionaries with info about submodules found in git
    working directory. No recursive search is done and this function needs
    to be called again, with proper git working directory, to get submodules
    for submodule. Information about submodules is cached per git_wdir to
    avoid calling submodule foreach command multiple times.
    """

    # The cache "abuses" how python evaluates default parameter values.
    # https://docs.python.org/3/reference/compound_stmts.html#function-definitions
    # Default parameter values are evaluated from left to right
    # when the function definition is executed
    if git_wdir in cache:
        return cache[git_wdir]

    out = _helper(['git', '-C', git_wdir, 'submodule', '--quiet', 'foreach',
                   'echo "$name,$sm_path,$displaypath,$sha1,$toplevel"'])

    submodules = []
    for line in out.splitlines():
        name, sm_path, displaypath, sha1, toplevel = line.split(',')
        submodule = {}
        submodule['path'] = utils.pjoin(git_wdir, sm_path)
        submodule['git_wdir'] = git_wdir
        submodule['git_dir'] = get_gitdir(git_wdir)
        submodule['name'] = name
        submodule['sm_path'] = sm_path
        submodule['displaypath'] = displaypath
        submodule['sha1'] = sha1
        submodule['toplevel'] = toplevel

        submodules.append(submodule)

    cache[git_wdir] = submodules

    return submodules


class CFGDict(dict):
    """Simple dict wrapper with two modification of the original class.
    1. It never overwrites values, only adds them.
       d = CFGDict()
       d['a'] = 1 # d['a'] now contains value 1
       d['a'] = 2 # d['a'] now contains list [1,2]
    2. The get_value method is same as dict get, except if the key value is list,
       it returns the last list entry. This mimics git-config --get
       d.get_value('a') # returns 2
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get_value(self, key: str, default: Optional[Any]=None) -> Any:
        """As "git-config --get" return only the last value."""
        val = self.get(key, default)
        if isinstance(val, list):
            return val[-1]
        return val

    def __setitem__(self, key: str, value: Optional[Any]) -> None:
        # Set key to value, but if key already exists, create a list
        # and add the old value and the new one into it. Meaning
        # values are always added and never overwritten.
        if key in self:
            if isinstance(self[key], list):
                self[key].append(value)
            else:
                super().__setitem__(key, [self[key], value])
        else:
            super().__setitem__(key, value)


def get_config(fn: str, cache: Dict[str, CFGDict]={}) -> CFGDict:
    """Return git configuration for absolute config file path.

    It uses git-config --list and parses its output into a CFGDict object.
    Each git variable name is a fully qualified variable name and it's used
    as a key in the CFGDict. Please see man 1 git-config for more info.

    For example

        submodule.components/protobuf-c/protobuf-c.path=components/protobuf-c/protobuf-c

    is stored as

        {
           'submodule.components/protobuf-c/protobuf-c.path': 'components/protobuf-c/protobuf-c'
        }

    If variable has multiple values, they are stored in a list.
    """
    # Cache handled via default parameter value. See submodule_foreach_enum()
    if fn in cache:
        return cache[fn]
    out = _helper(['git', 'config', '--list', '--file', fn])
    cfg = CFGDict()
    for line in out.splitlines():
        var, val = line.split('=', maxsplit=1)
        cfg[var] = val

    cache[fn] = cfg
    return cfg


def get_submodule_config(git_wdir: str, name: str) -> CFGDict:
    """Return configuration for submodule specified by name."""
    fn = utils.pjoin(git_wdir, '.gitmodules')
    cfg = get_config(fn)
    prefix = f'submodule.{name}.'
    sub_cfg = CFGDict()
    for var, val in cfg.items():
        if not var.startswith(prefix):
            continue
        var = var[len(prefix):]
        sub_cfg[var] = val

    return sub_cfg


def get_submodules_config(fn: str) -> CFGDict:
    """Return configuration for submodules

    The .gitmodules file is just another git config file. This function
    transforms the generic git config file representation, as returned
    by get_config(), into a format more suitable for work with submodules.
    It skips sections not related to submodules and removes the 'submodule.'
    section part from the fully qualified git config variable. All
    submodule info is stored in the CFGDict instance, where key is submodule
    name/path and value is dict with variable/value info.

    For example
        {
        'submodule.components/bt/controller/lib_esp32.path': 'components/bt/controller/lib_esp32',
        'submodule.components/bt/controller/lib_esp32.sbom-hash': 'd037ec89546fad14b5c4d5456c2e23a71e554966'
        }

    is transformed into

        {
        'components/bt/controller/lib_esp32': {
            'path': 'components/bt/controller/lib_esp32',
            'sbom-hash': 'd037ec89546fad14b5c4d5456c2e23a71e554966'
            }
        }
    """
    cfg = get_config(fn)
    prefix = f'submodule.'
    sub_cfg = CFGDict()
    for var, val in cfg.items():
        if not var.startswith(prefix):
            continue
        var = var[len(prefix):]
        splitted = var.rsplit('.', maxsplit=1)
        if len(splitted) != 2:
            continue
        module_name, var = splitted
        if module_name not in sub_cfg:
            sub_cfg[module_name] = {}
        sub_cfg[module_name][var] = val

    return sub_cfg


def get_tree_sha(fullpath: str) -> Optional[str]:
    """Return object's SHA from git-tree at fullpath"""
    gitwdir = get_gitwdir(fullpath)
    if not gitwdir:
        # The fullpath is not within a git tree, so there
        # no point of trying to find out the tree object SHA.
        return None
    relpath = utils.prelpath(fullpath, gitwdir)
    if relpath == '.':
        # If fullpath is a git root directory, it's most probably
        # a git submodule. We are interested in the submodule hash
        # as recorded in superproject, not in the hash on which
        # the submodule is checked out in working tree. So this
        # tries to run the ls-tree command on fullpath parent git.
        relpath = os.path.basename(gitwdir)
        gitwdir = os.path.dirname(gitwdir)

    output = _helper(['git', '-C', gitwdir, 'ls-tree', 'HEAD', relpath])

    if not output:
        return None
    return output.split()[2]


def get_branch(git_wdir: str) -> str:
    """Return current branch."""
    return _helper(['git', '-C', git_wdir, 'branch', '--show-current'])


def get_head(git_wdir: str) -> str:
    """Return HEAD full sha."""
    return _helper(['git', '-C', git_wdir, 'rev-parse', 'HEAD'])


def describe(path: str) -> str:
    """Return git describe info."""
    return _helper(['git', '-C', path, 'describe'])


def get_remote_url(path: str) -> str:
    """Return remote URL for specified path."""
    git_dir = get_gitdir(path)
    url: str = ''
    if not git_dir:
        return ''

    cfg = get_config(utils.pjoin(git_dir, 'config'))
    branch = get_branch(git_dir)
    remote = cfg.get_value(f'branch.{branch}.remote', 'origin')
    url = cfg.get_value(f'remote.{remote}.url', '')

    if not utils.is_remote_url(url):
        # ignore local repository url and URLs not using git, http or https scheme
        return ''

    return url


def get_remote_location(path: str) -> str:
    """Return remote <URL>@<HEAD sha>#<relative path> for path."""
    url = get_remote_url(path)
    if not url:
        return ''

    git_wdir = get_gitwdir(path)
    head = get_head(git_wdir)
    if head:
        url += f'@{head}'

    if path == git_wdir:
        return url

    url += '#' + utils.prelpath(path, git_wdir)

    return url
