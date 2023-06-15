# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Simple module for git interaction.
"""

from typing import Dict, List

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


def get_config(fn: str, cache: Dict[str, Dict[str,str]]={}) -> Dict[str,str]:
    """Return git configuration for absolute config file path."""
    # Cache handled via default parameter value. See submodule_foreach_enum()
    if fn in cache:
        return cache[fn]
    out = _helper(['git', 'config', '--list', '--file', fn])
    cfg = {}
    for line in out.splitlines():
        var, val = line.split('=', maxsplit=1)
        cfg[var] = val
    cache[fn] = cfg
    return cfg


def get_submodule_config(git_wdir: str, name: str) -> Dict[str,str]:
    """Return configuration for submodule specified by name."""
    fn = utils.pjoin(git_wdir, '.gitmodules')
    cfg = get_config(fn)
    prefix = f'submodule.{name}.'
    sub_cfg = {}
    for var, val in cfg.items():
        if not var.startswith(prefix):
            continue
        var = var.removeprefix(prefix)
        sub_cfg[var] = val

    return sub_cfg


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
    if not git_dir:
        return ''

    cfg = get_config(utils.pjoin(git_dir, 'config'))
    branch = get_branch(git_dir)
    remote = cfg.get(f'branch.{branch}.remote', 'origin')
    url = cfg.get(f'remote.{remote}.url', '')

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
