# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import os
import re
import shlex
from typing import Any, Dict, List, Set

import schema
import yaml
from license_expression import ExpressionError, get_spdx_licensing

from esp_idf_sbom.libsbom import git, log, utils

licensing = get_spdx_licensing()


def load(path: str) -> Dict[str,Any]:
    """Load manifest file

    :param path:  Full path to the manifest file.
    :returns:     Manifest dictionary.
    """

    manifest: Dict[str,Any] = {}
    if not os.path.isfile(path):
        return manifest

    try:
        with open(path, 'r') as f:
            return yaml.safe_load(f.read()) or {}
    except (OSError, yaml.parser.ParserError) as e:
        log.err.die(f'Cannot parse manifest file "{path}": {e}')

    return manifest


def get_submodule_manifet(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Transform sbom information specified in .gitmodules into manifest dictionary.

    :param cfg:   Submodule git config dictionary.
    :returns:     Manifest dictionary.
    """
    # Get all sbom keys and strip "sbom-" prefix
    module_sbom = {k[len('sbom-'):]:v for k,v in cfg.items() if k.startswith('sbom-')}

    if 'cve-exclude-list' in module_sbom:
        # Convert cve-exclude-list values from .gitconfig into list of dicts
        # as expected by validate_manifest
        cve_exclude_list = []
        if not isinstance(module_sbom['cve-exclude-list'], list):
            module_sbom['cve-exclude-list'] = [module_sbom['cve-exclude-list']]
        for cve_str in module_sbom['cve-exclude-list']:
            splitted = cve_str.split(maxsplit=1)
            cve_id = ''
            reason = ''
            if len(splitted) == 2:
                cve_id = splitted[0]
                reason = splitted[1]
            elif len(splitted) == 1:
                cve_id = splitted[0]
            cve_exclude_list.append({'cve': cve_id, 'reason': reason})
        module_sbom['cve-exclude-list'] = cve_exclude_list

    if 'manifests' in module_sbom:
        # Convert manifests paths from .gitconfig into list of dicts
        # as expected by validate_manifest
        manifests_paths_list = []
        manifests_paths_str_list = []
        if not isinstance(module_sbom['manifests'], list):
            manifests_paths_str_list = [module_sbom['manifests']]
        else:
            manifests_paths_str_list = module_sbom['manifests']

        for manifest_paths_str in manifests_paths_str_list:
            paths = shlex.split(manifest_paths_str)
            path = ''
            directory = ''
            if len(paths) > 1:
                path = paths[0]
                directory = paths[1]
            elif len(paths) == 1:
                path = paths[0]
            # validate_manifest will report errors if path or directory doesn't exist
            manifests_paths_list.append({'path': path, 'dest': directory})
        module_sbom['manifests'] = manifests_paths_list

    return module_sbom


def get_files(sources: List[str]) -> Dict[str, Set[str]]:
    """Go through sources list and gather all manifest files, including idf_component.yml and .gitmodule files

    :param sources:   List of manifest files and directories.
    :returns:         Dictionary with set of manifest file paths devided by
                      type(sbom.yml, idf_component.yml, .gitmodules)
    """
    manifest_files: Dict[str, Set[str]] = {
        'sbom.yml': set(),
        'idf_component.yml': set(),
        '.gitmodules': set()
    }

    def add_file(path: str) -> None:
        file_name = os.path.basename(path)
        if file_name in manifest_files:
            manifest_files[file_name].add(path)
        else:
            # Referenced manifest files with non-default sbom.yml filename
            manifest_files['sbom.yml'].add(path)

    for source in sources:
        source = utils.presolve(source)
        if os.path.isfile(source):
            add_file(source)
        elif os.path.isdir(source):
            for root, dirs, files in utils.pwalk(source):
                for file in files:
                    if file not in manifest_files.keys():
                        continue
                    add_file(os.path.join(root, file))
        else:
            log.err.die(f'"{source}" is not file nor directory')

    return manifest_files


def get_manifests(sources: List[str]) -> List[Dict[str, Any]]:
    """Go through sources list and gather all manifest. Manifest files are loaded and
    processed for referenced manifests, which are also included.

    :param sources:   List of manifest files and directories.
    :returns:         List of manifest dicts found in sources. Each manifest
                      has _src and _dst key added with information where it comes from
                      and for which directory it's intended.
    """
    manifest_list: List[Dict[str, Any]] = []
    manifest_source_files = get_files(sources)

    manifest_files = [(s, os.path.dirname(s)) for s in manifest_source_files['sbom.yml'] |
                      manifest_source_files['idf_component.yml']]
    while manifest_files:
        manifest_path, manifest_dir = manifest_files.pop()
        manifest_file = os.path.basename(manifest_path)
        manifest = load(manifest_path)
        if manifest_file == 'idf_component.yml':
            # extract the sbom part from idf_component manifest
            manifest = manifest.get('sbom', dict())
        if not manifest:
            continue

        manifest['_src'] = manifest_path
        manifest['_dst'] = manifest_dir
        manifest_list.append(manifest)

        # Add referenced manifests to list for processing
        referenced_manifests = manifest.get('manifests', [])
        for referenced_manifest in referenced_manifests:
            manifest_files.append((utils.pjoin(manifest_dir, referenced_manifest['path']),
                                   utils.pjoin(manifest_dir, referenced_manifest['dest'])))

    # Handle all .gitmodules files
    for submodule_file in manifest_source_files['.gitmodules']:
        submodules = git.get_submodules_config(submodule_file)
        for submodule_name, submodule_info in submodules.items():
            manifest = get_submodule_manifet(submodule_info)
            if not manifest:
                continue
            directory = utils.pjoin(os.path.dirname(submodule_file), submodule_info['path'])
            manifest['_src'] = f'{submodule_file} submodule {submodule_name}'
            manifest['_dst'] = directory
            manifest_list.append(manifest)

    return manifest_list


def validate(manifest: Dict[str,str], source:str, directory:str, die:bool=True) -> None:
    """Validate manifest dictionary

    :param manifest:  Loaded manifest file.
    :param source:    Where the manifest comes from. It may be file or
                      .gitmodules with the submodule name appended.
    :param directory: Component/package directory. For submodule this is path where the
                      submodule is actually placed in git work tree.
    """

    def check_person_organization(s: str) -> bool:
        if s.startswith('Person: ') or s.startswith('Organization: '):
            return True
        raise schema.SchemaError((f'Value "{s}" must have "Person: " or "Organization: " prefix.'))

    def check_url(url: str) -> bool:
        if utils.is_remote_url(url):
            return True
        raise schema.SchemaError((f'Value {url} must have "git", "http" or "https" scheme and domain.'))

    def check_cpe(cpe: str) -> bool:
        # Note: WFN, well-formed CPE name, attributes rules are stricter
        if re.match(r'^cpe:2\.3:[aho](?::\S+){10}', cpe):
            return True
        raise schema.SchemaError((f'Value "{cpe}" does not seem to be well-formed CPE name (WFN)'))

    def check_license(lic: str) -> bool:
        try:
            licensing.parse(lic, validate=True)
        except ExpressionError as e:
            raise schema.SchemaError((f'License expression "{lic}" is not valid: {e}'))
        return True

    def check_manifest_path(path:str) -> bool:
        fullpath = utils.pjoin(directory, path)
        if os.path.isfile(fullpath):
            return True
        raise schema.SchemaError((f'Referenced manifest file "{fullpath}" does not exist or is not a file'))

    def check_manifest_destination(dest:str) -> bool:
        fullpath = utils.pjoin(directory, dest)
        if os.path.isdir(fullpath):
            return True
        raise schema.SchemaError((f'Destination manifest directory "{fullpath}" does not exist or is not a directory'))

    def check_hash(sha:str) -> bool:
        git_sha = git.get_tree_sha(directory)
        msg = (f'Manifest in  \"{source}\" contains SHA \"{sha}\", which does not '
               f'match SHA \"{git_sha}\" recorded in git-tree for directory "{directory}". '
               f'Please update \"hash\" in \"{source}\" manifest '
               f'and also please do not forget to update version and other '
               f'information if necessary. It is important to keep this information '
               f'up-to-date for SBOM generation.')
        if sha == git_sha:
            return True
        raise schema.SchemaError(msg)

    cve_exclude_list_schema = schema.Schema(
        [{
            'cve': str,
            'reason': str,
        }], ignore_extra_keys=True)

    manifests_schema = schema.Schema(
        [{
            'path': schema.And(str, check_manifest_path),
            'dest': schema.And(str, check_manifest_destination),
        }], ignore_extra_keys=True)

    sbom_schema = schema.Schema(
        {
            schema.Optional('name'): str,
            schema.Optional('version'): schema.Or(str,float,int),
            schema.Optional('repository'): schema.And(str, check_url),
            schema.Optional('url'): schema.And(str, check_url),
            schema.Optional('cpe'): schema.And(str, check_cpe),
            schema.Optional('supplier'): schema.And(str, check_person_organization),
            schema.Optional('originator'): schema.And(str, check_person_organization),
            schema.Optional('description'): str,
            schema.Optional('license'): schema.And(str, check_license),
            schema.Optional('hash'): schema.And(str, check_hash),
            schema.Optional('cve-exclude-list'): cve_exclude_list_schema,
            schema.Optional('manifests'): manifests_schema,
        }, ignore_extra_keys=True)

    try:
        sbom_schema.validate(manifest)
    except schema.SchemaError as e:
        msg = f'Manifest in "{source}" for "{directory}" is not valid: {e}'
        if die:
            log.err.die(msg)
        raise RuntimeError(msg)
