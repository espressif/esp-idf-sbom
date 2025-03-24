# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import os
import shlex
from typing import Any, Dict, List, Set

import schema
import yaml
from license_expression import ExpressionError, get_spdx_licensing

from esp_idf_sbom.libsbom import CPE, expr, git, log, utils

licensing = get_spdx_licensing()


def fix(manifest: Dict[str, Any]) -> None:
    """Fix manifest keys, e.g. convert string entries to list."""

    # Convert cpe into a list
    if 'cpe' in manifest and type(manifest['cpe']) is not list:
        manifest['cpe'] = [manifest['cpe']]

    # Convert copyrights into a list
    if 'copyright' in manifest and type(manifest['copyright']) is not list:
        manifest['copyright'] = [manifest['copyright']]

    # Convert virtpackages into a list
    if 'virtpackages' in manifest and type(manifest['virtpackages']) is not list:
        manifest['virtpackages'] = [manifest['virtpackages']]

    # Convert cve-keywords into a list
    if 'cve-keywords' in manifest and type(manifest['cve-keywords']) is not list:
        manifest['cve-keywords'] = [manifest['cve-keywords']]

    if 'cpe' in manifest:
        # Expand cpes with version value
        ver = manifest.get('version', '')
        cpes_expanded = [cpe.format(ver) for cpe in manifest['cpe']]
        manifest['cpe'] = cpes_expanded


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
            manifest = yaml.safe_load(f.read()) or {}
    except (OSError, yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
        raise RuntimeError(f'Cannot parse manifest file "{path}": {e}')

    fix(manifest)

    return manifest


def get_submodule_manifest(cfg: Dict[str, Any]) -> Dict[str, Any]:
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

    fix(module_sbom)
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
            raise RuntimeError(f'"{source}" is not file nor directory')

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
    manifest_sources: List = []
    manifest_source_files = get_files(sources)

    manifest_sources = [(s, os.path.dirname(s)) for s in manifest_source_files['sbom.yml'] |
                        manifest_source_files['idf_component.yml']]
    while manifest_sources:
        manifest_source, manifest_dir = manifest_sources.pop(0)
        if isinstance(manifest_source, str):
            # Manifest source is in a file.
            manifest_path = manifest_source
            manifest_file = os.path.basename(manifest_path)
            manifest = load(manifest_path)
            if manifest_file == 'idf_component.yml':
                # extract the sbom part from idf_component manifest
                manifest = manifest.get('sbom', dict())
            if not manifest:
                continue
        else:
            # Manifest source is embedded dictionary.
            manifest_path = manifest_source[0]
            manifest = manifest_source[1]

        manifest['_src'] = manifest_path
        manifest['_dst'] = manifest_dir
        manifest_list.append(manifest)

        # Add referenced manifests to list for processing
        referenced_manifests = manifest.get('manifests', [])
        for cnt, referenced_manifest in enumerate(referenced_manifests):
            if not referenced_manifest.get('dest'):
                raise RuntimeError(f'Referenced manifest {cnt} in "{manifest_path}" is missing "dest" entry')

            if referenced_manifest.get('path'):
                # Referenced manifest is in file.
                manifest_sources.append((utils.pjoin(manifest_dir, referenced_manifest['path']),
                                         utils.pjoin(manifest_dir, referenced_manifest['dest'])))
            elif referenced_manifest.get('manifest'):
                # Referenced manifest is embedded.
                manifest_sources.append(((f'{manifest_path} in embedded manifest {cnt}', referenced_manifest['manifest']),
                                         utils.pjoin(manifest_dir, referenced_manifest['dest'])))
            else:
                raise RuntimeError((f'Referenced manifest {cnt} in "{manifest_path}" is '
                                    f'missing "path" or "manifest" entries'))

    # Handle all .gitmodules files
    for submodule_file in manifest_source_files['.gitmodules']:
        submodules = git.get_submodules_config(submodule_file)
        for submodule_name, submodule_info in submodules.items():
            manifest = get_submodule_manifest(submodule_info)
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

    def check_cpes(cpes: List[str]) -> bool:
        for cpe in cpes:
            if not CPE.is_cpe_valid(cpe):
                raise schema.SchemaError((f'Value "{cpe}" does not seem to be well-formed CPE string binding'))
        return True

    def check_license(lic: str) -> bool:
        try:
            licensing.parse(lic, validate=True)
        except ExpressionError as e:
            raise schema.SchemaError((f'License expression "{lic}" is not valid: {e}'))
        return True

    def check_manifest(data: dict) -> bool:
        if 'path' in data and 'manifest' in data:
            raise schema.SchemaError((f'Both "path" and "manifest" keys specified for "manifest" entry'))

        if 'path' not in data and 'manifest' not in data:
            raise schema.SchemaError((f'Missing "path" or "manifest" key for "manifests" entry'))

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
        if git_sha is None:
            # Even though the manifest contains hash variable, it may happen
            # that it's no longer part of git. For example the component might
            # have been exported or simply copied out of the git tree.
            # This is the case for managed components. Since there is no git information
            # available, we just skip this check.
            return True
        msg = (f'Manifest in \"{source}\" contains SHA \"{sha}\", which does not '
               f'match SHA \"{git_sha}\" recorded in git-tree for directory "{directory}". '
               f'Please update \"hash\" in \"{source}\" manifest '
               f'and also please do not forget to update version and other '
               f'information if necessary. It is important to keep this information '
               f'up-to-date for SBOM generation.')
        if sha == git_sha:
            return True
        raise schema.SchemaError(msg)

    def check_virtpackages(pkgs: List[str]) -> bool:
        for pkg in pkgs:
            check_manifest_path(pkg)
        return True

    def check_if(expression: str) -> bool:
        try:
            expr.evaluate(expression)
        except RuntimeError as e:
            raise schema.SchemaError((f'Expression "{expression}" is not valid: {e}'))
        return True

    cve_exclude_list_schema = schema.Schema(
        [{
            'cve': str,
            'reason': str,
        }], ignore_extra_keys=True)

    manifest_entry_schema = schema.Schema(schema.And(
        {
            schema.Optional('path'): schema.And(str, check_manifest_path),
            schema.Optional('manifest'): dict,
            'dest': schema.And(str, check_manifest_destination),
        },
        check_manifest,
        ignore_extra_keys=True))

    manifests_schema = schema.Schema(
        [manifest_entry_schema], ignore_extra_keys=True)

    sbom_schema = schema.Schema(
        {
            schema.Optional('name'): str,
            schema.Optional('version'): schema.Or(str,float,int),
            schema.Optional('repository'): schema.And(str, check_url),
            schema.Optional('url'): schema.And(str, check_url),
            schema.Optional('cpe'): schema.And(list, check_cpes),
            schema.Optional('supplier'): schema.And(str, check_person_organization),
            schema.Optional('originator'): schema.And(str, check_person_organization),
            schema.Optional('description'): str,
            schema.Optional('license'): schema.And(str, check_license),
            schema.Optional('copyright'): list,
            schema.Optional('hash'): schema.And(str, check_hash),
            schema.Optional('cve-exclude-list'): cve_exclude_list_schema,
            schema.Optional('cve-keywords'): list,
            schema.Optional('manifests'): manifests_schema,
            schema.Optional('virtpackages'): schema.And(list, check_virtpackages),
            schema.Optional('if'): schema.And(str, check_if),
        }, ignore_extra_keys=True)

    try:
        sbom_schema.validate(manifest)
    except schema.SchemaError as e:
        msg = f'Manifest in "{source}" for "{directory}" is not valid: {e}'
        if die:
            log.die(msg)
        raise RuntimeError(msg)
