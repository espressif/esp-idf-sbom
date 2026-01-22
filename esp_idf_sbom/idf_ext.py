# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import json
import sys
from pathlib import Path
from subprocess import CalledProcessError, run
from typing import Any

import click
from idf_py_actions.errors import FatalError
from idf_py_actions.tools import PropertyDict, yellow_print


def get_proj_desc(proj_desc_path: Path) -> dict:
    proj_desc: dict

    try:
        with open(proj_desc_path, 'r') as f:
            proj_desc = json.load(f)
    except (OSError, ValueError) as e:
        raise FatalError(f'cannot read project description file: {e}')

    return proj_desc


def get_proj_desc_path(args: PropertyDict) -> Path:
    return Path(args.build_dir) / 'project_description.json'


def action_extensions(base_actions: dict, project_path: str) -> dict:
    def sbom_create(subcommand_name: str, ctx: click.Context, args: PropertyDict,
                    spdx_file: str, **action_args: Any) -> None:
        proj_desc_path = get_proj_desc_path(args)
        proj_desc = get_proj_desc(proj_desc_path)
        app_bin = proj_desc['app_bin']

        if not spdx_file:
            spdx_file = (Path(args.build_dir) / app_bin).with_suffix('.spdx')

        cmd = [sys.executable,
               '-m',
               'esp_idf_sbom',
               'create',
               '--rem-unused',
               '--rem-config',
               '--output-file',
               str(spdx_file),
               str(proj_desc_path)]
        try:
            run(cmd, check=True)
        except CalledProcessError as e:
            raise FatalError(f'cannot create SBOM file "{spdx_file}": {e}')

        yellow_print(f'SBOM for "{app_bin}" created in "{spdx_file}"')

    def sbom_check(subcommand_name: str, ctx: click.Context, args: PropertyDict,
                   spdx_file: str, path: str, report_file: str, output_format: str,
                   nvd_api: bool, no_sync_db: bool, **action_args: Any) -> None:

        if spdx_file:
            cmd = [sys.executable, '-m', 'esp_idf_sbom', 'check', '--format', output_format]
        else:
            cmd = [sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--format', output_format]

        if report_file:
            cmd += ['--output-file', report_file]

        if not nvd_api:
            cmd += ['--local-db']

        if no_sync_db:
            cmd += ['--no-sync-db']

        if spdx_file:
            cmd += [spdx_file]
        elif path:
            cmd += [path]
        else:
            # Check the current working directory.
            pass

        try:
            run(cmd, check=True)
        except CalledProcessError as e:
            raise FatalError(f'Vulnerability scan failed: {e}')

    return {
        'version': '1',
        'actions': {
            'sbom-create': {
                'callback': sbom_create,
                'help': 'Create application SBOM in the SPDX format',
                'options': [
                    {
                        'names': ['--spdx-file'],
                        'help': ('The SBOM SPDX file path. The SBOM is by default created '
                                 'in the project build directory and is named after the project, '
                                 'with the filename having a .spdx extension.'),
                        'type': str,
                    }
                ],
                'dependencies': ['app'],
            },
            'sbom-check': {
                'callback': sbom_check,
                'help': ('Check application SBOM SPDX file or path with SBOM YAML '
                         'manifest files for vulnerabilities'),
                'options': [
                    {
                        'names': ['--spdx-file'],
                        'help': ('SBOM file in the SPDX format to check.'),
                        'type': str,
                    },
                    {
                        'names': ['--path'],
                        'help': ('Path to recursively search for SBOM YAML manifest files and '
                                 'scan them for vulnerabilities.'),
                        'type': str,
                    },
                    {
                        'names': ['--report-file'],
                        'help': 'Report output file.',
                        'type': str,
                    },
                    {
                        'names': ['--format', 'output_format'],
                        'help': 'Report format',
                        'type': click.Choice(['table', 'json', 'csv', 'markdown']),
                        'default': 'table',
                    },
                    {
                        'names': ['--nvd-api'],
                        'help': ('Use NVD REST API for vulnerabilities scan. '
                                 'By default local NVD database mirror is used. '
                                 'This option requires an internet connection, and '
                                 'the scan may take longer.'),
                        'is_flag': True,
                        'default': False,
                    },
                    {
                        'names': ['--no-sync-db'],
                        'help': ('By default, the local NVD database is updated before each scan. '
                                 'This option prevents the automatic update, allowing scans to be '
                                 'performed without an internet connection.'),
                        'is_flag': True,
                        'default': False,
                    },
                ],
            },
        },
    }
