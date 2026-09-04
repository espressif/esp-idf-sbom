# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import json
import os
import sys
from pathlib import Path
from subprocess import CalledProcessError
from subprocess import run
from typing import Any

import click
from esp_pylib.logger import log
from idf_py_actions.errors import FatalError
from idf_py_actions.tools import PropertyDict


def get_proj_desc(proj_desc_path: Path) -> dict:
    proj_desc: dict

    try:
        with open(proj_desc_path) as f:
            proj_desc = json.load(f)
    except (OSError, ValueError) as e:
        raise FatalError(f'cannot read project description file: {e}')

    return proj_desc


def get_proj_desc_path(args: PropertyDict) -> Path:
    return Path(args.build_dir) / 'project_description.json'


def action_extensions(base_actions: dict, project_path: str) -> dict:
    def sbom_create(
        subcommand_name: str,
        ctx: click.Context,
        args: PropertyDict,
        sbom_file: str,
        sbom_format: str,
        vex: str,
        vex_output: str,
        **action_args: Any,
    ) -> None:
        # Imported here and not at module level, so that idf.py startup stays
        # light; the format tables pull in the render backends.
        from esp_idf_sbom.libsbom.formats import SBOM_FORMATS
        from esp_idf_sbom.libsbom.formats import VEX_FORMATS
        from esp_idf_sbom.libsbom.formats import VEX_IN_SBOM

        fmt = SBOM_FORMATS.get(sbom_format)
        if fmt is None:
            raise FatalError(f'unknown SBOM format "{sbom_format}"; choose from: {", ".join(SBOM_FORMATS)}')

        # None for embed and none, which write no separate file.
        vexfmt = VEX_FORMATS.get(vex)
        if vexfmt is None and vex not in VEX_IN_SBOM:
            choices = ', '.join(list(VEX_IN_SBOM) + list(VEX_FORMATS))
            raise FatalError(f'unknown --vex value "{vex}"; choose from: {choices}')

        proj_desc_path = get_proj_desc_path(args)
        proj_desc = get_proj_desc(proj_desc_path)
        app_bin = proj_desc['app_bin']

        if not sbom_file:
            # Default output: build/<app><ext>, extension matching the format.
            sbom_file = str(Path(args.build_dir) / (Path(app_bin).stem + fmt.ext))

        if vexfmt is not None and not vex_output:
            vex_output = str(Path(args.build_dir) / (Path(app_bin).stem + vexfmt.ext))

        cmd = [
            sys.executable,
            '-m',
            'esp_idf_sbom',
            'create',
            '--format',
            sbom_format,
            '--vex',
            vex,
            '--rem-unused',
            '--rem-config',
            '--output-file',
            str(sbom_file),
        ]

        # Passed on even with embed and none, so that esp-idf-sbom reports the
        # combination as an error instead of the option being dropped here.
        if vex_output:
            cmd += ['--vex-output', str(vex_output)]

        cmd.append(str(proj_desc_path))

        try:
            run(cmd, check=True)
        except CalledProcessError as e:
            raise FatalError(f'cannot create SBOM file "{sbom_file}": {e}')

        log.note(f'SBOM for "{app_bin}" created in "{sbom_file}"')
        if vexfmt is not None:
            log.note(f'VEX for "{app_bin}" created in "{vex_output}"')

    def sbom_check(
        subcommand_name: str,
        ctx: click.Context,
        args: PropertyDict,
        sbom_file: str,
        path: str,
        report_file: str,
        output_format: str,
        nvd_api: bool,
        no_sync_db: bool,
        **action_args: Any,
    ) -> None:
        if sbom_file:
            cmd = [sys.executable, '-m', 'esp_idf_sbom', 'check', '--format', output_format]
        else:
            cmd = [sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--format', output_format]

        if report_file:
            cmd += ['--output-file', report_file]

        if not nvd_api:
            cmd += ['--local-db']

        if no_sync_db:
            cmd += ['--no-sync-db']

        if sbom_file:
            cmd += [sbom_file]
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
                'help': 'Create application SBOM in one of the supported formats',
                'options': [
                    {
                        'names': ['--file', '--spdx-file', 'sbom_file'],
                        'help': (
                            'Output SBOM file path. By default the SBOM is created in the '
                            'project build directory, named after the application, with an '
                            'extension matching --format (e.g. .spdx, .spdx.json, .cdx.json). '
                            '--spdx-file is an alias kept for backward compatibility.'
                        ),
                        'type': str,
                    },
                    {
                        'names': ['--format', 'sbom_format'],
                        'help': (
                            'Output SBOM format: spdx-tag-value (default), spdx-json, '
                            'spdx-json-ld or cyclonedx-json. A specific spec version can be '
                            'pinned with an @version suffix (e.g. spdx-json@2.2).'
                        ),
                        'type': str,
                        'default': 'spdx-tag-value',
                    },
                    {
                        'names': ['--vex'],
                        'help': (
                            'What to do with the vulnerability information, meaning the '
                            'excluded CVEs. embed - write it into the SBOM (default). '
                            'none - write no vulnerability information at all. '
                            'openvex or cyclonedx-json - write a separate VEX document and '
                            'leave the SBOM clean. cyclonedx-json links to the SBOM, so it '
                            'needs --format cyclonedx-json.'
                        ),
                        'type': str,
                        'default': os.environ.get('SBOM_CREATE_VEX', 'embed'),
                    },
                    {
                        'names': ['--vex-output', 'vex_output'],
                        'help': (
                            'Output VEX file path. Used only when --vex selects a VEX format. '
                            'By default the VEX is created in the project build directory, '
                            'named after the application, with an extension matching --vex '
                            '(e.g. .openvex.json, .vex.cdx.json).'
                        ),
                        'type': str,
                    },
                ],
                'dependencies': ['app'],
            },
            'sbom-check': {
                'callback': sbom_check,
                'help': ('Check application SBOM file or path with SBOM YAML manifest files for vulnerabilities'),
                'options': [
                    {
                        'names': ['--file', '--spdx-file', 'sbom_file'],
                        'help': (
                            'SBOM file to check. Any format esp-idf-sbom can produce is accepted; '
                            'the format is detected automatically. --spdx-file is an '
                            'alias kept for backward compatibility.'
                        ),
                        'type': str,
                    },
                    {
                        'names': ['--path'],
                        'help': (
                            'Path to recursively search for SBOM YAML manifest files and scan them for vulnerabilities.'
                        ),
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
                        'help': (
                            'Use NVD REST API for vulnerabilities scan. '
                            'By default local NVD database mirror is used. '
                            'This option requires an internet connection, and '
                            'the scan may take longer.'
                        ),
                        'is_flag': True,
                        'default': False,
                    },
                    {
                        'names': ['--no-sync-db'],
                        'help': (
                            'By default, the local NVD database is updated before each scan. '
                            'This option prevents the automatic update, allowing scans to be '
                            'performed without an internet connection.'
                        ),
                        'is_flag': True,
                        'default': False,
                    },
                ],
            },
        },
    }
