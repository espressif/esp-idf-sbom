#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
from argparse import Namespace
from typing import Dict, List

import yaml
from rich.console import Console
from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TextColumn,
                           TimeElapsedColumn)

from esp_idf_sbom.libsbom import log, mft, nvd, report, spdx


def cmd_create(args: Namespace) -> int:
    spdx_sbom = spdx.SPDXDocument(args, args.input_file)
    spdx_sbom.write(args.output_file)
    if args.print and args.output_file:
        spdx_sbom.write(force_colors=args.force_colors)
    return 0


def cmd_check(args: Namespace) -> int:
    if args.input_file == '-':
        buf = sys.stdin.read()
    else:
        try:
            with open(args.input_file, 'r') as f:
                buf = f.read()
        except OSError as e:
            sys.exit(f'cannot read SBOM file: {e}')

    record_list: List[Dict[str,str]] = []
    exit_code = 0

    packages = spdx.parse_packages(buf)
    if not args.check_all_packages:
        packages = spdx.filter_packages(packages)

    progress_disabled = args.quiet or args.no_progress
    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=progress_disabled,
        console=Console(stderr=True, no_color=args.no_colors, emoji=False))

    progress.start()

    try:
        progress_task = progress.add_task('Checking pakcages', total=len(packages))
        for pkg in packages.values():
            package_added = False
            progress.update(progress_task,advance=1, refresh=True, description=pkg['PackageName'][0])

            cpes = []
            for cpe_ref in pkg.get('ExternalRef', []):
                if not cpe_ref.startswith('SECURITY cpe23Type'):
                    continue
                _, _, cpe = cpe_ref.split()
                cpes.append(cpe)

            # Possible improvement if package does not explicitly specify CPE could be to use
            # cpeMatchString parameter(https://nvd.nist.gov/developers/products) and find possible
            # CPEs based on package name and version.

            cve_exclude_list = {}
            if 'PackageComment' in pkg:
                # get information about excluded CVEs
                comment = pkg['PackageComment'][0]
                comment = comment[len('<text>'):-len('</text>')]
                comment_yaml = yaml.safe_load(comment)
                cve_exclude_list = {cve['cve']: cve['reason'] for cve in comment_yaml['cve-exclude-list']}

            for cpe in cpes:
                try:
                    vulns = nvd.check(cpe, not progress_disabled)
                except RuntimeError as e:
                    progress.stop()
                    log.err.die(f'{e}')
                for vuln in vulns:
                    cve_id = vuln['cve']['id']
                    cve_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                    cve_desc = [desc['value'] for desc in vuln['cve']['descriptions'] if desc['lang'] == 'en'][0]
                    vulnerable = ''
                    exclude_reason = ''
                    cvss_version = ''
                    cvss_vector_string = ''
                    cvss_base_score = ''
                    cvss_base_severity = ''

                    metrics = vuln['cve'].get('metrics')
                    cvss = None
                    if metrics:
                        # get the first CVSS
                        first_cvss = next(iter(metrics), None)
                        cvss = metrics[first_cvss][0] if first_cvss else None

                    if cvss:
                        cvss_version = cvss['cvssData'].get('version', '')
                        cvss_vector_string = cvss['cvssData'].get('vectorString', '')
                        cvss_base_score = str(cvss['cvssData'].get('baseScore', ''))
                        cvss_base_severity = cvss['cvssData'].get('baseSeverity', cvss.get('baseSeverity', ''))

                    if cve_id in cve_exclude_list:
                        exclude_reason = cve_exclude_list[cve_id]
                        vulnerable = 'EXCLUDED'
                    else:
                        vulnerable = 'YES'
                        exit_code = 1

                    record = report.empty_record.copy()
                    record['pkg_name'] = pkg['PackageName'][0]
                    record['pkg_version'] = pkg['PackageVersion'][0] if 'PackageVersion' in pkg else ''
                    record['vulnerable'] = vulnerable
                    record['exclude_reason'] = exclude_reason
                    record['cve_id'] = cve_id
                    record['cve_link'] = cve_link
                    record['cve_desc'] = cve_desc
                    record['cpe'] = cpe
                    record['cvss_version'] = cvss_version
                    record['cvss_vector_string'] = cvss_vector_string
                    record['cvss_base_score'] = cvss_base_score
                    record['cvss_base_severity'] = cvss_base_severity
                    record_list.append(record)
                    package_added = True

            if not package_added:
                # No vulnerabilities found for given package
                record = report.empty_record.copy()
                record['pkg_name'] = pkg['PackageName'][0]
                record['pkg_version'] = pkg['PackageVersion'][0] if 'PackageVersion' in pkg else ''
                if not cpes:
                    # no CPE record, the package was not checked against NVD
                    record['vulnerable'] = 'SKIPPED'
                else:
                    # CPE record used to check package against NVD
                    record['vulnerable'] = 'NO'
                    record['cpe'] = ', '.join(cpes)
                record_list.append(record)

    except KeyboardInterrupt:
        progress.stop()
        log.err.die('Process terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()

    # Project package is the first one
    project_pkg = packages[next(iter(packages))]
    proj_name = project_pkg['PackageName'][0]
    proj_ver = project_pkg['PackageVersion'][0]
    report.show(record_list, args, proj_name, proj_ver)

    return exit_code


def cmd_manifest_validate(args: Namespace) -> int:
    progress_disabled = args.quiet or args.no_progress
    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=progress_disabled,
        console=Console(stderr=True, no_color=args.no_colors, emoji=False))

    progress.start()
    try:
        progress_task = progress.add_task('Validating manifests')
        progress.update(progress_task, refresh=True, description='searching for manifest files')

        manifests = mft.get_manifests(args.validate_paths)
        progress.update(progress_task, advance=0, refresh=True, total=len(manifests))

        for manifest in manifests:
            progress.update(progress_task, advance=1, refresh=True, description=manifest['_src'])
            mft.validate(manifest, manifest['_src'], manifest['_dst'], die=False)

    except RuntimeError as e:
        progress.stop()
        log.err.die(str(e))
    except KeyboardInterrupt:
        progress.stop()
        log.err.die('Process terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()

    return 0


def cmd_manifest_check(args: Namespace) -> int:
    record_list: List[Dict[str,str]] = []
    exit_code = 0

    progress_disabled = args.quiet or args.no_progress
    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=progress_disabled,
        console=Console(stderr=True, no_color=args.no_colors, emoji=False))

    progress.start()
    try:
        progress_task = progress.add_task('Checking manifest files for vulnerabilities')
        progress.update(progress_task, refresh=True, description='searching for manifest files')

        manifests = mft.get_manifests(args.check_paths)
        progress.update(progress_task, advance=0, refresh=True, total=len(manifests))

        for manifest in manifests:
            package_added = False
            progress.update(progress_task, advance=1, refresh=True, description=manifest['_src'])
            if 'cpe' not in manifest:
                continue

            cpes = manifest['cpe'] if isinstance(manifest['cpe'], list) else [manifest['cpe']]
            # Add version to CPEs
            version = manifest.get('version', '')
            cpes = [cpe.format(version) for cpe in cpes]
            name = manifest.get('name', manifest['cpe'].split(':')[4])
            cve_exclude_list = {cve['cve']: cve['reason'] for cve in manifest.get('cve-exclude-list', [])}
            for cpe in cpes:
                vulns = nvd.check(cpe, not progress_disabled)

                for vuln in vulns:
                    cve_id = vuln['cve']['id']
                    cve_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                    cve_desc = [desc['value'] for desc in vuln['cve']['descriptions'] if desc['lang'] == 'en'][0]
                    vulnerable = ''
                    exclude_reason = ''
                    cvss_version = ''
                    cvss_vector_string = ''
                    cvss_base_score = ''
                    cvss_base_severity = ''

                    metrics = vuln['cve'].get('metrics')
                    cvss = None
                    if metrics:
                        # get the first CVSS
                        first_cvss = next(iter(metrics), None)
                        cvss = metrics[first_cvss][0] if first_cvss else None

                    if cvss:
                        cvss_version = cvss['cvssData'].get('version', '')
                        cvss_vector_string = cvss['cvssData'].get('vectorString', '')
                        cvss_base_score = str(cvss['cvssData'].get('baseScore', ''))
                        cvss_base_severity = cvss['cvssData'].get('baseSeverity', cvss.get('baseSeverity', ''))

                    if cve_id in cve_exclude_list:
                        exclude_reason = cve_exclude_list[cve_id]
                        vulnerable = 'EXCLUDED'
                    else:
                        vulnerable = 'YES'
                        exit_code = 1

                    record = report.empty_record.copy()
                    record['pkg_name'] = name
                    record['pkg_version'] = version
                    record['vulnerable'] = vulnerable
                    record['exclude_reason'] = exclude_reason
                    record['cve_id'] = cve_id
                    record['cve_link'] = cve_link
                    record['cve_desc'] = cve_desc
                    record['cpe'] = cpe
                    record['cvss_version'] = cvss_version
                    record['cvss_vector_string'] = cvss_vector_string
                    record['cvss_base_score'] = cvss_base_score
                    record['cvss_base_severity'] = cvss_base_severity
                    record_list.append(record)
                    package_added = True

            if not package_added:
                # No vulnerabilities found for given package
                record = report.empty_record.copy()
                record['pkg_name'] = name
                record['pkg_version'] = version
                record['vulnerable'] = 'NO'
                record['cpe'] = ', '.join(cpes)
                record_list.append(record)

    except RuntimeError as e:
        progress.stop()
        log.err.die(str(e))
    except KeyboardInterrupt:
        progress.stop()
        log.err.die('Process terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()
    report.show(record_list, args)

    return exit_code


def main():
    parser = argparse.ArgumentParser(prog='esp-idf-sbom', description='ESP-IDF SBOM tool')
    parser.add_argument('-q', '--quiet',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_QUIET')),
                        help=('By default auxiliary messages like errors, warnings, debug messages '
                              'or progress are reported to the standard error stream. With this option '
                              'set, all such messages are suppressed.'))
    parser.add_argument('-n', '--no-colors',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_NO_COLORS')),
                        help=('Do not emit color codes. By default color codes are used when stdout '
                              'or stderr is connected to a terminal.'))
    parser.add_argument('-f', '--force-colors',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_FORCE_COLORS')),
                        help=('Emit color codes even when stdout or stderr '
                              'is not connected to a terminal.'))
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_VERBOSE')),
                        help=('Be verbose. Messages are printed to standard error output.'))
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_DEBUG')),
                        help=('Print debug information. Messages are printed to standard error output.'))

    parser.add_argument('--no-progress',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_CHECK_NO_PROGRESS')),
                        help=('Disable progress bar.'))

    subparsers = parser.add_subparsers(help='sub-command help')

    create_parser = subparsers.add_parser('create',
                                          help=('Create SBOM file based on the ESP-IDF '
                                                'project_description.json file.'))

    create_parser.set_defaults(func=cmd_create)
    create_parser.add_argument('input_file',
                               metavar='PROJECT_DESCRIPTION',
                               help=('Path to the project_description.json file generated '
                                     'by the ESP-IDF sbom tool.'))
    create_parser.add_argument('-o', '--output-file',
                               metavar='SBOM_FILE',
                               default=None,
                               help='Output SBOM file. Default is stdout.')
    create_parser.add_argument('--rem-config',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_REM_CONFIG')),
                               help='Remove configuration only components.')
    create_parser.add_argument('--add-config-deps',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_ADD_CONFIG_DEPS')),
                               help=('Add dependencies on configuration only components.'))
    create_parser.add_argument('--rem-unused',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_REM_UNUSED')),
                               help=('Remove components not linked into the final binary.'))
    create_parser.add_argument('--add-unused-deps',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_ADD_UNUSED_DEPS')),
                               help=('Add dependencies on components not linked '
                                     'into the final binary.'))
    create_parser.add_argument('--rem-submodules',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_REM_SUBMODULES')),
                               help=('Remove submodules info and include submodules files directly '
                                     'in components. By default submodules are reported as separated '
                                     'packages.'))
    create_parser.add_argument('--rem-subpackages',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_REM_SUBPACKAGES')),
                               help=('Remove subpackages info and include subpackages files directly '
                                     'in components. By default subpackages are reported as separated '
                                     'packages.'))
    create_parser.add_argument('--files',
                               choices=['auto', 'add', 'rem'],
                               default=os.environ.get('SBOM_CREATE_FILES', 'rem'),
                               help=('rem - Exclude all files. This will generate much smaller SBOM file '
                                     'and it is the default value. '
                                     'add - Explicitly add all files for any package. '
                                     'auto - Adds files only if there is no repository or URL and version '
                                     'information available for package.'))
    create_parser.add_argument('--no-guess',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_NO_GUESS')),
                               help=('Don\'t try to identify PackageSupplier and PackageVersion. '
                                     'By default URLs are checked for known suppliers, currently only '
                                     'Espressif Systems, and project version or git describe is used '
                                     'to identify versions. With this option PackageSupplier and '
                                     'PackageVersion will be omitted, unless explicitly stated in '
                                     'sbom.yml, idf_component.yml or .gitmodules.'))
    create_parser.add_argument('-p', '--print',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_PRINT')),
                               help=('Print generated SBOM file to stdout even if "--output-file" is used.'))
    create_parser.add_argument('--file-tags',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_NO_FILE_TAGS')),
                               help=('Scan files for SPDX file tags. This includes SPDX-License-Identifier, '
                                     'SPDX-FileCopyrightText and SPDX-FileContributor'))

    check_parser = subparsers.add_parser('check',
                                         help=('Check components/submodules in the ESP-IDF SBOM file '
                                               'for possible vulnerabilities reported in the '
                                               'National Vulnerability Database.'))
    check_parser.set_defaults(func=cmd_check)
    check_parser.add_argument('input_file',
                              metavar='SBOM_FILE',
                              default='-',
                              nargs='?',
                              help=('Path to the SBOM file generated by the ESP-IDF sbom tool. '
                                    'If not provided or "-", read from stdin.'))

    check_parser.add_argument('--check-all-packages',
                              action='store_true',
                              default=bool(os.environ.get('SBOM_CHECK_ALL')),
                              help=('Check all packages in the SBOM file. By default only packages, '
                                    'linked via the SPDX relationship to the main project package, '
                                    'are checked. This may report vulnerabilities, which do not '
                                    'affect the resulting binary! For example components with libraries, '
                                    'which are not linked into the final binary will be checked too.'))

    check_parser.add_argument('--format',
                              choices=['table', 'json', 'csv'],
                              default=os.environ.get('SBOM_CHECK_FORMAT', 'table'),
                              help=('table - Print report table. This is default.'
                                    'json - Print report in JSON format. '
                                    'csv - Print report in CSV format.'))

    manifest_parser = subparsers.add_parser('manifest',
                                            help=('Commands operating atop of manifest files.'))
    manifest_subparsers = manifest_parser.add_subparsers(help='sub-command help')

    manifest_validate_parser = manifest_subparsers.add_parser('validate',
                                                              help=('Validate manifest files.'))
    manifest_validate_parser.set_defaults(func=cmd_manifest_validate)
    manifest_validate_parser.add_argument('validate_paths',
                                          metavar='PATH_TO_VALIDATE',
                                          default=[os.path.curdir],
                                          nargs='*',
                                          help=('Manifest file(sbom.yml, idf_manifest.yml or .gitmodules) or '
                                                'directory, which will be searched for manifest files.'))

    manifest_check_parser = manifest_subparsers.add_parser('check',
                                                           help=('Check manifest files for vulnerabilities.'))
    manifest_check_parser.set_defaults(func=cmd_manifest_check)
    manifest_check_parser.add_argument('--format',
                                       choices=['table', 'json', 'csv'],
                                       help=('table - Print report table. This is default.'
                                             'json - Print report in JSON format. '
                                             'csv - Print report in CSV format.'))
    manifest_check_parser.add_argument('check_paths',
                                       metavar='PATH_TO_CHECK',
                                       default=[os.path.curdir],
                                       nargs='*',
                                       help=('Manifest file(sbom.yml, idf_manifest.yml or .gitmodules) or '
                                             'directory, which will be searched for manifest files.'))

    args = parser.parse_args()
    if args.quiet:
        log_level = log.NEVER
    elif args.debug:
        log_level = log.DEBUG
    elif args.verbose:
        log_level = log.INFO
    else:
        log_level = log.WARN

    log.err.config(not args.no_colors, log_level, args.force_colors)
    log.out.config(not args.no_colors, log.ALWAYS, args.force_colors)

    env = {key: value for key, value in os.environ.items() if key.startswith('SBOM_')}
    log.err.debug(f'environ: {env}')
    log.err.debug(f'args: {args}')

    return args.func(args)


if __name__ == '__main__':
    main()
