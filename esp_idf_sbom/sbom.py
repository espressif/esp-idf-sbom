#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import argparse
import datetime
import json
import os
import sys
from argparse import Namespace
from typing import Any, Dict, List

import yaml
from rich.align import Align
from rich.console import Console
from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom import log, nvd, spdx, utils


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

    empty_record = {
        'vulnerable': '',
        'pkg_name': '',
        'pkg_version': '',
        'cve_id': '',
        'cvss_base_score': '',
        'cvss_base_severity': '',
        'cvss_version': '',
        'cvss_vector_string': '',
        'cpe': '',
        'cve_link': '',
        'cve_desc': '',
        'exclude_reason': '',
    }

    record_list: List[Dict[str,str]] = []

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

                    record = empty_record.copy()
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
                record = empty_record.copy()
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
        log.err.die('Process to terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()

    # Sort records based on CVSS base score
    records_sorted = sorted(record_list, key=lambda r: float(r['cvss_base_score'] or 0), reverse=True)
    record_list = [r for r in records_sorted if r['vulnerable'] == 'YES']
    if record_list:
        exit_code = 1
    else:
        exit_code = 0
    record_list += [r for r in records_sorted if r['vulnerable'] == 'EXCLUDED']
    record_list += [r for r in records_sorted if r['vulnerable'] == 'NO']
    record_list += [r for r in records_sorted if r['vulnerable'] == 'SKIPPED']

    # Project package is the first one
    project_pkg = packages[next(iter(packages))]

    # Get summary
    summary: Dict[str, Any] = {
        'date': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'database': 'NATIONAL VULNERABILITY DATABASE (https://nvd.nist.gov)',
        'tool': {
            'name': 'esp-idf-sbom',
            'version': __version__,
            'cmdl': ' '.join('\"' + arg + '\"' if ' ' in arg else arg for arg in sys.argv),
        },
        'project': {
            'name': project_pkg['PackageName'][0],
            'version': project_pkg['PackageVersion'][0],
        },
        'cves_summary': {
            'critical': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'high': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'medium': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'low': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'unknown': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'total_cves_count': 0,
            'packages_count': str(len(packages)),
            'all_cves': [],
            'all_packages': [],
        }
    }

    # Add information about CVE into summary
    for r in record_list:
        if r['vulnerable'] != 'YES':
            continue
        summary['cves_summary']['total_cves_count'] += 1
        summary['cves_summary']['all_cves'].append(r['cve_id'])
        if r['pkg_name'] not in summary['cves_summary']['all_packages']:
            summary['cves_summary']['all_packages'].append(r['pkg_name'])
        severity = r['cvss_base_severity'] or 'unknown'
        severity_dict = summary['cves_summary'][severity.lower()]
        severity_dict['count'] += 1
        severity_dict['cves'].append(r['cve_id'])
        if r['pkg_name'] not in severity_dict['packages']:
            severity_dict['packages'].append(r['pkg_name'])

    console = Console(no_color=args.no_colors, emoji=False)

    if args.format == 'json':
        summary['records'] = record_list
        console.print_json(json.dumps(summary))
        sys.exit(exit_code)
    elif args.format == 'csv':
        console.print(','.join(utils.csv_escape(empty_record.keys())))
        for r in record_list:
            console.print(','.join(utils.csv_escape(r.values())))
        sys.exit(exit_code)

    cvss_severity_color_map = {
        'CRITICAL': '[red]',
        'HIGH': '[dark_orange]',
        'MEDIUM': '[yellow]',
        'LOW': '[green]',
        '': ''
    }

    # Table with report summary
    table = Table(title='Report summary', show_header=False)
    table.add_column('key', overflow='fold')
    table.add_column('value', overflow='fold')
    table.add_row('Date:', summary['date']),
    table.add_row('Project name:', summary['project']['name']),
    table.add_row('Project version:', summary['project']['version']),
    table.add_row('Vulnerability database:', summary['database']),
    table.add_row('Generated by tool:', f'{summary["tool"]["name"]} ({summary["tool"]["version"]})'),
    table.add_row('Generated with command:', f'{summary["tool"]["cmdl"]}'),
    table.add_row('Number of scanned packages:', f'{summary["cves_summary"]["packages_count"]}', end_section=True),

    severity_dict = summary['cves_summary']['critical']
    table.add_row('[red]CRITICAL CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[red]Packages affect by CRITICAL CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[red]Number of CRITICAL CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['high']
    table.add_row('[dark_orange]HIGH CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[dark_orange]Packages affect by HIGH CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[dark_orange]Number of HIGH CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['medium']
    table.add_row('[yellow]MEDIUM CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[yellow]Packages affect by MEDIUM CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[yellow]Number of MEDIUM CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['low']
    table.add_row('[green]LOW CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[green]Packages affect by LOW CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[green]Number of LOW CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['unknown']
    table.add_row('UNKNOWN CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('Packages affect by UNKNOWN CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('Number of UNKNOWN CVEs:', str(severity_dict['count']), end_section=True)

    table.add_row('[bright_blue]All CVEs found:', ', '.join(summary['cves_summary']['all_cves']))
    table.add_row('[bright_blue]All packages affect by CVEs:', ', '.join(summary['cves_summary']['all_packages']))
    table.add_row('[bright_blue]Total number of CVEs:', str(summary['cves_summary']['total_cves_count']))

    console.print(Align(table, align='center'), '\n')

    # Table with newly identified vulnerabilities
    table = Table(title='[red]Packages with Identified Vulnerabilities',
                  caption='Newly identified vulnerabilities. Further analysis may be required for confirmation.')
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')
    table.add_column('CVE ID', vertical='middle', justify='center', overflow='fold')
    table.add_column('Base Score', vertical='middle', justify='center', overflow='fold')
    table.add_column('Base Severity', vertical='middle', justify='center', overflow='fold')
    table.add_column('Information', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'YES':
            continue
        info_table = Table(show_edge=False, show_header=False, box=None)
        if any([r['cvss_vector_string'],
               r['cvss_version'],
               r['cpe'],
               r['cve_link'],
               r['cve_desc']]):
            info_table.add_column('key', overflow='fold')
            info_table.add_column('value', overflow='fold')
            info_table.add_row('[yellow]CVSS', r['cvss_version'])
            info_table.add_row(f'[yellow]Vec.', r['cvss_vector_string'])
            info_table.add_row('[yellow]CPE', r['cpe'])
            info_table.add_row('[yellow]Link', r['cve_link'])
            info_table.add_row('[yellow]Desc.', r['cve_desc'])

        table.add_row('[bright_blue]' + r['pkg_name'],
                      r['pkg_version'],
                      cvss_severity_color_map[r['cvss_base_severity']] + r['cve_id'],
                      cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_score'],
                      cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_severity'],
                      info_table,
                      end_section=True)

    if table.row_count:
        console.print(Align(table, align='center'), '\n')

    # Table with vulnerabilities in cve-exclude-list
    table = Table(title='[green]Packages with Excluded Vulnerabilities',
                  caption='Already assessed vulnerabilities that do not apply to packages.')
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')
    table.add_column('CVE ID', vertical='middle', justify='center', overflow='fold')
    table.add_column('Base Score', vertical='middle', justify='center', overflow='fold')
    table.add_column('Base Severity', vertical='middle', justify='center', overflow='fold')
    table.add_column('Information', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'EXCLUDED':
            continue
        info_table = Table(show_edge=False, show_header=False, box=None)
        if any([r['cvss_vector_string'],
               r['cvss_version'],
               r['cpe'],
               r['cve_link'],
               r['cve_desc'],
               r['exclude_reason']]):
            info_table.add_column('key', overflow='fold')
            info_table.add_column('value', overflow='fold')
            info_table.add_row('[yellow]CVSS', r['cvss_version'])
            info_table.add_row(f'[yellow]Vec.', r['cvss_vector_string'])
            info_table.add_row('[yellow]CPE', r['cpe'])
            info_table.add_row('[yellow]Link', r['cve_link'])
            info_table.add_row('[yellow]Desc.', r['cve_desc'])
            info_table.add_row('[yellow]Reason', r['exclude_reason'])

        table.add_row('[bright_blue]' + r['pkg_name'],
                      r['pkg_version'],
                      cvss_severity_color_map[r['cvss_base_severity']] + r['cve_id'],
                      cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_score'],
                      cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_severity'],
                      info_table,
                      end_section=True)

    if table.row_count:
        console.print(Align(table, align='center'), '\n')

    # Table with packages which were scanned and no vulnerability was found
    table = Table(title='[green]Packages with No Identified Vulnerabilities',
                  caption='Packages checked against NVD with no vulnerabilities found.')
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')
    table.add_column('CPE', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'NO':
            continue
        table.add_row('[bright_blue]' + r['pkg_name'],
                      r['pkg_version'],
                      '[yellow]' + r['cpe'],
                      end_section=True)

    if table.row_count:
        console.print(Align(table, align='center'), '\n')

    # Table with packages which were not scanned because of missing CPE
    table = Table(title='[green]Packages without CPE Information',
                  caption='Packages not checked against NVD.')
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'SKIPPED':
            continue
        table.add_row('[bright_blue]' + r['pkg_name'],
                      r['pkg_version'],
                      end_section=True)

    if table.row_count:
        console.print(Align(table, align='center'))

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
                               default=os.environ.get('SBOM_CREATE_FILES', 'auto'),
                               help=('rem - Exclude all files. This will generate much smaller SBOM file. '
                                     'add - Explicitly add all files for any package. '
                                     'auto - This is default value and it adds files only if there is no '
                                     'repository or URL and version information available for package.'))
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
    create_parser.add_argument('--no-file-tags',
                               dest='file_tags',
                               action='store_false',
                               default=not bool(os.environ.get('SBOM_CREATE_NO_FILE_TAGS')),
                               help=('Do not scan files for SPDX file tags. This includes SPDX-License-Identifier, '
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

    check_parser.add_argument('--no-progress',
                              action='store_true',
                              default=bool(os.environ.get('SBOM_CHECK_NO_PROGRESS')),
                              help=('Disable progress bar.'))
    check_parser.add_argument('--format',
                              choices=['table', 'json', 'csv'],
                              default=os.environ.get('SBOM_CHECK_FORMAT', 'table'),
                              help=('table - Print report table. This is default.'
                                    'json - Print report in JSON format. '
                                    'csv - Print report in CSV format.'))

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
