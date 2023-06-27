#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import textwrap
from argparse import Namespace

from esp_idf_sbom.libsbom import log, nvd, spdx


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

    table = []
    packages = spdx.parse_packages(buf)
    if not args.check_all_packages:
        packages = spdx.filter_packages(packages)
    for pkg in packages.values():
        if 'ExternalRef' not in pkg:
            continue

        cpe_refs = [ref for ref in pkg['ExternalRef'] if ref.startswith('SECURITY cpe23Type')]
        if not cpe_refs:
            continue

        for cpe_ref in cpe_refs:
            _, _, cpe = cpe_ref.split()
            log.err.info(f'checking {cpe} ... ')
            vulns = nvd.check(cpe)
            for vuln in vulns:
                cve_id = vuln['cve']['id']
                cve_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                cve_desc = [desc['value'] for desc in vuln['cve']['descriptions'] if desc['lang'] == 'en'][0]
                table.append((cpe, pkg['SPDXID'][0], pkg['PackageName'][0], cve_id, cve_link, cve_desc))

    if not table:
        log.out.green('No vulnerabilities found')
        return 0

    log.out.yellow('Following vulnerabilities were found. Further analysis may be required for confirmation.')

    for entry in table:
        cpe, spdxid, pkg_name, cve_id, cve_link, cve_desc = entry
        cve_desc = textwrap.fill(cve_desc)
        fmt = f'''\
CVEID:   {log.out.RED}{cve_id}{log.out.RESET}
CPE:     {cpe}
DETAIL:  {cve_link}
PACKAGE: {pkg_name}
SPDXID:  {spdxid}
{log.out.BLUE}{cve_desc}{log.out.RESET}
'''
        log.out.echo(fmt)

    return 1


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

    args = parser.parse_args()
    if args.quiet:
        log_level = log.NEVER
    if args.debug:
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
