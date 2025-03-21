#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os
import sys
from argparse import Namespace
from typing import Any, Dict, List

import yaml
from rich.progress import (BarColumn, MofNCompleteColumn, Progress, TextColumn,
                           TimeElapsedColumn)
from rich.table import Table

from esp_idf_sbom.libsbom import git, log, mft, nvd, report, spdx, utils

NAME_ARG = {
    'args': ['--extended-scan', '-n', '--name'],
    'kwargs': {
        'action': 'store_true',
        'dest': 'name',
        'help': ('If available, use the product part of the CPE and the keywords found '
                 'under the cve-keywords key in the manifest or generated SBOM file to '
                 'search for potential vulnerabilities. This involves scanning CVE '
                 'descriptions for these keywords in CVEs that have not yet been analyzed '
                 'by the NVD. The identified CVEs should be thoroughly examined for false '
                 'positives. Using this option may result in a report that includes CVEs '
                 'unrelated to the scanned components or CVEs that have already been fixed '
                 'in the scanned component versions. Exercise caution when using this option, '
                 'as it can provide early insights into newly reported CVEs but may also '
                 'lead to misleading reports.'),
    }
}


def cmd_create(args: Namespace) -> int:
    spdx_sbom = spdx.SPDXDocument(args, args.input_file)
    log.print(spdx_sbom.dump())
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

    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=args.no_progress,
        console=log.console_stderr)

    try:
        if args.local_db:
            if not args.no_sync_db:
                nvd.sync()
            log.eprint('Searching for possible CVEs in the local database')
            cpes = []
            keywords = []
            for pkg in packages.values():
                for cpe_ref in pkg.get('ExternalRef', []):
                    if not cpe_ref.startswith('SECURITY cpe23Type'):
                        continue
                    _, _, cpe = cpe_ref.split()
                    cpes.append(cpe)
                    if args.name:
                        # Include the product (package name) from the CPE in the keywords
                        keywords.append(cpe.split(':')[4])

                comment = spdx.parse_package_comment(pkg)
                if args.name:
                    # Include keywords from the SPDX Package comment.
                    keywords += comment.get('cve-keywords', [])
            nvd.cache_cves(cpes, keywords)

        progress.start()
        progress_task = progress.add_task('Checking packages', total=len(packages))
        for pkg in packages.values():
            pkg_records: List[Dict[str,str]] = []
            pkg_name = pkg['PackageName'][0]
            pkg_ver = pkg['PackageVersion'][0] if 'PackageVersion' in pkg else ''
            package_added = False

            progress.update(progress_task,advance=1, refresh=True, description=pkg['PackageName'][0])

            cpes = []
            keywords = []
            for cpe_ref in pkg.get('ExternalRef', []):
                if not cpe_ref.startswith('SECURITY cpe23Type'):
                    continue
                _, _, cpe = cpe_ref.split()
                cpes.append(cpe)
                if args.name:
                    # Include the product name from CPE in the keywords to ensure it is searched in the CVE description.
                    product = cpe.split(':')[4]
                    keywords.append(product)

            cve_exclude_list = {}
            comment = spdx.parse_package_comment(pkg)
            if 'cve-exclude-list' in comment:
                # get information about excluded CVEs
                cve_exclude_list = {cve['cve']: cve['reason'] for cve in comment['cve-exclude-list']}
            if args.name:
                keywords += comment.get('cve-keywords', [])

            for cpe in cpes:
                vulns = nvd.check_cpe(cpe, args.local_db)
                for vuln in vulns:
                    record = report.create_vulnerable_record(vuln, cve_exclude_list, cpe, '', pkg_name, pkg_ver)
                    pkg_records.append(record)
                    package_added = True

            if args.name:
                for keyword in keywords:
                    vulns = nvd.check_keyword(keyword, args.local_db)
                    for vuln in vulns:
                        existing_record = report.find_record_by_cve(pkg_records, vuln['cve']['id'])
                        if existing_record:
                            # The same CVE was discovered using different keywords.
                            existing_record['keyword'] += f', {keyword}'
                            continue
                        record = report.create_vulnerable_record(vuln, cve_exclude_list, '', keyword, pkg_name, pkg_ver)
                        pkg_records.append(record)
                        package_added = True

            if not package_added:
                # No vulnerabilities found for given package
                record = report.create_non_vulnerable_record(cpes, keywords, pkg_name, pkg_ver)
                pkg_records.append(record)

            for record in pkg_records:
                if record['vulnerable'] == 'YES':
                    exit_code = 1

            record_list += pkg_records

    except (RuntimeError, OSError) as e:
        progress.stop()
        log.die(str(e))
    except KeyboardInterrupt:
        progress.stop()
        log.die('Process terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()

    # Project package is the first one
    project_pkg = packages[next(iter(packages))]
    proj_name = project_pkg['PackageName'][0]
    proj_ver = project_pkg['PackageVersion'][0]
    report.show(record_list, args, proj_name, proj_ver)

    return exit_code


def cmd_license(args: Namespace) -> int:
    # Set options how the SPDXDocument should be generated.
    # We need to make sure that file_tags is enabled,
    # so licenses and copyrights are collected from the
    # component/package files.
    args.rem_config = True
    args.rem_unused = True
    args.files = 'rem'
    args.no_guess = False
    args.file_tags = True
    args.rem_submodules = False
    args.rem_subpackages = False
    args.add_config_deps = False
    args.add_unused_deps = False
    spdx_sbom = spdx.SPDXDocument(args, args.input_file)

    # The Project SPDX object already contains aggregated
    # licenses and copyrights from packages/components
    # which were linked into the final binary. We can use
    # this information to print an overall report about licenses
    # and copyrights used by the project application.
    tags = spdx_sbom.project.tags
    proj_name = spdx_sbom.project.name
    if args.unify_copyrights:
        copyrights = list(tags.simplify_copyrights(tags.copyrights))
    else:
        copyrights = list(tags.copyrights)
    licenses_merged = tags.licenses_expressions | tags.licenses_expressions_declared
    license_concluded = tags.simplify_licenses(licenses_merged)
    licenses = list(licenses_merged)

    packages = []
    if args.packages:
        for package in spdx_sbom.project.walk_packages():
            if args.unify_copyrights:
                package_copyrights = list(package.tags.simplify_copyrights(package.tags.copyrights))
            else:
                package_copyrights = list(package.tags.copyrights)
            package_licenses_merged = package.tags.licenses_expressions | package.tags.licenses_expressions_declared
            package_license_concluded = tags.simplify_licenses(package_licenses_merged)
            package_licenses = list(package_licenses_merged)

            package_info: Dict[str, Any] = {}
            package_info['name'] = package.name
            package_info['license_concluded'] = package_license_concluded
            package_info['licenses'] = package_licenses
            package_info['copyrights'] = package_copyrights
            packages.append(package_info)

    if args.format == 'json':
        log.print_json(json.dumps(
            {'license_concluded': license_concluded,
             'licenses': licenses,
             'copyrights': copyrights,
             'packages': packages}))
        return 0

    table = Table(title=f'Licenses and copyrights for project {proj_name}', show_header=False)
    table.add_column(overflow='fold')
    table.add_column(overflow='fold')
    table.add_row('License concluded', license_concluded)
    for lic in licenses:
        table.add_row('License', lic)
    for c in copyrights:
        table.add_row('Copyright', c)
    log.print(table, '\n')

    for pkg in packages:
        table = Table(title=f'Licenses and copyrights for package {pkg["name"]}', show_header=False)
        table.add_column(overflow='fold')
        table.add_column(overflow='fold')
        table.add_row('License concluded', pkg['license_concluded'])
        for lic in pkg['licenses']:
            table.add_row('License', lic)
        for c in pkg['copyrights']:
            table.add_row('Copyright', c)
        log.print(table, '\n')

    return 0


def cmd_nvdsync(args: Namespace) -> int:
    return nvd.sync()


def cmd_manifest_validate(args: Namespace) -> int:
    def is_git_rebase_in_progress() -> bool:
        rebase_merge_dir = git.get_gitpath('rebase-merge')
        rebase_apply_dir = git.get_gitpath('rebase-apply')
        if os.path.isdir(rebase_merge_dir) or os.path.isdir(rebase_apply_dir):
            return True

        return False

    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=args.no_progress,
        console=log.console_stderr)

    exit_code = 0
    try:
        if args.skip_on_rebase and is_git_rebase_in_progress():
            log.print('Git rebase is in progress, skipping the check.')
            return exit_code

        progress.start()
        progress_task = progress.add_task('Validating manifests')
        progress.update(progress_task, refresh=True, description='searching for manifest files')

        manifests = mft.get_manifests(args.validate_paths)
        progress.update(progress_task, advance=0, refresh=True, total=len(manifests))

        for manifest in manifests:
            progress.update(progress_task, advance=1, refresh=True, description=manifest['_src'])
            try:
                mft.validate(manifest, manifest['_src'], manifest['_dst'], die=False)
            except RuntimeError as e:
                log.err(str(e))
                exit_code = 1

    except (RuntimeError, OSError) as e:
        progress.stop()
        log.die(str(e))
    except KeyboardInterrupt:
        progress.stop()
        log.die('Process terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()

    return exit_code


def cmd_manifest_check(args: Namespace) -> int:
    record_list: List[Dict[str,str]] = []
    exit_code = 0

    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=args.no_progress,
        console=log.console_stderr)

    try:
        if args.local_db and not args.no_sync_db:
            nvd.sync()

        log.eprint('Searching for manifest files')
        manifests = mft.get_manifests(args.check_paths)

        if args.local_db:
            log.eprint('Searching for possible CVEs in the local database')
            cpes: List[str] = []
            keywords: List[str] = []
            for manifest in manifests:
                if 'cpe' in manifest:
                    cpes += manifest['cpe']
                    if args.name:
                        keywords += [cpe.split(':')[4] for cpe in cpes]
                if args.name:
                    keywords += manifest.get('cve-keywords', [])
            nvd.cache_cves(cpes, keywords)

        progress.start()
        progress_task = progress.add_task('Checking manifest files for vulnerabilities', total=len(manifests))
        for manifest in manifests:
            pkg_records: List[Dict[str,str]] = []
            pkg_name = manifest.get('name')
            pkg_ver = manifest.get('version', '')
            package_added = False

            progress.update(progress_task, advance=1, refresh=True, description=manifest['_src'])

            cpes = []
            keywords = []
            for cpe in manifest.get('cpe', []):
                # Include the version in the CPE, as it might currently only have a placeholder.
                cpe = cpe.format(pkg_ver)
                cpes.append(cpe)
                product = cpe.split(':')[4]
                if args.name:
                    # Include the product name from CPE in the keywords to ensure it is searched in the CVE description.
                    keywords.append(product)
                if not pkg_name:
                    # If the manifest lacks a name, use the product part from the CPE.
                    pkg_name = product

            if not pkg_name:
                # Without a package name or CPE, use the manifest path as the name.
                pkg_name = manifest['_src']

            cve_exclude_list = {cve['cve']: cve['reason'] for cve in manifest.get('cve-exclude-list', [])}
            if args.name:
                keywords += manifest.get('cve-keywords', [])
            for cpe in cpes:
                vulns = nvd.check_cpe(cpe, args.local_db)
                for vuln in vulns:
                    record = report.create_vulnerable_record(vuln, cve_exclude_list, cpe, '', pkg_name, pkg_ver)
                    pkg_records.append(record)
                    package_added = True

            if args.name:
                for keyword in keywords:
                    vulns = nvd.check_keyword(keyword, args.local_db)
                    for vuln in vulns:
                        existing_record = report.find_record_by_cve(pkg_records, vuln['cve']['id'])
                        if existing_record:
                            # The same CVE was discovered using different keywords.
                            existing_record['keyword'] += f', {keyword}'
                            continue
                        record = report.create_vulnerable_record(vuln, cve_exclude_list, '', keyword, pkg_name, pkg_ver)
                        pkg_records.append(record)
                        package_added = True

            if not package_added:
                # No vulnerabilities found for given package
                record = report.create_non_vulnerable_record(cpes, keywords, pkg_name, pkg_ver)
                pkg_records.append(record)

            for record in pkg_records:
                if record['vulnerable'] == 'YES':
                    exit_code = 1

            record_list += pkg_records

    except (RuntimeError, OSError) as e:
        progress.stop()
        log.die(str(e))
    except KeyboardInterrupt:
        progress.stop()
        log.die('Process terminated')

    progress.update(progress_task,advance=0, refresh=True, description='')
    progress.stop()
    report.show(record_list, args)

    return exit_code


def cmd_manifest_license(args: Namespace) -> int:
    progress = Progress(
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn('{task.description}'),
        disable=args.no_progress,
        console=log.console_stderr)

    packages = []
    progress.start()
    try:
        progress_task = progress.add_task('Collecting licenses and copyrights information')
        progress.update(progress_task, refresh=True, description='searching for manifest files')

        manifests = mft.get_manifests(args.license_paths)
        progress.update(progress_task, advance=0, refresh=True, total=len(manifests))
        manifest_paths = [manifest['_dst'] for manifest in manifests]

        for manifest in manifests:
            progress.update(progress_task, advance=1, refresh=True, description=manifest['_src'])

            exclude_dirs = manifest_paths.copy()
            exclude_dirs.remove(manifest['_dst'])

            tags = spdx.SPDXDirTags(manifest['_dst'], exclude_dirs)

            if 'copyright' in manifest:
                # Store copyrights declared in manifest
                tags.copyrights |= set(manifest['copyright'])

            if 'license' in manifest:
                # Store license declared in manifest
                tags.licenses_expressions_declared |= set([manifest['license']])

            if args.unify_copyrights:
                package_copyrights = list(tags.simplify_copyrights(tags.copyrights))
            else:
                package_copyrights = list(tags.copyrights)
            package_licenses_merged = tags.licenses_expressions | tags.licenses_expressions_declared
            package_license_concluded = tags.simplify_licenses(package_licenses_merged)
            package_licenses = list(package_licenses_merged)

            package_info: Dict[str, Any] = {}
            package_info['name'] = manifest['name'] if 'name' in manifest else manifest['_src']
            package_info['license_concluded'] = package_license_concluded
            package_info['licenses'] = package_licenses
            package_info['copyrights'] = package_copyrights
            packages.append(package_info)

        progress.update(progress_task,advance=0, refresh=True, description='')
        progress.stop()

        if args.format == 'json':
            log.print_json(json.dumps(packages))
            return 0

        for pkg in packages:
            table = Table(title=f'Licenses and copyrights for package {pkg["name"]}', show_header=False)
            table.add_column(overflow='fold')
            table.add_column(overflow='fold')
            table.add_row('License concluded', pkg['license_concluded'])
            for lic in pkg['licenses']:
                table.add_row('License', lic)
            for c in pkg['copyrights']:
                table.add_row('Copyright', c)
            log.print(table, '\n')

    except KeyboardInterrupt:
        progress.stop()
        log.die('Process terminated')

    return 0


def cmd_manifest_aggregate(args: Namespace) -> int:
    # Locate all manifest files in the specified path and create a single SBOM
    # manifest file with all manifests expanded.
    try:
        aggregated: Dict = {'manifests': []}
        args.aggregate_path = utils.presolve(args.aggregate_path)
        manifests = mft.get_manifests([args.aggregate_path])
        for manifest in manifests:
            dst = manifest['_dst']
            dst = utils.prelpath(dst, args.aggregate_path)
            # Remove internal manifest entries which are added by the get_manifests function.
            manifest.pop('_dst')
            manifest.pop('_src')
            # Remove the referenced manifests, as they will be provided as standalone
            # expanded manifests by the get_manifests function.
            manifest.pop('manifests', None)
            if not manifest:
                # There is nothing left in the manifest file, because it was just a placeholder
                # for referenced manifests.
                continue
            aggregated['manifests'].append({'manifest': manifest, 'dest': dst})

        if args.output_file:
            with open(args.output_file, 'w') as f:
                yaml.dump(aggregated, f)

        else:
            log.print(yaml.dump(aggregated))

    except (RuntimeError, OSError) as e:
        log.die(str(e))
    except KeyboardInterrupt:
        log.die('Process terminated')

    return 0


def main():
    parser = argparse.ArgumentParser(prog='esp-idf-sbom', description='ESP-IDF SBOM tool')
    parser.add_argument('-q', '--quiet',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_QUIET')),
                        help='Suppress all output.')
    parser.add_argument('-n', '--no-color',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_NO_COLOR')),
                        help=('Do not emit color codes. By default color codes are used when stdout '
                              'or stderr is connected to a terminal.'))
    parser.add_argument('-f', '--force-terminal',
                        action='store_true',
                        default=bool(os.environ.get('SBOM_FORCE_TERMINAL')) or None,
                        help=('Enable terminal control codes even if out is not attached to terminal. '
                              'This option is ignored if used along with the "--output-file" option.'))
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
    create_parser.add_argument('--file-tags',
                               action='store_true',
                               default=bool(os.environ.get('SBOM_CREATE_NO_FILE_TAGS')),
                               help=('Scan files for SPDX file tags. This includes SPDX-License-Identifier, '
                                     'SPDX-FileCopyrightText and SPDX-FileContributor'))
    create_parser.add_argument('--disable-conditions',
                               action='store_true',
                               help=('When processing manifest files, disregard the conditions for the "if" key.'))

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

    check_parser.add_argument('-o', '--output-file',
                              metavar='OUTPUT_FILE',
                              help=('Print output to the specified file instead of stdout.'))

    check_parser.add_argument(*NAME_ARG['args'], **NAME_ARG['kwargs'])

    check_parser.add_argument('--check-all-packages',
                              action='store_true',
                              default=bool(os.environ.get('SBOM_CHECK_ALL')),
                              help=('Check all packages in the SBOM file. By default only packages, '
                                    'linked via the SPDX relationship to the main project package, '
                                    'are checked. This may report vulnerabilities, which do not '
                                    'affect the resulting binary! For example components with libraries, '
                                    'which are not linked into the final binary will be checked too.'))

    check_parser.add_argument('--local-db',
                              action='store_true',
                              default=bool(os.environ.get('SBOM_CHECK_LOCAL_DB')),
                              help=('Use local NVD mirror for vulnerability check.'))

    check_parser.add_argument('--no-sync-db',
                              action='store_true',
                              default=bool(os.environ.get('SBOM_CHECK_NO_SYNC_DB')),
                              help=('Skip updating local NVD mirror before vulnerability check.'))

    check_parser.add_argument('--format',
                              choices=['table', 'json', 'csv', 'markdown'],
                              default=os.environ.get('SBOM_CHECK_FORMAT', 'table'),
                              help=('table - Print report table. This is default.'
                                    'json - Print report in JSON format. '
                                    'csv - Print report in CSV format.'))

    license_parser = subparsers.add_parser('license',
                                           help=('Print licenses and copyrights used in the project '
                                                 'described by PROJECT_DESCRIPTION json file.'))
    license_parser.set_defaults(func=cmd_license)
    license_parser.add_argument('input_file',
                                metavar='PROJECT_DESCRIPTION',
                                help=('Path to the project_description.json file generated '
                                      'by the ESP-IDF sbom tool.'))

    license_parser.add_argument('-o', '--output-file',
                                metavar='OUTPUT_FILE',
                                help=('Print output to the specified file instead of stdout.'))

    license_parser.add_argument('--format',
                                choices=['table', 'json'],
                                default=os.environ.get('SBOM_LICENSE_FORMAT', 'table'),
                                help=('table - Print report table. This is default.'
                                      'json - Print report in JSON format.'))

    license_parser.add_argument('-p', '--packages',
                                action='store_true',
                                default=bool(os.environ.get('SBOM_LICENSE_PACKAGES')),
                                help='Include also per package license and copyright information.')

    license_parser.add_argument('-u', '--unify-copyrights',
                                action='store_true',
                                default=bool(os.environ.get('SBOM_LICENSE_UNIFY_COPYRIGHTS')),
                                help=('Unify copyright years. If the same copyright is used at different '
                                      'places with different years or year ranges, this option will unify them.'))

    license_parser.add_argument('--disable-conditions',
                                action='store_true',
                                help=('When processing manifest files, disregard the conditions for the "if" key.'))

    nvdsync_parser = subparsers.add_parser('sync-db',
                                           help=('Update local NVD git repository.'))
    nvdsync_parser.set_defaults(func=cmd_nvdsync)

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
                                          help=('Manifest file (sbom.yml, idf_manifest.yml or .gitmodules) or '
                                                'directory, which will be searched for manifest files.'))

    # Bypass validation if a git rebase is ongoing. Utilized by the pre-commit hook.
    manifest_validate_parser.add_argument('--skip-on-rebase',
                                          action='store_true',
                                          help=argparse.SUPPRESS)

    manifest_check_parser = manifest_subparsers.add_parser('check',
                                                           help=('Check manifest files for vulnerabilities.'))
    manifest_check_parser.set_defaults(func=cmd_manifest_check)

    manifest_check_parser.add_argument('-o', '--output-file',
                                       metavar='OUTPUT_FILE',
                                       help=('Print output to the specified file instead of stdout.'))

    manifest_check_parser.add_argument(*NAME_ARG['args'], **NAME_ARG['kwargs'])

    manifest_check_parser.add_argument('--local-db',
                                       action='store_true',
                                       default=bool(os.environ.get('SBOM_CHECK_LOCAL_DB')),
                                       help=('Use local NVD mirror for vulnerability check.'))

    manifest_check_parser.add_argument('--no-sync-db',
                                       action='store_true',
                                       default=bool(os.environ.get('SBOM_CHECK_NO_SYNC_DB')),
                                       help=('Skip updating local NVD mirror before vulnerability check.'))

    manifest_check_parser.add_argument('--format',
                                       choices=['table', 'json', 'csv', 'markdown'],
                                       help=('table - Print report table. This is default.'
                                             'json - Print report in JSON format. '
                                             'csv - Print report in CSV format.'))
    manifest_check_parser.add_argument('check_paths',
                                       metavar='PATH_TO_CHECK',
                                       default=[os.path.curdir],
                                       nargs='*',
                                       help=('Manifest file (sbom.yml, idf_manifest.yml or .gitmodules) or '
                                             'directory, which will be searched for manifest files.'))

    manifest_license_parser = manifest_subparsers.add_parser('license',
                                                             help=('Print licenses and copyrights for manifest files '
                                                                   'found in specified path'))
    manifest_license_parser.set_defaults(func=cmd_manifest_license)
    manifest_license_parser.add_argument('license_paths',
                                         metavar='LICENCE_PATH',
                                         default=[os.path.curdir],
                                         nargs='*',
                                         help=('Manifest file (sbom.yml, idf_manifest.yml or .gitmodules) or '
                                               'directory, which will be searched for manifest files.'))
    manifest_license_parser.add_argument('--format',
                                         choices=['table', 'json'],
                                         default=os.environ.get('SBOM_LICENSE_FORMAT', 'table'),
                                         help=('table - Print report table. This is default.'
                                               'json - Print report in JSON format.'))
    manifest_license_parser.add_argument('-u', '--unify-copyrights',
                                         action='store_true',
                                         default=bool(os.environ.get('SBOM_LICENSE_UNIFY_COPYRIGHTS')),
                                         help=('Unify copyright years. If the same copyright is used at different '
                                               'places with different years or year ranges, this option will unify them.'))

    manifest_aggregate_parser = manifest_subparsers.add_parser(
        'aggregate',
        help=(('Combine all manifest files located in AGGREGATE_PATH into a single SBOM '
               'manifest file by using the referenced manifests'))
    )
    manifest_aggregate_parser.set_defaults(func=cmd_manifest_aggregate)
    manifest_aggregate_parser.add_argument('aggregate_path',
                                           metavar='AGGREGATE_PATH',
                                           default=[os.path.curdir],
                                           help=('Manifest file (sbom.yml, idf_manifest.yml or .gitmodules) or '
                                                 'directory, which will be searched for manifest files.'))
    manifest_aggregate_parser.add_argument('-o', '--output-file',
                                           metavar='OUTPUT_FILE',
                                           help=('Print output to the specified file instead of stdout.'))

    ofile = sys.stdout
    try:
        args = parser.parse_args()
        if args.force_terminal:
            force_terminal_stdout = True
            force_terminal_stderr = True
        else:
            force_terminal_stdout = None
            force_terminal_stderr = None

        if hasattr(args, 'output_file') and args.output_file:
            force_terminal_stdout = False
            ofile = open(args.output_file, 'w')

        log.set_console(ofile, args.quiet, args.no_color, force_terminal_stdout,
                        force_terminal_stderr, args.debug)

        env = {key: value for key, value in os.environ.items() if key.startswith('SBOM_')}
        log.debug(f'environ: {env}')
        log.debug(f'args: {args}')

        if 'func' not in args:
            parser.print_help(sys.stderr)
            sys.exit(1)

        return args.func(args)

    except KeyboardInterrupt:
        sys.exit(1)
    finally:
        if ofile:
            ofile.close()


if __name__ == '__main__':
    sys.exit(main())
