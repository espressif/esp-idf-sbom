#!/usr/bin/env python

# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import json
import os
import sys
from typing import Any
from typing import Dict
from typing import List

import rich_click as click
import yaml
from rich.table import Table

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom import git
from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom import mft
from esp_idf_sbom.libsbom import nvd
from esp_idf_sbom.libsbom import report
from esp_idf_sbom.libsbom import spdx
from esp_idf_sbom.libsbom import utils

EXTENDED_SCAN_HELP = (
    'If available, use the product part of the CPE and the keywords found '
    'under the cve-keywords key in the manifest or generated SBOM file to '
    'search for potential vulnerabilities. This involves scanning CVE '
    'descriptions for these keywords in CVEs that have not yet been analyzed '
    'by the NVD. It also queries each CPE with its version set to NA (-) to '
    'surface CVEs that NVD recorded without a specific version; these are '
    'reported as MAYBE, as their applicability to the scanned version cannot '
    'be determined. The identified CVEs should be thoroughly examined for false '
    'positives. Using this option may result in a report that includes CVEs '
    'unrelated to the scanned components or CVEs that have already been fixed '
    'in the scanned component versions. Exercise caution when using this option, '
    'as it can provide early insights into newly reported CVEs but may also '
    'lead to misleading reports.'
)

NO_SYNC_EXCLUDED_CVES_HELP = (
    'Skip downloading the excluded_cves.yaml file from the esp-idf-sbom '
    'repository. The on-disk cache at ~/.esp-idf-sbom/excluded_cves.yaml '
    'is used if it exists; otherwise the exclusion list is treated as '
    'empty. Intended for fully air-gapped runs that combine well with '
    '--local-db.'
)


def extended_scan_option(func: Any) -> Any:
    # Shared --extended-scan flag (dest=extended_scan); -n/--name are kept as
    # backward-compatible aliases. Used by check and manifest check.
    return click.option('--extended-scan', '-n', '--name', 'extended_scan', is_flag=True, help=EXTENDED_SCAN_HELP)(func)


def no_sync_excluded_cves_option(func: Any) -> Any:
    return click.option(
        '--no-sync-excluded-cves',
        is_flag=True,
        default=bool(os.environ.get('SBOM_NO_SYNC_EXCLUDED_CVES')),
        help=NO_SYNC_EXCLUDED_CVES_HELP,
    )(func)


def cmd_create(args: Dict[str, Any]) -> int:
    spdx_sbom = spdx.SPDXDocument(args, args['input_file'])
    log.print(spdx_sbom.dump())
    return 0


def cmd_check(args: Dict[str, Any]) -> int:
    if args['input_file'] == '-':
        buf = sys.stdin.read()
    else:
        try:
            with open(args['input_file']) as f:
                buf = f.read()
        except OSError as e:
            log.die(f'cannot read SBOM file: {e}')

    record_list: List[Dict[str, str]] = []
    exit_code = 0

    packages = spdx.parse_packages(buf)
    if not args['check_all_packages']:
        packages = spdx.filter_packages(packages)

    try:
        if args['local_db']:
            if not args['no_sync_db']:
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
                    if args['extended_scan']:
                        # Include the product (package name) from the CPE in the keywords
                        keywords.append(cpe.split(':')[4])

                comment = spdx.parse_package_comment(pkg)
                if args['extended_scan']:
                    # Include keywords from the SPDX Package comment.
                    keywords += comment.get('cve-keywords', [])
            # Also scan the sibling CPEs of vendor-renamed products (see
            # utils.expand_cpe_aliases). Expand before caching so the local
            # mirror pre-fetch covers them too.
            cpes = utils.expand_cpe_aliases(cpes)
            nvd.cache_cves(cpes, keywords)

        log.eprint('Checking packages')
        with log.progress(
            total=len(packages),
            file=sys.stderr,
            disable=args['no_progress'],
        ) as bar:
            for pkg in packages.values():
                pkg_records: List[Dict[str, str]] = []
                pkg_name = pkg['PackageName'][0]
                pkg_ver = pkg['PackageVersion'][0] if 'PackageVersion' in pkg else ''
                package_added = False

                bar.update(1)

                cpes = []
                keywords = []
                for cpe_ref in pkg.get('ExternalRef', []):
                    if not cpe_ref.startswith('SECURITY cpe23Type'):
                        continue
                    _, _, cpe = cpe_ref.split()
                    cpes.append(cpe)
                    if args['extended_scan']:
                        # Include the CPE product name in the keywords so it is searched in the CVE description.
                        product = cpe.split(':')[4]
                        keywords.append(product)

                manifest_exclude_list: Dict[str, str] = {}
                comment = spdx.parse_package_comment(pkg)
                if 'cve-exclude-list' in comment:
                    # get information about excluded CVEs
                    manifest_exclude_list = {cve['cve']: cve['reason'] for cve in comment['cve-exclude-list']}
                if args['extended_scan']:
                    keywords += comment.get('cve-keywords', [])

                # Also scan the sibling CPEs of vendor-renamed products (see
                # utils.expand_cpe_aliases).
                cpes = utils.expand_cpe_aliases(cpes)

                for cpe in cpes:
                    # Merge globally-applicable exclusions for this CPE with manifest excludes.
                    # Manifest-level entries take precedence (more specific).
                    cve_exclude_list = nvd.get_excluded_cves_for_cpe(cpe)
                    cve_exclude_list.update(manifest_exclude_list)

                    vulns = nvd.check_cpe(cpe, args['local_db'])
                    for vuln in vulns:
                        record = report.create_vulnerable_record(vuln, cve_exclude_list, cpe, '', pkg_name, pkg_ver)
                        pkg_records.append(record)
                        package_added = True

                if args['extended_scan']:
                    for keyword in keywords:
                        vulns = nvd.check_keyword(keyword, args['local_db'])
                        for vuln in vulns:
                            existing_record = report.find_record_by_cve(pkg_records, vuln['cve']['id'])
                            if existing_record:
                                # The same CVE was discovered using different keywords.
                                existing_record['keyword'] += f', {keyword}'
                                continue
                            record = report.create_vulnerable_record(
                                vuln, manifest_exclude_list, '', keyword, pkg_name, pkg_ver, maybe=True
                            )
                            pkg_records.append(record)
                            package_added = True

                    # Also query each CPE with the version set to NA (-), which
                    # surfaces CVEs NVD recorded without a pinned version (e.g.
                    # against an unreleased development snapshot). Whether such a
                    # CVE applies to the scanned version cannot be derived from
                    # the CPE, so it is reported as MAYBE for manual review,
                    # never asserted as YES.
                    for cpe in cpes:
                        parts = cpe.split(':')
                        if len(parts) < 6 or parts[5] in ('-', '*'):
                            # Already NA/ANY; the regular scan above covers it.
                            continue
                        na_cpe = ':'.join(parts[:5] + ['-'] + parts[6:])
                        cve_exclude_list = nvd.get_excluded_cves_for_cpe(cpe)
                        cve_exclude_list.update(manifest_exclude_list)
                        for vuln in nvd.check_cpe(na_cpe, args['local_db']):
                            if report.find_record_by_cve(pkg_records, vuln['cve']['id']):
                                # Already reported by the version or keyword scan.
                                continue
                            record = report.create_vulnerable_record(
                                vuln, cve_exclude_list, na_cpe, '', pkg_name, pkg_ver, maybe=True
                            )
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
        log.die(str(e))
    except KeyboardInterrupt:
        log.die('Process terminated')

    # Project package is the first one
    project_pkg = packages[next(iter(packages))]
    proj_name = project_pkg['PackageName'][0]
    proj_ver = project_pkg['PackageVersion'][0]
    report.show(record_list, args, proj_name, proj_ver)

    return exit_code


def cmd_license(args: Dict[str, Any]) -> int:
    # Set options how the SPDXDocument should be generated.
    # We need to make sure that file_tags is enabled,
    # so licenses and copyrights are collected from the
    # component/package files.
    args['rem_config'] = True
    args['rem_unused'] = True
    args['files'] = 'rem'
    args['no_guess'] = False
    args['file_tags'] = True
    args['rem_submodules'] = False
    args['rem_subpackages'] = False
    args['add_config_deps'] = False
    args['add_unused_deps'] = False
    spdx_sbom = spdx.SPDXDocument(args, args['input_file'])

    # The Project SPDX object already contains aggregated
    # licenses and copyrights from packages/components
    # which were linked into the final binary. We can use
    # this information to print an overall report about licenses
    # and copyrights used by the project application.
    tags = spdx_sbom.project.tags
    proj_name = spdx_sbom.project.name
    if args['unify_copyrights']:
        copyrights = sorted(tags.simplify_copyrights(tags.copyrights))
    else:
        copyrights = sorted(tags.copyrights)
    licenses_merged = tags.licenses_expressions | tags.licenses_expressions_declared
    license_concluded = tags.simplify_licenses(licenses_merged)
    licenses = sorted(licenses_merged)

    packages = []
    if args['packages']:
        for package in spdx_sbom.project.walk_packages():
            if args['unify_copyrights']:
                package_copyrights = sorted(package.tags.simplify_copyrights(package.tags.copyrights))
            else:
                package_copyrights = sorted(package.tags.copyrights)
            package_licenses_merged = package.tags.licenses_expressions | package.tags.licenses_expressions_declared
            package_license_concluded = tags.simplify_licenses(package_licenses_merged)
            package_licenses = sorted(package_licenses_merged)

            package_info: Dict[str, Any] = {}
            package_info['name'] = package.name
            package_info['license_concluded'] = package_license_concluded
            package_info['licenses'] = package_licenses
            package_info['copyrights'] = package_copyrights
            packages.append(package_info)

    if args['format'] == 'json':
        log.print_json(
            json.dumps(
                {
                    'license_concluded': license_concluded,
                    'licenses': licenses,
                    'copyrights': copyrights,
                    'packages': packages,
                }
            )
        )
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


def cmd_nvdsync(args: Dict[str, Any]) -> int:
    return nvd.sync()


def cmd_manifest_validate(args: Dict[str, Any]) -> int:
    def is_git_rebase_in_progress() -> bool:
        rebase_merge_dir = git.get_gitpath('rebase-merge')
        rebase_apply_dir = git.get_gitpath('rebase-apply')
        if os.path.isdir(rebase_merge_dir) or os.path.isdir(rebase_apply_dir):
            return True

        return False

    exit_code = 0
    try:
        if args['skip_on_rebase'] and is_git_rebase_in_progress():
            log.print('Git rebase is in progress, skipping the check.')
            return exit_code

        log.eprint('Searching for manifest files')
        manifests = mft.get_manifests(args['validate_paths'])

        log.eprint('Validating manifests')
        with log.progress(
            total=len(manifests),
            file=sys.stderr,
            disable=args['no_progress'],
        ) as bar:
            for manifest in manifests:
                bar.update(1)
                try:
                    mft.validate(manifest, manifest['_src'], manifest['_dst'], die=False)
                except RuntimeError as e:
                    log.err(str(e))
                    exit_code = 1

    except (RuntimeError, OSError) as e:
        log.die(str(e))
    except KeyboardInterrupt:
        log.die('Process terminated')

    return exit_code


def cmd_manifest_check(args: Dict[str, Any]) -> int:
    record_list: List[Dict[str, str]] = []
    exit_code = 0

    try:
        if args['local_db'] and not args['no_sync_db']:
            nvd.sync()

        # Honor a repository-local excluded_cves.yaml at the root of any scanned
        # ESP-IDF tree, extending the global exclusion list for this scan only.
        for source in args['check_paths']:
            if utils.is_idf_root(source):
                nvd.merge_local_excluded_cves(source)

        log.eprint('Searching for manifest files')
        manifests = mft.get_manifests(args['check_paths'])

        if args['local_db']:
            log.eprint('Searching for possible CVEs in the local database')
            cpes: List[str] = []
            keywords: List[str] = []
            for manifest in manifests:
                if 'cpe' in manifest:
                    cpes += manifest['cpe']
                    if args['extended_scan']:
                        keywords += [cpe.split(':')[4] for cpe in cpes]
                if args['extended_scan']:
                    keywords += manifest.get('cve-keywords', [])
            nvd.cache_cves(cpes, keywords)

        log.eprint('Checking manifest files for vulnerabilities')
        with log.progress(
            total=len(manifests),
            file=sys.stderr,
            disable=args['no_progress'],
        ) as bar:
            for manifest in manifests:
                pkg_records: List[Dict[str, str]] = []
                pkg_name = manifest.get('name')
                pkg_ver = manifest.get('version', '')
                package_added = False

                bar.update(1)

                cpes = []
                keywords = []
                for cpe in manifest.get('cpe', []):
                    # Include the version in the CPE, as it might currently only have a placeholder.
                    cpe = cpe.format(pkg_ver)
                    cpes.append(cpe)
                    product = cpe.split(':')[4]
                    if args['extended_scan']:
                        # Include the CPE product name in the keywords so it is searched in the CVE description.
                        keywords.append(product)
                    if not pkg_name:
                        # If the manifest lacks a name, use the product part from the CPE.
                        pkg_name = product

                if not pkg_name:
                    # Without a package name or CPE, use the manifest path as the name.
                    pkg_name = manifest['_src']

                manifest_exclude_list = {cve['cve']: cve['reason'] for cve in manifest.get('cve-exclude-list', [])}
                if args['extended_scan']:
                    keywords += manifest.get('cve-keywords', [])
                for cpe in cpes:
                    # Merge globally-applicable exclusions for this CPE with manifest excludes.
                    # Manifest-level entries take precedence (more specific).
                    cve_exclude_list = nvd.get_excluded_cves_for_cpe(cpe)
                    cve_exclude_list.update(manifest_exclude_list)

                    vulns = nvd.check_cpe(cpe, args['local_db'])
                    for vuln in vulns:
                        record = report.create_vulnerable_record(vuln, cve_exclude_list, cpe, '', pkg_name, pkg_ver)
                        pkg_records.append(record)
                        package_added = True

                if args['extended_scan']:
                    for keyword in keywords:
                        vulns = nvd.check_keyword(keyword, args['local_db'])
                        for vuln in vulns:
                            existing_record = report.find_record_by_cve(pkg_records, vuln['cve']['id'])
                            if existing_record:
                                # The same CVE was discovered using different keywords.
                                existing_record['keyword'] += f', {keyword}'
                                continue
                            record = report.create_vulnerable_record(
                                vuln, manifest_exclude_list, '', keyword, pkg_name, pkg_ver, maybe=True
                            )
                            pkg_records.append(record)
                            package_added = True

                    # Also query each CPE with the version set to NA (-), which
                    # surfaces CVEs NVD recorded without a pinned version (e.g.
                    # against an unreleased development snapshot). Whether such a
                    # CVE applies to the scanned version cannot be derived from
                    # the CPE, so it is reported as MAYBE for manual review,
                    # never asserted as YES.
                    for cpe in cpes:
                        parts = cpe.split(':')
                        if len(parts) < 6 or parts[5] in ('-', '*'):
                            # Already NA/ANY; the regular scan above covers it.
                            continue
                        na_cpe = ':'.join(parts[:5] + ['-'] + parts[6:])
                        cve_exclude_list = nvd.get_excluded_cves_for_cpe(cpe)
                        cve_exclude_list.update(manifest_exclude_list)
                        for vuln in nvd.check_cpe(na_cpe, args['local_db']):
                            if report.find_record_by_cve(pkg_records, vuln['cve']['id']):
                                # Already reported by the version or keyword scan.
                                continue
                            record = report.create_vulnerable_record(
                                vuln, cve_exclude_list, na_cpe, '', pkg_name, pkg_ver, maybe=True
                            )
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
        log.die(str(e))
    except KeyboardInterrupt:
        log.die('Process terminated')

    report.show(record_list, args)

    return exit_code


def cmd_manifest_license(args: Dict[str, Any]) -> int:
    packages = []
    try:
        log.eprint('Searching for manifest files')
        manifests = mft.get_manifests(args['license_paths'])
        manifest_paths = [manifest['_dst'] for manifest in manifests]

        log.eprint('Collecting licenses and copyrights information')
        with log.progress(
            total=len(manifests),
            file=sys.stderr,
            disable=args['no_progress'],
        ) as bar:
            for manifest in manifests:
                bar.update(1)

                exclude_dirs = manifest_paths.copy()
                exclude_dirs.remove(manifest['_dst'])

                tags = spdx.SPDXDirTags(manifest['_dst'], exclude_dirs)

                if 'copyright' in manifest:
                    # Store copyrights declared in manifest
                    tags.copyrights |= set(manifest['copyright'])

                if 'license' in manifest:
                    # Store license declared in manifest
                    tags.licenses_expressions_declared |= set([manifest['license']])

                if args['unify_copyrights']:
                    package_copyrights = sorted(tags.simplify_copyrights(tags.copyrights))
                else:
                    package_copyrights = sorted(tags.copyrights)
                package_licenses_merged = tags.licenses_expressions | tags.licenses_expressions_declared
                package_license_concluded = tags.simplify_licenses(package_licenses_merged)
                package_licenses = sorted(package_licenses_merged)

                package_info: Dict[str, Any] = {}
                package_info['name'] = manifest['name'] if 'name' in manifest else manifest['_src']
                package_info['license_concluded'] = package_license_concluded
                package_info['licenses'] = package_licenses
                package_info['copyrights'] = package_copyrights
                packages.append(package_info)

        if args['format'] == 'json':
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
        log.die('Process terminated')

    return 0


def cmd_manifest_aggregate(args: Dict[str, Any]) -> int:
    # Locate all manifest files in the specified path and create a single SBOM
    # manifest file with all manifests expanded.
    try:
        aggregated: Dict = {'manifests': []}
        args['aggregate_path'] = utils.presolve(args['aggregate_path'])
        manifests = mft.get_manifests([args['aggregate_path']])
        for manifest in manifests:
            dst = manifest['_dst']
            dst = utils.prelpath(dst, args['aggregate_path'])
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

        if args['output_file']:
            with open(args['output_file'], 'w') as f:
                yaml.dump(aggregated, f)

        else:
            log.print(yaml.dump(aggregated))

    except (RuntimeError, OSError) as e:
        log.die(str(e))
    except KeyboardInterrupt:
        log.die('Process terminated')

    return 0


def _dispatch(ctx: click.Context, func: Any, **params: Any) -> None:
    # Merge the global options (stored on ctx.obj by the group) and the
    # subcommand options into a single args dict, configure the console, run the
    # selected command and exit with its code.
    options = ctx.obj
    args = {**options, **params}

    ofile = sys.stdout
    output_file = params.get('output_file')
    if output_file:
        # set_console pins stdout to this file and drops --force-terminal there,
        # so the written report stays ANSI-free.
        ofile = open(output_file, 'w')

    log.set_console(
        ofile,
        options['quiet'],
        options['no_color'],
        options['force_terminal'],
        options['debug'],
        options['no_hint'],
    )

    env = {key: value for key, value in os.environ.items() if key.startswith('SBOM_')}
    log.debug(f'environ: {env}')
    log.debug(f'args: {args}')

    # Propagate the --no-sync-excluded-cves flag to the nvd module so the
    # excluded_cves.yaml fetch is skipped on subcommands that consult it.
    nvd.EXCLUDED_CVES_NO_SYNC = bool(args.get('no_sync_excluded_cves', False))

    try:
        exit_code = func(args)
    finally:
        if ofile is not sys.stdout:
            ofile.close()

    ctx.exit(exit_code)


@click.group(invoke_without_command=True, context_settings={'help_option_names': ['-h', '--help']})
@click.option('-q', '--quiet', is_flag=True, default=bool(os.environ.get('SBOM_QUIET')), help='Suppress all output.')
@click.option(
    '-n',
    '--no-color',
    is_flag=True,
    default=bool(os.environ.get('SBOM_NO_COLOR')),
    help='Do not emit color codes. By default color codes are used when stdout or stderr is connected to a terminal.',
)
@click.option(
    '-f',
    '--force-terminal',
    is_flag=True,
    default=bool(os.environ.get('SBOM_FORCE_TERMINAL')),
    help=(
        'Enable terminal control codes even if out is not attached to terminal. '
        'This option is ignored if used along with the "--output-file" option.'
    ),
)
@click.option(
    '-d',
    '--debug',
    is_flag=True,
    default=bool(os.environ.get('SBOM_DEBUG')),
    help='Print debug information. Messages are printed to standard error output.',
)
@click.option(
    '--no-progress',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CHECK_NO_PROGRESS')),
    help='Disable progress bar.',
)
@click.option(
    '--no-hint',
    is_flag=True,
    default=bool(os.environ.get('SBOM_NO_HINT')),
    help='Suppress informational hints, such as the NVD API key suggestion printed during online scans.',
)
@click.version_option(__version__, '-V', '--version', prog_name='esp-idf-sbom', message='%(prog)s %(version)s')
@click.pass_context
def main(
    ctx: click.Context,
    quiet: bool,
    no_color: bool,
    force_terminal: bool,
    debug: bool,
    no_progress: bool,
    no_hint: bool,
) -> None:
    """ESP-IDF SBOM tool"""
    ctx.obj = {
        'quiet': quiet,
        'no_color': no_color,
        'force_terminal': force_terminal,
        'debug': debug,
        'no_progress': no_progress,
        'no_hint': no_hint,
    }
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help(), err=True)
        ctx.exit(1)


@main.command('create')
@click.argument('input_file', metavar='PROJECT_DESCRIPTION')
@click.option(
    '-o',
    '--output',
    '--output-file',
    'output_file',
    metavar='SBOM_FILE',
    default=None,
    help='Output SBOM file. Default is stdout.',
)
@click.option(
    '--rem-config',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_REM_CONFIG')),
    help='Remove configuration only components.',
)
@click.option(
    '--add-config-deps',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_ADD_CONFIG_DEPS')),
    help='Add dependencies on configuration only components.',
)
@click.option(
    '--rem-unused',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_REM_UNUSED')),
    help='Remove components not linked into the final binary.',
)
@click.option(
    '--add-unused-deps',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_ADD_UNUSED_DEPS')),
    help='Add dependencies on components not linked into the final binary.',
)
@click.option(
    '--rem-submodules',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_REM_SUBMODULES')),
    help=(
        'Remove submodules info and include submodules files directly '
        'in components. By default submodules are reported as separated '
        'packages.'
    ),
)
@click.option(
    '--rem-subpackages',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_REM_SUBPACKAGES')),
    help=(
        'Remove subpackages info and include subpackages files directly '
        'in components. By default subpackages are reported as separated '
        'packages.'
    ),
)
@click.option(
    '--files',
    type=click.Choice(['auto', 'add', 'rem']),
    default=os.environ.get('SBOM_CREATE_FILES', 'rem'),
    help=(
        'rem - Exclude all files. This will generate much smaller SBOM file '
        'and it is the default value. '
        'add - Explicitly add all files for any package. '
        'auto - Adds files only if there is no repository or URL and version '
        'information available for package.'
    ),
)
@click.option(
    '--no-guess',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_NO_GUESS')),
    help=(
        "Don't try to identify PackageSupplier and PackageVersion. "
        'By default URLs are checked for known suppliers, currently only '
        'Espressif Systems, and project version or git describe is used '
        'to identify versions. With this option PackageSupplier and '
        'PackageVersion will be omitted, unless explicitly stated in '
        'sbom.yml, idf_component.yml or .gitmodules.'
    ),
)
@click.option(
    '--file-tags',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CREATE_NO_FILE_TAGS')),
    help=(
        'Scan files for SPDX file tags. This includes SPDX-License-Identifier, '
        'SPDX-FileCopyrightText and SPDX-FileContributor'
    ),
)
@click.option(
    '--disable-conditions',
    is_flag=True,
    help='When processing manifest files, disregard the conditions for the "if" key.',
)
@no_sync_excluded_cves_option
@click.pass_context
def create(ctx: click.Context, **params: Any) -> None:
    """Create SBOM file based on the ESP-IDF project_description.json file."""
    _dispatch(ctx, cmd_create, **params)


@main.command('check')
@click.argument('input_file', metavar='SBOM_FILE', required=False, default='-')
@click.option(
    '-o',
    '--output',
    '--output-file',
    'output_file',
    metavar='OUTPUT_FILE',
    default=None,
    help='Print output to the specified file instead of stdout.',
)
@extended_scan_option
@click.option(
    '--check-all-packages',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CHECK_ALL')),
    help=(
        'Check all packages in the SBOM file. By default only packages, '
        'linked via the SPDX relationship to the main project package, '
        'are checked. This may report vulnerabilities, which do not '
        'affect the resulting binary! For example components with libraries, '
        'which are not linked into the final binary will be checked too.'
    ),
)
@click.option(
    '--local-db',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CHECK_LOCAL_DB')),
    help='Use local NVD mirror for vulnerability check.',
)
@no_sync_excluded_cves_option
@click.option(
    '--no-sync-db',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CHECK_NO_SYNC_DB')),
    help='Skip updating local NVD mirror before vulnerability check.',
)
@click.option(
    '--format',
    type=click.Choice(['table', 'json', 'csv', 'markdown']),
    default=os.environ.get('SBOM_CHECK_FORMAT', 'table'),
    help=(
        'table - Print report table. This is default.'
        'json - Print report in JSON format. '
        'csv - Print report in CSV format.'
    ),
)
@click.pass_context
def check(ctx: click.Context, **params: Any) -> None:
    """Check components/submodules in the ESP-IDF SBOM file for possible vulnerabilities.

    Vulnerabilities are reported based on the National Vulnerability Database.
    """
    _dispatch(ctx, cmd_check, **params)


@main.command('license')
@click.argument('input_file', metavar='PROJECT_DESCRIPTION')
@click.option(
    '-o',
    '--output',
    '--output-file',
    'output_file',
    metavar='OUTPUT_FILE',
    default=None,
    help='Print output to the specified file instead of stdout.',
)
@click.option(
    '--format',
    type=click.Choice(['table', 'json']),
    default=os.environ.get('SBOM_LICENSE_FORMAT', 'table'),
    help='table - Print report table. This is default.json - Print report in JSON format.',
)
@click.option(
    '-p',
    '--packages',
    is_flag=True,
    default=bool(os.environ.get('SBOM_LICENSE_PACKAGES')),
    help='Include also per package license and copyright information.',
)
@click.option(
    '-u',
    '--unify-copyrights',
    is_flag=True,
    default=bool(os.environ.get('SBOM_LICENSE_UNIFY_COPYRIGHTS')),
    help=(
        'Unify copyright years. If the same copyright is used at different '
        'places with different years or year ranges, this option will unify them.'
    ),
)
@click.option(
    '--disable-conditions',
    is_flag=True,
    help='When processing manifest files, disregard the conditions for the "if" key.',
)
@click.pass_context
def license(ctx: click.Context, **params: Any) -> None:
    """Print licenses and copyrights used in the project described by PROJECT_DESCRIPTION json file."""
    _dispatch(ctx, cmd_license, **params)


@main.command('sync-db')
@click.pass_context
def sync_db(ctx: click.Context, **params: Any) -> None:
    """Update local NVD git repository."""
    _dispatch(ctx, cmd_nvdsync, **params)


@main.group('manifest', invoke_without_command=True)
@click.pass_context
def manifest(ctx: click.Context) -> None:
    """Commands operating atop of manifest files."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help(), err=True)
        ctx.exit(1)


@manifest.command('validate')
@click.argument('validate_paths', metavar='PATH_TO_VALIDATE', nargs=-1)
# Bypass validation if a git rebase is ongoing. Utilized by the pre-commit hook.
@click.option('--skip-on-rebase', is_flag=True, hidden=True)
@click.pass_context
def manifest_validate(ctx: click.Context, **params: Any) -> None:
    """Validate manifest files."""
    params['validate_paths'] = list(params['validate_paths']) or [os.path.curdir]
    _dispatch(ctx, cmd_manifest_validate, **params)


@manifest.command('check')
@click.option(
    '-o',
    '--output',
    '--output-file',
    'output_file',
    metavar='OUTPUT_FILE',
    default=None,
    help='Print output to the specified file instead of stdout.',
)
@extended_scan_option
@click.option(
    '--local-db',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CHECK_LOCAL_DB')),
    help='Use local NVD mirror for vulnerability check.',
)
@click.option(
    '--no-sync-db',
    is_flag=True,
    default=bool(os.environ.get('SBOM_CHECK_NO_SYNC_DB')),
    help='Skip updating local NVD mirror before vulnerability check.',
)
@no_sync_excluded_cves_option
@click.option(
    '--format',
    type=click.Choice(['table', 'json', 'csv', 'markdown']),
    help=(
        'table - Print report table. This is default.'
        'json - Print report in JSON format. '
        'csv - Print report in CSV format.'
    ),
)
@click.argument('check_paths', metavar='PATH_TO_CHECK', nargs=-1)
@click.pass_context
def manifest_check(ctx: click.Context, **params: Any) -> None:
    """Check manifest files for vulnerabilities."""
    params['check_paths'] = list(params['check_paths']) or [os.path.curdir]
    _dispatch(ctx, cmd_manifest_check, **params)


@manifest.command('license')
@click.argument('license_paths', metavar='LICENCE_PATH', nargs=-1)
@click.option(
    '--format',
    type=click.Choice(['table', 'json']),
    default=os.environ.get('SBOM_LICENSE_FORMAT', 'table'),
    help='table - Print report table. This is default.json - Print report in JSON format.',
)
@click.option(
    '-u',
    '--unify-copyrights',
    is_flag=True,
    default=bool(os.environ.get('SBOM_LICENSE_UNIFY_COPYRIGHTS')),
    help=(
        'Unify copyright years. If the same copyright is used at different '
        'places with different years or year ranges, this option will unify them.'
    ),
)
@click.pass_context
def manifest_license(ctx: click.Context, **params: Any) -> None:
    """Print licenses and copyrights for manifest files found in specified path."""
    params['license_paths'] = list(params['license_paths']) or [os.path.curdir]
    _dispatch(ctx, cmd_manifest_license, **params)


@manifest.command('aggregate')
@click.argument('aggregate_path', metavar='AGGREGATE_PATH')
@click.option(
    '-o',
    '--output',
    '--output-file',
    'output_file',
    metavar='OUTPUT_FILE',
    default=None,
    help='Print output to the specified file instead of stdout.',
)
@click.pass_context
def manifest_aggregate(ctx: click.Context, **params: Any) -> None:
    """Combine all manifest files in AGGREGATE_PATH into a single SBOM manifest using the referenced manifests."""
    _dispatch(ctx, cmd_manifest_aggregate, **params)


if __name__ == '__main__':
    main()
