# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import datetime
import json
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from rich.box import MARKDOWN
from rich.console import Group
from rich.table import Table
from rich.text import Text

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom import nvd
from esp_idf_sbom.libsbom import utils
from esp_idf_sbom.libsbom import vex
from esp_idf_sbom.libsbom.sbom import SBOM
from esp_idf_sbom.libsbom.sbom import VexAssessment

REPORT_VERSION = 3
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
    'keyword': '',
    'cve_link': '',
    'cve_desc': '',
    'exclude_reason': '',
    'status': '',
    'kev_added': '',
    'kev_name': '',
    # What the VEX says about the CVE for this package.
    'vex_status': '',
    'vex_justification': '',
    'vex_detail': '',
    'vex_action': '',
}


def add_kev_rows(info_table: Table, record: Dict[str, str]) -> None:
    """Add what CISA says about a Known Exploited Vulnerability to a CVE's
    information table. Nothing is added for a CVE outside the catalog.
    """
    if not record['kev_added']:
        return

    info_table.add_row('[red]KEV', record['kev_name'])
    info_table.add_row('[red]Added', record['kev_added'])


def add_vex_rows(info_table: Table, record: Dict[str, str]) -> None:
    """Add what the VEX says about the CVE to its information table. Nothing is
    added for a CVE without a VEX statement."""
    if not record['vex_status']:
        return

    info_table.add_row('[yellow]VEX', record['vex_status'])
    if record['vex_justification']:
        info_table.add_row('[yellow]Justif.', record['vex_justification'])
    # An excluded CVE already shows the impact statement in its Reason row.
    if record['vex_detail'] and record['vulnerable'] != 'EXCLUDED':
        info_table.add_row('[yellow]Detail', record['vex_detail'])
    if record['vex_action']:
        info_table.add_row('[yellow]Action', record['vex_action'])


def show(records: List[Dict[str, str]], args: Dict[str, Any], proj_name: str = '', proj_ver: str = '') -> None:
    # Order records by CVSS base score (highest first), breaking ties by package
    # name and version. The NO and SKIPPED groups carry no score, so every record
    # in them compares equal on score; without the name/version tie-breaker they
    # would keep the scan (traversal) order and appear unsorted to the user. Since
    # Python's sort is stable, sorting by name/version first and by score second
    # yields "score descending, then name/version ascending".
    records_sorted = sorted(records, key=lambda r: (r['pkg_name'], r['pkg_version']))
    records_sorted = sorted(records_sorted, key=lambda r: float(r['cvss_base_score'] or 0), reverse=True)
    record_list = [r for r in records_sorted if r['vulnerable'] == 'YES']
    record_list += [r for r in records_sorted if r['vulnerable'] == 'MAYBE']
    record_list += [r for r in records_sorted if r['vulnerable'] == 'EXCLUDED']
    record_list += [r for r in records_sorted if r['vulnerable'] == 'NO']
    record_list += [r for r in records_sorted if r['vulnerable'] == 'SKIPPED']

    pkgs_cnt = len({record['pkg_name'] for record in record_list})

    if args['local_db']:
        version = nvd.local_db_version()
        database = f'NATIONAL VULNERABILITY DATABASE MIRROR ({version})'
    else:
        database = 'NATIONAL VULNERABILITY DATABASE REST API (https://nvd.nist.gov)'

    # Get summary
    summary: Dict[str, Any] = {
        'version': REPORT_VERSION,
        'date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'database': database,
        'tool': {
            'name': 'esp-idf-sbom',
            'version': __version__,
            'cmdl': ' '.join('"' + arg + '"' if ' ' in arg else arg for arg in sys.argv),
        },
        'project': {
            'name': proj_name,
            'version': proj_ver,
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
            'none': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'unknown': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'kev': {
                'count': 0,
                'cves': [],
                'packages': [],
            },
            'total_cves_count': 0,
            'packages_count': pkgs_cnt,
            'all_cves': [],
            'all_packages': [],
        },
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
        if r['kev_added']:
            kev_dict = summary['cves_summary']['kev']
            kev_dict['count'] += 1
            kev_dict['cves'].append(r['cve_id'])
            if r['pkg_name'] not in kev_dict['packages']:
                kev_dict['packages'].append(r['pkg_name'])

    if args['format'] == 'json':
        summary['records'] = record_list
        log.print_json(json.dumps(summary))
        return
    elif args['format'] == 'csv':
        log.print(','.join(utils.csv_escape(empty_record.keys())))
        for r in record_list:
            log.print(','.join(utils.csv_escape(r.values())))
        return
    elif args['format'] == 'markdown':
        table = Table(box=MARKDOWN)
        for key in empty_record.keys():
            table.add_column(key, overflow='fold')
        for r in record_list:
            table.add_row(*r.values())
        log.print(table)
        return

    cvss_severity_color_map = {
        'CRITICAL': '[red]',
        'HIGH': '[dark_orange]',
        'MEDIUM': '[yellow]',
        'LOW': '[green]',
        'NONE': '',
        '': '',
    }

    # Table with report summary
    table = Table(title='Report summary', show_header=False)
    table.add_column('key', overflow='fold')
    table.add_column('value', overflow='fold')
    table.add_row('Date:', summary['date'])
    table.add_row('Project name:', summary['project']['name'])
    table.add_row('Project version:', summary['project']['version'])
    table.add_row('Vulnerability database:', summary['database'])
    table.add_row('Generated by tool:', f'{summary["tool"]["name"]} ({summary["tool"]["version"]})')
    table.add_row('Generated with command:', f'{summary["tool"]["cmdl"]}')
    table.add_row('Number of scanned packages:', f'{summary["cves_summary"]["packages_count"]}', end_section=True)

    severity_dict = summary['cves_summary']['critical']
    table.add_row('[red]CRITICAL CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[red]Packages affected by CRITICAL CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[red]Number of CRITICAL CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['high']
    table.add_row('[dark_orange]HIGH CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[dark_orange]Packages affected by HIGH CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[dark_orange]Number of HIGH CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['medium']
    table.add_row('[yellow]MEDIUM CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[yellow]Packages affected by MEDIUM CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[yellow]Number of MEDIUM CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['low']
    table.add_row('[green]LOW CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[green]Packages affected by LOW CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[green]Number of LOW CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['none']
    table.add_row('NONE CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('Packages affected by NONE CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('Number of NONE CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['unknown']
    table.add_row('UNKNOWN CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('Packages affected by UNKNOWN CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('Number of UNKNOWN CVEs:', str(severity_dict['count']), end_section=True)

    severity_dict = summary['cves_summary']['kev']
    table.add_row('[red]KEV CVEs found:', ', '.join(severity_dict['cves']))
    table.add_row('[red]Packages affected by KEV CVEs:', ', '.join(severity_dict['packages']))
    table.add_row('[red]Number of KEV CVEs:', str(severity_dict['count']), end_section=True)

    table.add_row('[bright_blue]All CVEs found:', ', '.join(summary['cves_summary']['all_cves']))
    table.add_row('[bright_blue]All packages affected by CVEs:', ', '.join(summary['cves_summary']['all_packages']))
    table.add_row('[bright_blue]Total number of CVEs:', str(summary['cves_summary']['total_cves_count']))

    log.print(table, '\n')

    # Table with newly identified vulnerabilities
    table = Table(
        title='[red]Packages with Identified Vulnerabilities',
        caption='Newly identified vulnerabilities. Further analysis may be required for confirmation.',
    )
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
        if any([r['cvss_vector_string'], r['cvss_version'], r['cpe'], r['cve_link'], r['status'], r['cve_desc']]):
            info_table.add_column('key', overflow='fold')
            info_table.add_column('value', overflow='fold')
            info_table.add_row('[yellow]Status', r['status'])
            info_table.add_row('[yellow]CVSS', r['cvss_version'])
            info_table.add_row('[yellow]Vec.', r['cvss_vector_string'])
            info_table.add_row('[yellow]CPE', r['cpe'])
            info_table.add_row('[yellow]Link', r['cve_link'])
            info_table.add_row('[yellow]Desc.', r['cve_desc'])
            add_vex_rows(info_table, r)
            add_kev_rows(info_table, r)

        table.add_row(
            '[bright_blue]' + r['pkg_name'],
            r['pkg_version'],
            cvss_severity_color_map[r['cvss_base_severity']] + r['cve_id'],
            cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_score'],
            cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_severity'],
            info_table,
            end_section=True,
        )

    if table.row_count:
        log.print(table, '\n')

    # Table of potential vulnerabilities identified through keyword search
    table = Table(
        title='[yellow]Packages with Possible Vulnerabilities (Needs to be analyzed carefully)',
        caption='Could include false positives that are unrelated to the specified packages or their versions.',
    )
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')
    table.add_column('CVE ID', vertical='middle', justify='center', overflow='fold')
    table.add_column('Information', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'MAYBE':
            continue
        info_table = Table(show_edge=False, show_header=False, box=None)
        if any([r['cve_link'], r['cve_desc']]):
            info_table.add_column('key', overflow='fold')
            info_table.add_column('value', overflow='fold')
            info_table.add_row('[yellow]Status', r['status'])
            info_table.add_row('[yellow]Keyword', r['keyword'])
            info_table.add_row('[yellow]Link', r['cve_link'])
            info_table.add_row('[yellow]Desc.', r['cve_desc'])
            add_vex_rows(info_table, r)
            add_kev_rows(info_table, r)

        table.add_row(
            '[bright_blue]' + r['pkg_name'],
            r['pkg_version'],
            r['cve_id'],
            info_table,
            end_section=True,
        )

    if table.row_count:
        log.print(table, '\n')

    # Table with vulnerabilities in cve-exclude-list
    table = Table(
        title='[green]Packages with Excluded Vulnerabilities',
        caption='Already assessed vulnerabilities that do not apply to packages.',
    )
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
        if any(
            [r['cvss_vector_string'], r['cvss_version'], r['cpe'], r['cve_link'], r['cve_desc'], r['exclude_reason']]
        ):
            info_table.add_column('key', overflow='fold')
            info_table.add_column('value', overflow='fold')
            info_table.add_row('[yellow]CVSS', r['cvss_version'])
            info_table.add_row('[yellow]Vec.', r['cvss_vector_string'])
            info_table.add_row('[yellow]CPE', r['cpe'])
            info_table.add_row('[yellow]Link', r['cve_link'])
            info_table.add_row('[yellow]Desc.', r['cve_desc'])
            info_table.add_row('[yellow]Reason', r['exclude_reason'])
            add_vex_rows(info_table, r)
            add_kev_rows(info_table, r)

        table.add_row(
            '[bright_blue]' + r['pkg_name'],
            r['pkg_version'],
            cvss_severity_color_map[r['cvss_base_severity']] + r['cve_id'],
            cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_score'],
            cvss_severity_color_map[r['cvss_base_severity']] + r['cvss_base_severity'],
            info_table,
            end_section=True,
        )

    if table.row_count:
        log.print(table, '\n')

    # Table with packages which were scanned and no vulnerability was found
    table = Table(
        title='[green]Packages with No Identified Vulnerabilities',
        caption='Packages checked against NVD with no vulnerabilities found.',
    )
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')
    table.add_column('CPE', vertical='middle', justify='center', overflow='fold')
    if args['extended_scan']:
        table.add_column('Keyword', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'NO':
            continue
        if args['extended_scan']:
            table.add_row(
                '[bright_blue]' + r['pkg_name'],
                r['pkg_version'],
                '[yellow]' + r['cpe'],
                '[yellow]' + r['keyword'],
                end_section=True,
            )
        else:
            table.add_row('[bright_blue]' + r['pkg_name'], r['pkg_version'], '[yellow]' + r['cpe'], end_section=True)

    if table.row_count:
        log.print(table, '\n')

    # Table with packages which were not scanned because of missing CPE
    table = Table(
        title='[green]Packages without CPE and Keyword Information',
        caption='Packages were not checked against the NVD due to the absence of CPE or keywords.',
    )
    table.add_column('Package', vertical='middle', justify='center', overflow='fold')
    table.add_column('Version', vertical='middle', justify='center', overflow='fold')

    for r in record_list:
        if r['vulnerable'] != 'SKIPPED':
            continue
        table.add_row('[bright_blue]' + r['pkg_name'], r['pkg_version'], end_section=True)

    if table.row_count:
        log.print(table)


def create_non_vulnerable_record(cpes: List[str], keywords: List[str], pkg_name: str, pkg_ver: str) -> Dict[str, str]:
    # Helper for creating a record of a non-vulnerable package.
    record = empty_record.copy()

    record['pkg_name'] = pkg_name
    record['pkg_version'] = pkg_ver
    if not cpes and not keywords:
        # There is no CPE record or keyword available, so the package was
        # not verified against the NVD.
        record['vulnerable'] = 'SKIPPED'
    else:
        record['vulnerable'] = 'NO'
        record['cpe'] = ', '.join(cpes)
        record['keyword'] = ', '.join(keywords)

    return record


def select_cvss_metric(metrics: Optional[Dict[str, List[Dict[str, Any]]]]) -> Optional[Dict[str, Any]]:
    """Select the CVSS metric that best matches what NVD shows for a CVE.

    NVD groups CVSS metrics by version (cvssMetricV40/V31/V30/V2). Each group is
    a list that may contain an NVD ``Primary`` score together with one or more
    CNA-provided ``Secondary`` scores. NVD displays the Primary score on the CVE
    page, so we prefer it; otherwise the report can pick a Secondary score with a
    different severity (e.g. CVE-2026-25532, where a Secondary scored 6.3/MEDIUM
    while NVD's Primary is 8.0/HIGH).

    Selection rule: the highest-version Primary metric, falling back to the first
    metric of the highest available version when no Primary is present. The
    ``type`` field is required by the NVD schema, but ``.get()`` is used
    defensively so a missing value simply degrades to the fallback.
    """
    if not metrics:
        return None

    version_order = ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')
    ordered_keys = [k for k in version_order if k in metrics]
    # Keep any unexpected keys as a last resort, preserving their original order.
    ordered_keys += [k for k in metrics if k not in version_order]

    # Prefer NVD's Primary metric, scanning from the highest CVSS version down.
    for key in ordered_keys:
        primary = next((m for m in metrics[key] if m.get('type') == 'Primary'), None)
        if primary is not None:
            return primary

    # No Primary present: use the first metric of the highest available version.
    for key in ordered_keys:
        if metrics[key]:
            return metrics[key][0]

    return None


def _exclude_reason(assessment: VexAssessment) -> str:
    """The text reported for an excluded CVE.

    A not_affected assessment carries an impact statement or a justification. A
    fixed one needs neither, so fall back to the status itself.
    """
    if assessment.impact_statement:
        return assessment.impact_statement
    if assessment.justification is not None:
        return str(assessment.justification)
    return str(assessment.status)


def create_vulnerable_record(
    vuln: Dict[str, Any],
    assessments: Dict[str, VexAssessment],
    cpe: str,
    keyword: str,
    pkg_name: str,
    pkg_ver: str,
    maybe: bool = False,
) -> Dict[str, str]:
    # Helper for creating a record of a discovered vulnerability.
    record = empty_record.copy()
    if not vuln:
        record['pkg_name'] = pkg_name
        record['pkg_version'] = pkg_ver
        record['vulnerable'] = 'NO'
        record['cpe'] = cpe
        return record

    cve_id = vuln['cve']['id']
    status = vuln['cve'].get('vulnStatus', '')
    cve_link = f'https://nvd.nist.gov/vuln/detail/{cve_id}'
    cve_desc = next((desc['value'] for desc in vuln['cve'].get('descriptions', []) if desc['lang'] == 'en'), '')
    vulnerable = ''
    exclude_reason = ''
    cvss_version = ''
    cvss_vector_string = ''
    cvss_base_score = ''
    cvss_base_severity = ''

    # Prefer NVD's Primary metric (see select_cvss_metric) so the reported
    # severity matches what NVD shows, rather than a CNA-provided Secondary score.
    cvss = select_cvss_metric(vuln['cve'].get('metrics'))

    if cvss:
        cvss_version = cvss['cvssData'].get('version', '')
        cvss_vector_string = cvss['cvssData'].get('vectorString', '')
        cvss_base_score = str(cvss['cvssData'].get('baseScore', ''))
        cvss_base_severity = cvss['cvssData'].get('baseSeverity', cvss.get('baseSeverity', ''))

    # NVD embeds CISA's Known Exploited Vulnerabilities catalog in the CVE record
    # itself, so being in KEV needs no separate feed. kev_added doubles as the
    # marker: it is set only for a CVE that is in the catalog.
    kev_added = vuln['cve'].get('cisaExploitAdd', '')
    kev_name = vuln['cve'].get('cisaVulnerabilityName', '')

    assessment = assessments.get(cve_id)
    if assessment is not None and assessment.known_status().suppresses:
        exclude_reason = _exclude_reason(assessment)
        vulnerable = 'EXCLUDED'
    elif assessment is not None and assessment.known_status().is_affected:
        # The VEX says that the CVE applies, so a keyword or NA-version match is
        # confirmed.
        vulnerable = 'YES'
    elif maybe:
        # The caller could not confirm the CVE applies to the scanned version (a
        # keyword-description match, or a match against a CPE whose version is
        # NA), so report it as MAYBE for manual review rather than asserting YES.
        vulnerable = 'MAYBE'
    else:
        vulnerable = 'YES'

    record['pkg_name'] = pkg_name
    record['pkg_version'] = pkg_ver
    record['vulnerable'] = vulnerable
    record['exclude_reason'] = exclude_reason
    record['cve_id'] = cve_id
    record['cve_link'] = cve_link
    record['cve_desc'] = cve_desc
    record['cpe'] = cpe
    record['keyword'] = keyword
    record['cvss_version'] = cvss_version
    record['cvss_vector_string'] = cvss_vector_string
    record['cvss_base_score'] = cvss_base_score
    record['cvss_base_severity'] = cvss_base_severity
    record['status'] = status
    record['kev_added'] = kev_added
    record['kev_name'] = kev_name
    if assessment is not None:
        record['vex_status'] = str(assessment.status)
        record['vex_justification'] = str(assessment.justification) if assessment.justification else ''
        record['vex_detail'] = assessment.impact_statement
        record['vex_action'] = assessment.action_statement

    return record


def find_record_by_cve(records: List[Dict[str, str]], cve_id: str) -> Optional[Dict[str, str]]:
    # Helper for verifying if a CVE is already recorded. This helps to ensure
    # the CVE is reported only once, even if it is identified through various
    # keywords.
    for record in records:
        if record['cve_id'] == cve_id:
            return record
    return None


# The fields of a VEX statement, by the name in VexAssessment, and the keys of a
# statements file that set them.
_VEX_FIELDS = (
    ('status', 'status'),
    ('justification', 'justification'),
    ('impact_statement', 'detail'),
    ('action_statement', 'action'),
    ('response', 'response'),
)


def _vex_text(assessment: VexAssessment, field: str, vocabulary: str) -> str:
    """The value of a field in a vocabulary, cisa or cyclonedx, see vexvalues.py. A
    response has only a CycloneDX name."""
    value = getattr(assessment, field)
    if isinstance(value, list):
        return ', '.join(str(getattr(item, vocabulary, item)) for item in value)
    if value is None or isinstance(value, str):
        return value or ''
    return str(getattr(value, vocabulary))


def show_vex_update(sbom: SBOM, original: vex.Vex, statements: List[vex.Vex], vocabulary: str) -> None:
    """Print the statements of vex update to stderr.

    For each statement of the SBOM model, it prints the CVE and the package, and a
    table with the value of each field in original, the value that the statements
    files set and the new value. The values are in the vocabulary of the output
    format. So a field whose value changes in the model, but keeps its name, is not
    changed. For example, CycloneDX has code_not_present for two CISA
    justifications. A summary with the counts comes first, then the modified
    statements. A new statement is modified too, and has no old values.

    :param sbom: the SBOM model after the statements files are applied
    :param original: the VEX of the model before the statements files are applied
    :param statements: the statements files, in their order
    :param vocabulary: the vocabulary of the output format, see formats.VexFormat
    """
    old = {(product.ref, s.vulnerability): s for s in original.statements for product in s.products}
    # The fields that the statements files set for each package and CVE. As in
    # vex.apply(), the value of a later file wins.
    stated: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for vexdoc in statements:
        for statement in vexdoc.statements:
            for product in statement.products:
                for pkg in vex.find_packages(sbom, product):
                    values = stated.setdefault((pkg.ref, statement.vulnerability), {})
                    values.update({field: getattr(statement, field) for field in statement.keys or ()})

    cards: List[Tuple[bool, str, Table, Table]] = []
    # The CVEs whose status changed and the CVEs that no statements file names.
    status_changed: List[str] = []
    unstated: List[str] = []
    for pkg in sbom.packages:
        for assessment in pkg.assessments:
            key = (pkg.ref, assessment.vulnerability)
            before = old.get(key)
            stated_values = stated.get(key, {})
            stated_assessment = VexAssessment(vulnerability=assessment.vulnerability, **stated_values)
            # The table fills the console. Rich splits the width equally between Old,
            # Statement and New, so with less width a short value would wrap.
            fields = Table(expand=True)
            fields.add_column('Field', no_wrap=True)
            for name in ('Old', 'Statement', 'New'):
                fields.add_column(name, ratio=1, overflow='fold')
            changed = False
            for field, name in _VEX_FIELDS:
                old_text = _vex_text(before, field, vocabulary) if before is not None else ''
                new_text = _vex_text(assessment, field, vocabulary)
                stated_text = ''
                if field in stated_values:
                    # A key with an empty value removes the field.
                    stated_text = _vex_text(stated_assessment, field, vocabulary) or '(removed)'
                if old_text != new_text:
                    fields.add_row(
                        Text(name, 'yellow'), Text(old_text, 'red'), Text(stated_text), Text(new_text, 'green')
                    )
                    changed = True
                    if field == 'status' and before is not None:
                        status_changed.append(assessment.vulnerability)
                else:
                    fields.add_row(name, Text(old_text), Text(stated_text), Text(new_text))

            info = Table.grid(padding=(0, 1))
            info.add_column(style='yellow', no_wrap=True)
            info.add_column(no_wrap=True)
            info.add_row('CVE', Text(assessment.vulnerability, 'bold'))
            info.add_row('Package', Text(pkg.package_name, 'bright_blue'))
            info.add_row('Version', Text(pkg.version))
            info.add_row('Package id', Text('\n'.join([pkg.ref, *pkg.cpes])))
            info.add_row('Modified', 'yes' if changed else 'no')
            info.add_row('Statements', 'yes' if key in stated else 'no')
            if key not in stated:
                unstated.append(assessment.vulnerability)
            cards.append((changed, assessment.vulnerability, info, fields))

    # The modified statements first. sort() keeps the order of the others, so the
    # CVEs of each line of the summary are in the order of the statements.
    cards.sort(key=lambda card: not card[0])
    summary = Table(title='VEX update report', show_header=False)
    summary.add_column('key', no_wrap=True)
    summary.add_column('count')
    summary.add_column('CVEs')
    for name, cves in (
        ('Statements:', [card[1] for card in cards]),
        ('Modified:', [card[1] for card in cards if card[0]]),
        ('Status changed:', status_changed),
        ('In no statements file:', unstated),
    ):
        summary.add_row(name, str(len(cves)), Text(', '.join(cves)))

    report: List[Any] = [summary]
    for _, _, info, fields in cards:
        report += [Text(), info, fields]
    log.eprint(Group(*report))
