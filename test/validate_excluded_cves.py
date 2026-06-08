#!/usr/bin/env python

# SPDX-FileCopyrightText: 2024-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
from esp_idf_sbom.libsbom import CPE  # noqa: E402

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')
VERSION_KEYS = ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding')


def validate_scoped(cve_id: str, value: dict) -> list:
    errors = []
    if 'cpes' not in value:
        errors.append(f'{cve_id}: dict entry must have `cpes`')
        return errors
    cpes = value['cpes']
    if not isinstance(cpes, list) or not cpes:
        errors.append(f'{cve_id}: `cpes` must be a non-empty list')
        return errors
    for idx, entry in enumerate(cpes):
        if not isinstance(entry, dict):
            errors.append(f'{cve_id}: cpes[{idx}] must be a mapping')
            continue
        if 'cpe' not in entry:
            errors.append(f'{cve_id}: cpes[{idx}] missing `cpe`')
            continue
        cpe = entry['cpe']
        if not isinstance(cpe, str) or not CPE.is_cpe_valid(cpe):
            errors.append(f'{cve_id}: cpes[{idx}].cpe is not a valid CPE 2.3 string: {cpe!r}')
            continue
        cpe_version = cpe.split(':')[5]
        has_bound = any(k in entry for k in VERSION_KEYS)
        if cpe_version == '*' and not has_bound:
            # An ANY (*) version with no version bounds matches every version,
            # so it would suppress the CVE for all versions, including ones
            # where it is not fixed. Require bounds in that case.
            errors.append(
                f'{cve_id}: cpes[{idx}] has ANY (*) version in `cpe` and no '
                f'version bounds. This would suppress the CVE for all versions, '
                f'including unfixed ones'
            )
        # Pair sanity: Start*Including and Start*Excluding mutually exclusive (same for End*).
        if 'versionStartIncluding' in entry and 'versionStartExcluding' in entry:
            errors.append(f'{cve_id}: cpes[{idx}] has both versionStartIncluding and versionStartExcluding')
        if 'versionEndIncluding' in entry and 'versionEndExcluding' in entry:
            errors.append(f'{cve_id}: cpes[{idx}] has both versionEndIncluding and versionEndExcluding')
    return errors


for fn in sys.argv[1:]:
    with open(fn) as f:
        cves = yaml.safe_load(f)

    errors = []
    for cve, value in cves.items():
        if not CVE_RE.match(cve):
            errors.append(f'{cve} does not match CVE format')
            continue
        if isinstance(value, str):
            # Legacy unconditional exclusion -- string is the reason. No further checks.
            continue
        if isinstance(value, dict):
            errors += validate_scoped(cve, value)
            continue
        errors.append(f'{cve}: value must be a string (unconditional) or a mapping (CPE-scoped)')

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        sys.exit(1)
