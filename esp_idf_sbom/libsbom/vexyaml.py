# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Parse VEX statements that a person writes in YAML into the VEX model.

The file keeps the statements about the CVEs of one SBOM, grouped by package:

    packages:
      - package: cpe:2.3:o:amazon:freertos:10.5.1:*:*:*:*:*:*:*
        vulnerabilities:
          - cve: CVE-2099-2222
            status: affected
            detail: The product calls the affected function from the TCP task.
            action: Update to ESP-IDF v5.5.2 in firmware 1.3.

The package can be named by any id that the SBOM or a VEX file shows for it, see
_product(). vex.find_packages() then finds it in the SBOM. Unknown keys are
ignored, so that a newer version of the tool can add keys.
"""

from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

import schema
import yaml

from esp_idf_sbom.libsbom import cyclonedx
from esp_idf_sbom.libsbom import spdx
from esp_idf_sbom.libsbom import vex


def _one_of(values: List[str], what: str) -> Callable[[str], bool]:
    def check(value: str) -> bool:
        if value in values:
            return True
        raise schema.SchemaError(f'{what} "{value}" must be one of: {", ".join(values)}.')

    return check


def _not_empty(value: str) -> bool:
    if value:
        return True
    raise schema.SchemaError('The value must not be empty.')


def _check_status_fields(entry: Dict[str, Any]) -> bool:
    """The fields that a status needs or allows, as CISA describes them."""
    status = entry['status']
    if 'justification' in entry and status != vex.VexStatus.NOT_AFFECTED.value:
        raise schema.SchemaError('A justification is only for the not_affected status.')
    if status == vex.VexStatus.NOT_AFFECTED.value and not entry.get('justification') and not entry.get('detail'):
        raise schema.SchemaError('The not_affected status needs a justification or a detail.')
    if status == vex.VexStatus.AFFECTED.value and not entry.get('action'):
        raise schema.SchemaError('The affected status needs an action.')
    return True


def _check_responses(value: Any) -> bool:
    if not isinstance(value, list):
        raise schema.SchemaError('The response must be a list, for example [update].')
    check = _one_of(_RESPONSES, 'Response')
    return all(check(response) for response in value)


_STATUSES = [status.value for status in vex.VexStatus]
_JUSTIFICATIONS = [justification.value for justification in vex.VexJustification]
_RESPONSES = [response.value for response in vex.VexResponse]

_PACKAGE = schema.Schema(
    {
        'package': schema.And(str, _not_empty),
        'vulnerabilities': list,
    },
    ignore_extra_keys=True,
)

# The flag must be on And, because And checks the dict with its own flag.
_VULNERABILITY = schema.And(
    {
        'cve': schema.And(str, _not_empty),
        'status': schema.And(str, _one_of(_STATUSES, 'Status')),
        schema.Optional('justification'): schema.And(str, _one_of(_JUSTIFICATIONS, 'Justification')),
        schema.Optional('detail'): str,
        schema.Optional('action'): str,
        schema.Optional('response'): _check_responses,
    },
    _check_status_fields,
    ignore_extra_keys=True,
)


def _product(package: str) -> Tuple[vex.VexProduct, str, int]:
    """The product that a package id names, and the id and version of the SBOM
    that the id names, if it names one.

    A CPE 2.3 string and a PURL are used as they are. A BOM-Link, an SPDX 2.2 id
    and an SPDX 3.0.1 element id give the ref of the package. Any other value is
    a ref or a package name, and find_packages() tries the ref first.
    """
    if package.startswith('cpe:2.3:'):
        return vex.VexProduct(cpes=[package]), '', 1
    if package.startswith('cpe:'):
        raise ValueError(f'"{package}" is not a CPE 2.3 string.')
    if package.startswith('pkg:'):
        return vex.VexProduct(purl=package), '', 1
    link = cyclonedx.parse_bom_link(package)
    if link is not None:
        ref, sbom_id, version = link
        return vex.VexProduct(ref=ref), sbom_id, version
    element = spdx.split_element_id(package)
    if element is not None:
        namespace, ref = element
        return vex.VexProduct(ref=ref), namespace, 1
    ref = spdx.unref(package)
    if ref != package:
        return vex.VexProduct(ref=ref), '', 1
    return vex.VexProduct(ref=package, name=package), '', 1


def parse_vex(text: str) -> vex.Vex:
    """Parse the YAML file into the VEX model.

    Each CVE of a package becomes one statement for that package. The statements
    have no times. The SBOM id is set when a package id names the SBOM, which a
    BOM-Link and an SPDX 3.0.1 element id do. Raise ValueError when the file is
    not valid.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f'The file is not valid YAML: {e}')
    if not isinstance(document, dict) or not isinstance(document.get('packages'), list):
        raise ValueError('The file needs a "packages" list.')

    statements = []
    sbom_id, sbom_version = '', 1
    for index, entry in enumerate(document['packages']):
        where = f'packages[{index}]'
        try:
            _PACKAGE.validate(entry)
            product, link_id, link_version = _product(entry['package'])
        except (schema.SchemaError, ValueError) as e:
            raise ValueError(f'{where}: {e}')
        where += f' ({entry["package"]})'

        if link_id:
            if sbom_id and (link_id, link_version) != (sbom_id, sbom_version):
                raise ValueError(f'{where}: the packages name more than one SBOM, "{sbom_id}" and "{link_id}".')
            sbom_id, sbom_version = link_id, link_version

        for cve_index, cve_entry in enumerate(entry['vulnerabilities']):
            cve_where = f'{where}: vulnerabilities[{cve_index}]'
            if isinstance(cve_entry, dict) and isinstance(cve_entry.get('cve'), str):
                cve_where += f' ({cve_entry["cve"]})'
            try:
                _VULNERABILITY.validate(cve_entry)
            except schema.SchemaError as e:
                raise ValueError(f'{cve_where}: {e}')

            status = vex.VexStatus(cve_entry['status'])
            justification = cve_entry.get('justification')
            # Without a response, not_affected gets will_not_fix, like a cve-exclude-list
            # entry in sbom.assessment_from_exclusion().
            default = [vex.VexResponse.WILL_NOT_FIX.value] if status is vex.VexStatus.NOT_AFFECTED else []
            statements.append(
                vex.VexStatement(
                    vulnerability=cve_entry['cve'],
                    status=status,
                    justification=vex.VexJustification(justification) if justification else None,
                    response=[vex.VexResponse(value) for value in cve_entry.get('response', default)],
                    impact_statement=cve_entry.get('detail', ''),
                    action_statement=cve_entry.get('action', ''),
                    products=[product],
                )
            )

    return vex.Vex(statements=statements, sbom_id=sbom_id, sbom_version=sbom_version)
