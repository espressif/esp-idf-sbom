# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Parse VEX statements that a person writes in YAML into the VEX model.

The file keeps the statements about the CVEs of one SBOM, grouped by package:

    format-version: 1
    packages:
      - package: cpe:2.3:o:amazon:freertos:10.5.1:*:*:*:*:*:*:*
        vulnerabilities:
          - cve: CVE-2099-2222
            status: affected
            detail: The product calls the affected function from the TCP task.
            action: Update to ESP-IDF v5.5.2 in firmware 1.3.

A statement changes only the fields that the file sets, see VexStatement.keys. It
can also leave out the status, see VexAssessment.status. A key with an empty
value removes the field. The package can be named by any id that the SBOM or a
VEX file shows for it, see _product(). vex.find_packages() then finds it in the
SBOM. Unknown keys are ignored, so that a newer version of the tool can add keys.
A change that an older version must not ignore needs a new FORMAT_VERSION.
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

# The version of the file format. Increase it only for a change that an older
# esp-idf-sbom must not ignore, for example a key that limits the packages that a
# statement applies to. An older esp-idf-sbom then stops instead of misreading the
# file. A new key that it can ignore keeps the version.
FORMAT_VERSION = 1


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


def _check_justification(value: str) -> bool:
    """A justification, or an empty value, which removes it."""
    return value == '' or _one_of(_JUSTIFICATIONS, 'Justification')(value)


def _check_responses(value: Any) -> bool:
    if not isinstance(value, list):
        raise schema.SchemaError('The response must be a list, for example [update].')
    check = _one_of(_RESPONSES, 'Response')
    return all(check(response) for response in value)


# A status can be named by its CISA or its CycloneDX name, for example affected or
# exploitable.
_STATUSES = vex.VexStatus.names()
_JUSTIFICATIONS = vex.VexJustification.names()
_RESPONSES = vex.VexResponse.names()

_PACKAGE = schema.Schema(
    {
        'package': schema.And(str, _not_empty),
        'vulnerabilities': list,
    },
    ignore_extra_keys=True,
)

_VULNERABILITY = schema.Schema(
    {
        'cve': schema.And(str, _not_empty),
        schema.Optional('status'): schema.And(str, _one_of(_STATUSES, 'Status')),
        schema.Optional('justification'): schema.And(str, _check_justification),
        schema.Optional('detail'): str,
        schema.Optional('action'): str,
        schema.Optional('response'): _check_responses,
    },
    ignore_extra_keys=True,
)


def _fields(entry: Dict[str, Any]) -> Dict[str, Any]:
    """The fields that a statement sets, as VexAssessment names them. An empty value
    removes the field."""
    values: Dict[str, Any] = {}
    if 'status' in entry:
        values['status'] = vex.VexStatus(entry['status'])
    if 'justification' in entry:
        values['justification'] = vex.VexJustification(entry['justification']) if entry['justification'] else None
    if 'detail' in entry:
        values['impact_statement'] = entry['detail']
    if 'action' in entry:
        values['action_statement'] = entry['action']
    if 'response' in entry:
        values['response'] = [vex.VexResponse(value) for value in entry['response']]
    return values


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

    Each CVE of a package becomes one statement for that package. Its keys are the
    fields that the file sets, and the other fields have their default values. A
    statement without a status has None. The statements have no times. The SBOM id
    is set when a package id names the SBOM, which a BOM-Link and an SPDX 3.0.1
    element id do. Raise ValueError when the file is not valid, also when its
    format-version is not FORMAT_VERSION. A file without format-version has
    version 1.
    """
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f'The file is not valid YAML: {e}')
    if not isinstance(document, dict):
        raise ValueError('The file needs a "packages" list.')
    # Checked first, because a newer format can also change the other keys.
    version = document.get('format-version', 1)
    if type(version) is not int or version != FORMAT_VERSION:
        raise ValueError(
            f'The file has format-version {version!r}. This version of esp-idf-sbom reads only '
            f'format-version {FORMAT_VERSION}. Update esp-idf-sbom.'
        )
    if not isinstance(document.get('packages'), list):
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
            values = _fields(cve_entry)
            statements.append(
                vex.VexStatement(vulnerability=cve_entry['cve'], products=[product], keys=frozenset(values), **values)
            )

    return vex.Vex(statements=statements, sbom_id=sbom_id, sbom_version=sbom_version)
