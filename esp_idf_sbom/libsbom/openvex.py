# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""OpenVEX backend for the format-neutral VEX model.

OpenVEX uses the CISA vocabulary, so this backend maps nothing. It writes the
status and justification values from the model as they are.

OpenVEX names products by purl and CPE. These belong to the package, not to a
document, so one OpenVEX file works with an SBOM in any format. This includes
SPDX 2.2, which has no VEX format of its own and is what create writes by
default. A CycloneDX VEX points into one SBOM document instead, and works only
with that document.

A package with no purl and no CPE cannot be named here, see _product().
"""

import datetime
import json
import uuid
from typing import Any
from typing import Dict
from typing import Optional

from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom import vex
from esp_idf_sbom.libsbom.sbom import TOOL_NAME
from esp_idf_sbom.libsbom.sbom import TOOL_PURL
from esp_idf_sbom.libsbom.sbom import TOOL_SUPPLIER
from esp_idf_sbom.libsbom.sbom import TOOL_VERSION

# TOOL_SUPPLIER has the SPDX form 'Organization: ...'. OpenVEX wants only the name.
_AUTHOR = TOOL_SUPPLIER.split(': ', 1)[-1]


def _product(product: vex.VexProduct) -> Optional[Dict[str, Any]]:
    """Convert a model product to an OpenVEX component.

    All fields are optional, so a product without identifiers is still valid, but
    no tool can match it. Such a product is dropped instead. check does not scan
    a package with no purl and no CPE by identity either.
    """
    identifiers: Dict[str, str] = {}
    if product.purl:
        identifiers['purl'] = product.purl
    if product.cpes:
        identifiers['cpe23'] = product.cpes[0]

    if not identifiers:
        log.warn(
            f'Package "{product.name or product.ref}" has no PURL or CPE. It cannot be '
            f'identified in an OpenVEX file, so its statements are not written.'
        )
        return None

    # OpenVEX suggests using the purl as the component IRI.
    return {'@id': identifiers.get('purl', product.ref), 'identifiers': identifiers}


def _statement(statement: vex.VexStatement) -> Optional[Dict[str, Any]]:
    products = [p for p in (_product(product) for product in statement.products) if p]
    if not products:
        return None

    entry: Dict[str, Any] = {
        'vulnerability': {'name': statement.vulnerability},
        'products': products,
        'status': statement.status.value,
    }
    # A not_affected statement needs a justification or an impact_statement. We
    # write the impact_statement, because the manifest reason is free text.
    if statement.justification is not None:
        entry['justification'] = statement.justification.value
    if statement.impact_statement:
        entry['impact_statement'] = statement.impact_statement
    if statement.action_statement:
        entry['action_statement'] = statement.action_statement

    return entry


def _render_json(vexdoc: vex.Vex, version: str) -> str:
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    statements = [s for s in (_statement(statement) for statement in vexdoc.statements) if s]

    # @id must be an IRI for this document. A urn:uuid is an IRI and does not use
    # a domain name we do not own.
    document: Dict[str, Any] = {
        '@context': f'https://openvex.dev/ns/v{version}',
        '@id': 'urn:uuid:' + str(uuid.uuid4()),
        'author': _AUTHOR,
        'timestamp': timestamp,
        'version': 1,
        'tooling': f'{TOOL_NAME} {TOOL_VERSION} ({TOOL_PURL})',
        'statements': statements,
    }

    return json.dumps(document, indent=2)


def render_vex(vexdoc: vex.Vex, format: str = 'json', version: str = '0.2.0') -> str:
    """Render a format-neutral VEX as a standalone OpenVEX document.

    :param vexdoc: the VEX model to serialize
    :param format: 'json', the only OpenVEX format
    :param version: the OpenVEX spec version to emit (currently '0.2.0')
    """
    if format == 'json':
        return _render_json(vexdoc, version)
    raise ValueError(f'unsupported OpenVEX format: {format!r}')
