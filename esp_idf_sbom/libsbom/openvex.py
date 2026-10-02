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
from esp_idf_sbom.libsbom.sbom import TOOL_VERSION

# OpenVEX requires an author. Without a manufacturer in the project manifest, use
# the default of go-vex, the OpenVEX reference library.
_UNKNOWN_AUTHOR = 'Unknown Author'


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

    vulnerability: Dict[str, Any] = {'name': statement.vulnerability}
    if statement.nvd_url:
        vulnerability['@id'] = statement.nvd_url
    entry: Dict[str, Any] = {'vulnerability': vulnerability}
    if statement.first_issued:
        entry['timestamp'] = statement.first_issued
    if statement.last_updated:
        entry['last_updated'] = statement.last_updated
    entry['products'] = products
    entry['status'] = statement.status.value
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
    # timestamp is when the document was first issued.
    timestamp = vexdoc.first_issued or datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    statements = [s for s in (_statement(statement) for statement in vexdoc.statements) if s]

    # @id must be an IRI for this document. A urn:uuid is an IRI and does not use
    # a domain name we do not own.
    document: Dict[str, Any] = {
        '@context': f'https://openvex.dev/ns/v{version}',
        '@id': vexdoc.doc_id or 'urn:uuid:' + str(uuid.uuid4()),
        # The manufacturer name has the form 'Organization: ...'. OpenVEX wants only the name.
        'author': vexdoc.manufacturer.name.split(': ', 1)[-1] or _UNKNOWN_AUTHOR,
        'timestamp': timestamp,
    }
    if vexdoc.last_updated:
        document['last_updated'] = vexdoc.last_updated
    document['version'] = vexdoc.doc_version
    document['tooling'] = f'{TOOL_NAME} {TOOL_VERSION} ({TOOL_PURL})'
    document['statements'] = statements

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


# ===========================================================================
# Parse: OpenVEX -> VEX model
# ===========================================================================


def _parse_product(product: Dict[str, Any]) -> vex.VexProduct:
    identifiers = product.get('identifiers', {})
    cpe = identifiers.get('cpe23') or identifiers.get('cpe22') or ''
    purl = identifiers.get('purl', '')
    if not purl and str(product.get('@id', '')).startswith('pkg:'):
        # render() writes the purl as the @id, so read it back from there when
        # the file has no identifiers map.
        purl = str(product['@id'])
    return vex.VexProduct(purl=purl, cpes=[cpe] if cpe else [])


def _parse_statement(statement: Dict[str, Any], issued: str) -> Optional[vex.VexStatement]:
    try:
        status = vex.VexStatus(statement.get('status', ''))
    except ValueError:
        # status is required and its values are fixed, so anything else is not a
        # statement we can use.
        log.warn(f'Skipping OpenVEX statement with unknown status "{statement.get("status", "")}".')
        return None

    first_issued = statement.get('timestamp') or issued
    justification = None
    if statement.get('justification'):
        try:
            justification = vex.VexJustification(statement['justification'])
        except ValueError:
            log.warn(f'Ignoring unknown OpenVEX justification "{statement["justification"]}".')

    return vex.VexStatement(
        vulnerability=statement.get('vulnerability', {}).get('name', ''),
        status=status,
        products=[_parse_product(p) for p in statement.get('products', [])],
        justification=justification,
        impact_statement=statement.get('impact_statement', ''),
        action_statement=statement.get('action_statement', ''),
        first_issued=first_issued,
        last_updated=statement.get('last_updated') or first_issued,
    )


def parse_vex(text: str) -> vex.Vex:
    """Parse an OpenVEX document into the format-neutral VEX model.

    OpenVEX uses the CISA values, so status and justification are read as they
    are. The document does not name an SBOM, so sbom_id stays empty. A statement
    without a timestamp gets the timestamp of the document, as the OpenVEX
    inheritance rules say. A statement without last_updated was not changed since
    it was first issued, as CISA says the two are initially the same.
    """
    document = json.loads(text)
    issued = document.get('timestamp', '')
    statements = [s for s in (_parse_statement(s, issued) for s in document.get('statements', [])) if s]
    return vex.Vex(
        statements=statements,
        doc_id=document.get('@id', ''),
        doc_version=int(document.get('version', 1)),
        first_issued=issued,
        last_updated=document.get('last_updated', ''),
        author=document.get('author', ''),
    )
