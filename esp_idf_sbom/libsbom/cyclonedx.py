# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""CycloneDX backend for the format-neutral SBOM model.

render() serializes the model to CycloneDX 1.6 JSON and parse() reads it back.
The model maps to CycloneDX components plus a dependencies graph; the per-package
cve-exclude-list is rendered as native CycloneDX VEX -- a vulnerability with
analysis.state = not_affected affecting the component.

A CycloneDX component carries a single native cpe, so the first CPE goes there
and any extras are carried as standard identity evidence (evidence.identity[]).
The cve-keywords, which have no native slot, are kept as a namespaced property.
Both round-trip and keep check seeing every CPE.
"""

import datetime
import json
import uuid
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import List

from esp_idf_sbom.libsbom import vex
from esp_idf_sbom.libsbom.sbom import SBOM
from esp_idf_sbom.libsbom.sbom import TOOL_DISTRIBUTION_URL
from esp_idf_sbom.libsbom.sbom import TOOL_LICENSE
from esp_idf_sbom.libsbom.sbom import TOOL_NAME
from esp_idf_sbom.libsbom.sbom import TOOL_PURL
from esp_idf_sbom.libsbom.sbom import TOOL_SUPPLIER
from esp_idf_sbom.libsbom.sbom import TOOL_SUPPLIER_URL
from esp_idf_sbom.libsbom.sbom import TOOL_URL
from esp_idf_sbom.libsbom.sbom import TOOL_VERSION
from esp_idf_sbom.libsbom.sbom import File
from esp_idf_sbom.libsbom.sbom import Organization
from esp_idf_sbom.libsbom.sbom import Package
from esp_idf_sbom.libsbom.sbom import PackageKind
from esp_idf_sbom.libsbom.sbom import kind_and_name
from esp_idf_sbom.libsbom.sbom import simplify_licenses

# Namespaced component property for data CycloneDX has no native slot for. Extra
# CPEs use the standard evidence.identity[] instead (see _component).
_PROP_CVE_KEYWORD = 'esp-idf-sbom:cve-keyword'

# The model's package role -> CycloneDX component type (default 'library').
_KIND_TYPE = {
    PackageKind.PROJECT: 'application',
    PackageKind.FRAMEWORK: 'framework',
    PackageKind.TOOLCHAIN: 'application',
}


# ===========================================================================
# Render: SBOM model -> CycloneDX 1.6 JSON
# ===========================================================================


def _supplier_name(supplier: str) -> str:
    """Drop the SPDX-style 'Organization: ' / 'Person: ' prefix; a CycloneDX
    supplier is already an organizational entity."""
    for prefix in ('Organization: ', 'Person: '):
        if supplier.startswith(prefix):
            return supplier[len(prefix) :]
    return supplier


def _entity(org: Organization) -> Dict[str, Any]:
    """Render a document-level Organization as a CycloneDX organizationalEntity."""
    entity: Dict[str, Any] = {}
    if org.name:
        entity['name'] = _supplier_name(org.name)
    if org.url:
        entity['url'] = [org.url]
    if org.contact_email:
        entity['contact'] = [{'email': org.contact_email}]
    return entity


def _tool_component() -> Dict[str, Any]:
    """The metadata.tools entry for this tool. Since CycloneDX 1.5 such entries
    are full components, so the tool identifies itself as any component does.
    """
    return {
        'type': 'application',
        'name': TOOL_NAME,
        'version': TOOL_VERSION,
        'supplier': {'name': _supplier_name(TOOL_SUPPLIER), 'url': [TOOL_SUPPLIER_URL]},
        'purl': TOOL_PURL,
        'licenses': [{'license': {'id': TOOL_LICENSE}}],
        'externalReferences': [
            {'type': 'vcs', 'url': TOOL_URL},
            {'type': 'distribution', 'url': TOOL_DISTRIBUTION_URL},
        ],
    }


def _component(pkg: Package) -> Dict[str, Any]:
    comp: Dict[str, Any] = {
        'type': _KIND_TYPE.get(pkg.kind, 'library'),
        'bom-ref': pkg.ref,
        'name': pkg.package_name,
    }
    if pkg.version:
        comp['version'] = pkg.version
    supplier = _supplier_name(pkg.supplier)
    if supplier:
        comp['supplier'] = {'name': supplier}
    if pkg.originator:
        comp['publisher'] = _supplier_name(pkg.originator)
    if pkg.description:
        comp['description'] = pkg.description
    expr = simplify_licenses(pkg.licenses_concluded | pkg.licenses_declared)
    if expr:
        comp['licenses'] = [{'expression': expr}]
    if pkg.copyrights:
        comp['copyright'] = '\n'.join(sorted(pkg.copyrights))
    if pkg.cpes:
        comp['cpe'] = pkg.cpes[0]
    if pkg.purl:
        comp['purl'] = pkg.purl
    if pkg.checksum_sha256:
        comp['hashes'] = [{'alg': 'SHA-256', 'content': pkg.checksum_sha256}]
    extrefs: List[Dict[str, str]] = []
    if pkg.repository:
        extrefs.append({'type': 'vcs', 'url': pkg.repository})
    if pkg.download_url:
        extrefs.append({'type': 'distribution', 'url': pkg.download_url})
    if extrefs:
        comp['externalReferences'] = extrefs

    # A component has a single native 'cpe'; the first goes there and the rest are
    # carried as standard identity evidence (CycloneDX 1.6 evidence.identity[]).
    if len(pkg.cpes) > 1:
        comp['evidence'] = {'identity': [{'field': 'cpe', 'concludedValue': cpe} for cpe in pkg.cpes[1:]]}

    properties: List[Dict[str, str]] = [{'name': _PROP_CVE_KEYWORD, 'value': kw} for kw in pkg.cve_keywords]
    if properties:
        comp['properties'] = properties

    if pkg.files:
        comp['components'] = [_file_component(pkg, f, i) for i, f in enumerate(pkg.files)]

    return comp


def _file_component(pkg: Package, file: File, index: int) -> Dict[str, Any]:
    """A file inside a package, as a nested CycloneDX component of type 'file'."""
    fcomp: Dict[str, Any] = {
        'type': 'file',
        'bom-ref': f'{pkg.ref}-File-{index}',
        'name': file.path,
        'hashes': [
            {'alg': 'SHA-1', 'content': file.sha1},
            {'alg': 'SHA-256', 'content': file.sha256},
        ],
    }
    if file.license_concluded:
        fcomp['licenses'] = [{'expression': file.license_concluded}]
    if file.copyrights:
        fcomp['copyright'] = '\n'.join(sorted(file.copyrights))
    return fcomp


# The CISA values used by the model, mapped to the larger CycloneDX ones. Only
# this backend needs a map. OpenVEX and SPDX 3.0.1 use the CISA values.
_ANALYSIS_STATE = {
    vex.VexStatus.NOT_AFFECTED: 'not_affected',
    vex.VexStatus.AFFECTED: 'exploitable',
    vex.VexStatus.FIXED: 'resolved',
    vex.VexStatus.UNDER_INVESTIGATION: 'in_triage',
}

# component_not_present and vulnerable_code_not_present both map to
# code_not_present, so this map cannot be reversed. Parsing reads back the status
# and the detail text, not the justification.
_ANALYSIS_JUSTIFICATION = {
    vex.VexJustification.COMPONENT_NOT_PRESENT: 'code_not_present',
    vex.VexJustification.VULNERABLE_CODE_NOT_PRESENT: 'code_not_present',
    vex.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: 'code_not_reachable',
    vex.VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: 'protected_at_runtime',
    vex.VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST: 'protected_by_mitigating_control',
}


def _vulnerability(statement: vex.VexStatement, bom_link: str = '') -> Dict[str, Any]:
    """Convert a VEX statement to a CycloneDX vulnerability entry.

    In an SBOM the affected components are named by their bom-ref. A standalone
    VEX has no components, so bom_link holds the 'urn:cdx:<serial>/<version>' of
    the SBOM and the refs become BOM-Links into it.
    """
    analysis: Dict[str, Any] = {'state': _ANALYSIS_STATE[statement.status]}
    if statement.justification is not None:
        analysis['justification'] = _ANALYSIS_JUSTIFICATION[statement.justification]
    analysis['detail'] = statement.impact_statement

    return {
        'bom-ref': f'vex-{statement.products[0].ref}-{statement.vulnerability}',
        'id': statement.vulnerability,
        'analysis': analysis,
        'affects': [{'ref': f'{bom_link}#{p.ref}' if bom_link else p.ref} for p in statement.products],
    }


def _render_json(sbom: SBOM, version: str) -> str:
    serial = 'urn:uuid:' + str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    by_ref = {pkg.ref: pkg for pkg in sbom.packages}

    dependencies = [{'ref': pkg.ref, 'dependsOn': list(pkg.depends_on)} for pkg in sbom.packages if pkg.depends_on]

    vulnerabilities = [_vulnerability(statement) for statement in vex.build(sbom).statements]

    bom: Dict[str, Any] = {
        'bomFormat': 'CycloneDX',
        'specVersion': version,
        'serialNumber': serial,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': {'components': [_tool_component()]},
        },
    }
    # Two separate facts, and consumers differ on which one they read.
    if sbom.supplier:
        bom['metadata']['supplier'] = _entity(sbom.supplier)
    if sbom.manufacturer:
        bom['metadata']['manufacturer'] = _entity(sbom.manufacturer)
    root = by_ref.get(sbom.root)
    if root is not None:
        bom['metadata']['component'] = _component(root)
    components = [_component(pkg) for pkg in sbom.packages if pkg.ref != sbom.root]
    if components:
        bom['components'] = components
    if dependencies:
        bom['dependencies'] = dependencies
    if vulnerabilities:
        bom['vulnerabilities'] = vulnerabilities

    return json.dumps(bom, indent=2)


def render(sbom: SBOM, format: str = 'json', version: str = '1.6') -> str:
    """Render a format-neutral SBOM as a CycloneDX document.

    :param sbom: the SBOM model to serialize
    :param format: 'json' for CycloneDX JSON
    :param version: the CycloneDX spec version to emit (currently '1.6')
    """
    if format == 'json':
        return _render_json(sbom, version)
    raise ValueError(f'unsupported CycloneDX format: {format!r}')


def _bom_link(vexdoc: vex.Vex) -> str:
    """Return the BOM-Link for the SBOM this VEX belongs to.

    The schema pattern is ^urn:cdx:<uuid>/[1-9][0-9]*$, so the serialNumber is
    used without the urn:uuid: prefix.
    """
    if not vexdoc.sbom_id:
        raise ValueError('a standalone CycloneDX VEX needs the serialNumber of its SBOM')
    prefix = 'urn:uuid:'
    serial = vexdoc.sbom_id[len(prefix) :] if vexdoc.sbom_id.startswith(prefix) else vexdoc.sbom_id
    return f'urn:cdx:{serial}/{vexdoc.sbom_version}'


def _render_vex_json(vexdoc: vex.Vex, version: str) -> str:
    serial = 'urn:uuid:' + str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    link = _bom_link(vexdoc)

    # A BOM with assessments only, no components and no dependencies. The SBOM is
    # referenced twice: once for the whole document, so that tools can find it, and
    # once in every affects[] entry, so that each statement can be resolved alone.
    bom: Dict[str, Any] = {
        'bomFormat': 'CycloneDX',
        'specVersion': version,
        'serialNumber': serial,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': {'components': [_tool_component()]},
        },
        'externalReferences': [
            {
                'type': 'bom',
                'url': link,
                'comment': f'SBOM this VEX applies to: {vexdoc.sbom_name}',
            }
        ],
        'vulnerabilities': [_vulnerability(statement, bom_link=link) for statement in vexdoc.statements],
    }

    return json.dumps(bom, indent=2)


def render_vex(vexdoc: vex.Vex, format: str = 'json', version: str = '1.6') -> str:
    """Render a format-neutral VEX as a standalone CycloneDX document.

    :param vexdoc: the VEX model to serialize
    :param format: 'json' for CycloneDX JSON
    :param version: the CycloneDX spec version to emit (currently '1.6')
    """
    if format == 'json':
        return _render_vex_json(vexdoc, version)
    raise ValueError(f'unsupported CycloneDX VEX format: {format!r}')


# ===========================================================================
# Parse: CycloneDX JSON -> SBOM model
# ===========================================================================


def _entity_to_organization(entity: Dict[str, Any]) -> Organization:
    """Read a CycloneDX organizationalEntity back into an Organization.

    The name comes back without the prefix render strips, as package suppliers
    do. _supplier_name leaves an unprefixed name alone, so a re-render matches.
    """
    urls = entity.get('url', [])
    contacts = entity.get('contact', [])
    return Organization(
        name=entity.get('name', ''),
        url=urls[0] if urls else '',
        contact_email=next((c.get('email', '') for c in contacts if c.get('email')), ''),
    )


def _package_from_component(
    comp: Dict[str, Any], depends_on: List[str], cve_exclude_list: List[Dict[str, str]]
) -> Package:
    ref = comp.get('bom-ref', '')
    kind, name = kind_and_name(ref)

    cpes: List[str] = []
    if comp.get('cpe'):
        cpes.append(comp['cpe'])
    # Extra CPEs come from identity evidence; identity may be a single object
    # (CycloneDX 1.5) or an array (1.6).
    identity = comp.get('evidence', {}).get('identity', [])
    if isinstance(identity, dict):
        identity = [identity]
    for entry in identity:
        if entry.get('field') == 'cpe' and entry.get('concludedValue'):
            cpes.append(entry['concludedValue'])

    cve_keywords: List[str] = []
    for prop in comp.get('properties', []):
        if prop.get('name') == _PROP_CVE_KEYWORD:
            cve_keywords.append(prop.get('value', ''))

    repository = ''
    download_url = ''
    for extref in comp.get('externalReferences', []):
        if extref.get('type') == 'vcs' and not repository:
            repository = extref.get('url', '')
        elif extref.get('type') == 'distribution' and not download_url:
            download_url = extref.get('url', '')

    checksum = ''
    for entry in comp.get('hashes', []):
        if entry.get('alg') == 'SHA-256':
            checksum = entry.get('content', '')
            break

    return Package(
        ref=ref,
        name=name,
        package_name=comp.get('name', ''),
        kind=kind,
        version=comp.get('version', ''),
        description=comp.get('description', ''),
        supplier=comp.get('supplier', {}).get('name', ''),
        originator=comp.get('publisher', ''),
        repository=repository,
        download_url=download_url,
        purl=comp.get('purl', ''),
        cpes=cpes,
        checksum_sha256=checksum,
        cve_exclude_list=cve_exclude_list,
        cve_keywords=cve_keywords,
        depends_on=depends_on,
    )


def _parse_json(text: str) -> SBOM:
    bom = json.loads(text)

    components: List[Dict[str, Any]] = []
    root_ref = ''
    meta_component = bom.get('metadata', {}).get('component')
    if meta_component:
        components.append(meta_component)
        root_ref = meta_component.get('bom-ref', '')
    components.extend(bom.get('components', []))

    depends_on = {dep.get('ref', ''): list(dep.get('dependsOn', [])) for dep in bom.get('dependencies', [])}

    # VEX not_affected statements -> per-component cve-exclude-list.
    excludes: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for vuln in bom.get('vulnerabilities', []):
        if vuln.get('analysis', {}).get('state') != 'not_affected':
            continue
        entry = {'cve': vuln.get('id', ''), 'reason': vuln.get('analysis', {}).get('detail', '')}
        for affect in vuln.get('affects', []):
            ref = affect.get('ref', '')
            if ref:
                excludes[ref].append(entry)

    packages = [
        _package_from_component(c, depends_on.get(c.get('bom-ref', ''), []), excludes.get(c.get('bom-ref', ''), []))
        for c in components
    ]

    # The producing tool, used only for the provenance note in cmd_check. In
    # CycloneDX 1.5+ metadata.tools is an object with a components list; in 1.4 it
    # was a plain list of tool objects -- accept both.
    creator = ''
    tools = bom.get('metadata', {}).get('tools', {})
    tool_list = tools.get('components', []) if isinstance(tools, dict) else tools
    for tool in tool_list:
        if isinstance(tool, dict) and tool.get('name'):
            creator = tool['name']
            break

    if not root_ref and packages:
        root_ref = packages[0].ref
    name = meta_component.get('name', '') if meta_component else ''
    if not name and packages:
        name = packages[0].package_name

    metadata = bom.get('metadata', {})
    return SBOM(
        name=name,
        root=root_ref,
        supplier=_entity_to_organization(metadata.get('supplier', {})),
        manufacturer=_entity_to_organization(metadata.get('manufacturer', {})),
        packages=packages,
        creator=creator,
    )


def parse(text: str, format: str = 'json') -> SBOM:
    """Parse a CycloneDX document into the format-neutral SBOM model.

    :param text: the CycloneDX document
    :param format: 'json' for CycloneDX JSON
    """
    if format == 'json':
        return _parse_json(text)
    raise ValueError(f'unsupported CycloneDX format: {format!r}')
