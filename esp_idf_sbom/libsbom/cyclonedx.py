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

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom.sbom import SBOM
from esp_idf_sbom.libsbom.sbom import File
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


def _render_json(sbom: SBOM, version: str) -> str:
    serial = 'urn:uuid:' + str(uuid.uuid4())
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    by_ref = {pkg.ref: pkg for pkg in sbom.packages}

    dependencies = [{'ref': pkg.ref, 'dependsOn': list(pkg.depends_on)} for pkg in sbom.packages if pkg.depends_on]

    # Each cve-exclude entry is a VEX not_affected statement on its component.
    vulnerabilities: List[Dict[str, Any]] = []
    for pkg in sbom.packages:
        for entry in pkg.cve_exclude_list:
            vulnerabilities.append(
                {
                    'bom-ref': f'vex-{pkg.ref}-{entry["cve"]}',
                    'id': entry['cve'],
                    'analysis': {'state': 'not_affected', 'detail': entry['reason']},
                    'affects': [{'ref': pkg.ref}],
                }
            )

    bom: Dict[str, Any] = {
        'bomFormat': 'CycloneDX',
        'specVersion': version,
        'serialNumber': serial,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': {'components': [{'type': 'application', 'name': 'esp-idf-sbom', 'version': __version__}]},
        },
    }
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


# ===========================================================================
# Parse: CycloneDX JSON -> SBOM model
# ===========================================================================


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

    return SBOM(name=name, root=root_ref, packages=packages, creator=creator)


def parse(text: str, format: str = 'json') -> SBOM:
    """Parse a CycloneDX document into the format-neutral SBOM model.

    :param text: the CycloneDX document
    :param format: 'json' for CycloneDX JSON
    """
    if format == 'json':
        return _parse_json(text)
    raise ValueError(f'unsupported CycloneDX format: {format!r}')
