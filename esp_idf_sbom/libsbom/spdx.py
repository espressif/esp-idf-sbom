# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""SPDX backend for the format-neutral SBOM model.

render() serializes the model to SPDX (2.2 tag/value and JSON, 3.0 JSON-LD) and
parse() reads those back into the model. All gathering (project_description.json,
manifests, git) lives in libsbom/sbom.py; this module only maps between the model
and the SPDX serializations, as the section comments below describe.
"""

import datetime
import hashlib
import json
import re
import sys
import uuid
from typing import Any
from typing import Dict
from typing import List

import yaml

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom.sbom import SBOM
from esp_idf_sbom.libsbom.sbom import File
from esp_idf_sbom.libsbom.sbom import Package
from esp_idf_sbom.libsbom.sbom import PackageKind
from esp_idf_sbom.libsbom.sbom import kind_and_name
from esp_idf_sbom.libsbom.sbom import simplify_licenses

# ===========================================================================
# Render: format-neutral SBOM model -> SPDX serialization
#
# Inverse of the SBOM* build path in libsbom/sbom.py: the model stores raw
# values (absent = '' or empty set, refs without the SPDXRef- prefix, the
# cve-exclude-list kept structured), and render() reapplies the SPDX
# serialization tokens the builder deliberately left out: NOASSERTION for
# unspecified values, the <text>...</text> wrappers, the SPDXRef-/SPDXRef-FILE-
# prefixes, the package verification code computed from file SHA1s and the
# PackageComment YAML. The flat, ordered SBOM.packages list mirrors the order
# the tag/value document emits packages, so a single pass reproduces it.
# ===========================================================================

# SPDXID values may only contain letters, numbers, '.' and '-' (SPDX 2.2
# 3.2.4); same character class as the model's SBOMObject.sanitize.
_SPDXID_RE = re.compile(r'[^0-9a-zA-Z.\-]')


def _sanitize_spdxid(value: str) -> str:
    return _SPDXID_RE.sub('-', value)


def _verification_code(sha1s: List[str]) -> str:
    """Package verification code: SHA1 of the sorted, concatenated file SHA1s
    (SPDX 2.2 3.9.4)."""
    return hashlib.sha1(''.join(sorted(sha1s)).encode()).hexdigest()


def _package_comment(pkg: Package) -> str:
    """Reconstruct the PackageComment body (without the <text> wrapper) from the
    structured cve-exclude-list / cve-keywords carried on the model."""
    comment = ''

    if pkg.cve_exclude_list:
        cve_info = {'cve-exclude-list': pkg.cve_exclude_list}
        cve_info_yaml = yaml.dump(cve_info, indent=4)
        cve_info_desc = (
            '# The cve-exclude-list list contains CVEs, which were already evaluated and the package is not vulnerable.'
        )
        comment += f'{cve_info_desc}\n{cve_info_yaml}'

    if pkg.cve_keywords:
        cve_keywords = {'cve-keywords': pkg.cve_keywords}
        cve_keywords_yaml = yaml.dump(cve_keywords, indent=4)
        cve_keywords_desc = '# The cve-keywords list includes strings used to search through CVE descriptions.'
        comment += f'{cve_keywords_desc}\n{cve_keywords_yaml}'

    return comment


def _file_spdxid(pkg: Package, file: File) -> str:
    """The SPDXID of a file. Per-file SPDXIDs are prefixed to avoid collisions:
    the project binary with the project name alone, every other package with its
    name doubled. file.path is './' + relpath; the SPDXID is built from the bare
    relpath.
    """
    relpath = file.path[2:] if file.path.startswith('./') else file.path
    prefix = pkg.name if pkg.kind is PackageKind.PROJECT else f'{pkg.name}-{pkg.name}'
    return 'SPDXRef-FILE-' + _sanitize_spdxid(f'{prefix}-{relpath}')


def _render_file(pkg: Package, file: File) -> str:
    """Render a single File as SPDX File Information tag/values."""
    out = ''
    out += f'FileName: {file.path}\n'
    out += f'SPDXID: {_file_spdxid(pkg, file)}\n'
    out += f'FileChecksum: SHA1: {file.sha1}\n'
    out += f'FileChecksum: SHA256: {file.sha256}\n'

    if file.licenses_in_file:
        for lic in sorted(file.licenses_in_file):
            out += f'LicenseInfoInFile: {lic}\n'
    else:
        out += 'LicenseInfoInFile: NOASSERTION\n'

    out += f'LicenseConcluded: {file.license_concluded or "NOASSERTION"}\n'

    if file.copyrights:
        out += 'FileCopyrightText: <text>{}</text>\n'.format('\n'.join(sorted(file.copyrights)))
    else:
        out += 'FileCopyrightText: NOASSERTION\n'

    for contributor in sorted(file.contributors):
        out += f'FileContributor: {contributor}\n'

    return out


def _render_package(pkg: Package) -> str:
    """Render a single Package as SPDX Package Information tag/values, followed
    by its files, in the SPDX 2.2 package tag order."""
    out = ''
    out += f'PackageName: {pkg.package_name}\n'
    if pkg.description:
        out += f'PackageSummary: <text>{pkg.description}</text>\n'
    out += f'SPDXID: SPDXRef-{pkg.ref}\n'
    if pkg.version:
        out += f'PackageVersion: {pkg.version}\n'
    out += f'PackageSupplier: {pkg.supplier or "NOASSERTION"}\n'
    if pkg.originator:
        out += f'PackageOriginator: {pkg.originator}\n'
    out += f'PackageDownloadLocation: {pkg.download_url or "NOASSERTION"}\n'

    if pkg.files:
        out += 'FilesAnalyzed: true\n'
        out += f'PackageVerificationCode: {_verification_code([f.sha1 for f in pkg.files])}\n'
        if pkg.licenses_from_files:
            for lic in sorted(pkg.licenses_from_files):
                out += f'PackageLicenseInfoFromFiles: {lic}\n'
        else:
            out += 'PackageLicenseInfoFromFiles: NOASSERTION\n'
    else:
        out += 'FilesAnalyzed: false\n'

    out += f'PackageLicenseConcluded: {simplify_licenses(pkg.licenses_concluded) or "NOASSERTION"}\n'
    out += f'PackageLicenseDeclared: {simplify_licenses(pkg.licenses_declared) or "NOASSERTION"}\n'

    if pkg.copyrights:
        out += 'PackageCopyrightText: <text>{}</text>\n'.format('\n'.join(sorted(pkg.copyrights)))
    else:
        out += 'PackageCopyrightText: NOASSERTION\n'

    if pkg.repository:
        out += f'ExternalRef: OTHER repository {pkg.repository}\n'
    for cpe in pkg.cpes:
        out += f'ExternalRef: SECURITY cpe23Type {cpe}\n'
    if pkg.purl:
        out += f'ExternalRef: PACKAGE-MANAGER purl {pkg.purl}\n'

    comment = _package_comment(pkg)
    if comment:
        out += f'PackageComment: <text>\n{comment}</text>\n'

    for dep in pkg.depends_on:
        out += f'Relationship: SPDXRef-{pkg.ref} DEPENDS_ON SPDXRef-{dep}\n'

    if pkg.checksum_sha256:
        out += f'PackageChecksum: SHA256: {pkg.checksum_sha256}\n'

    if pkg.files:
        out += '\n'
        out += f'# {pkg.name} {pkg.kind.value} files'
        for file in pkg.files:
            out += '\n'
            out += _render_file(pkg, file)

    return out


def _package_header(pkg: Package) -> str:
    """The '# ...' comment line that precedes each package. Non-contractual
    (parsers ignore comments) but reproduced for byte compatibility."""
    if pkg.kind is PackageKind.PROJECT:
        return f'# project {pkg.name}\n'
    return f'# {pkg.name} {pkg.kind.value}\n'


def _render_tagvalue(sbom: SBOM, version: str) -> str:
    """Render the SBOM as an SPDX 2.2 tag/value document."""
    argv = ' '.join('"' + arg + '"' if ' ' in arg else arg for arg in sys.argv)
    namespace = 'http://spdx.org/spdxdocs/' + _sanitize_spdxid(sbom.name) + '-' + str(uuid.uuid4())
    created = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    out = ''
    out += f'# Generated by esp-idf-sbom {__version__} with {argv}\n\n'
    out += f'# SPDX document for project {sbom.name}\n'

    out += f'SPDXVersion: SPDX-{version}\n'
    out += 'DataLicense: CC0-1.0\n'
    out += 'SPDXID: SPDXRef-DOCUMENT\n'
    out += f'DocumentName: {sbom.name}\n'
    out += f'DocumentNamespace: {namespace}\n'
    out += f'Creator: Tool: {sbom.creator}\n'
    out += f'Created: {created}\n'
    out += 'CreatorComment: <text>ESP-IDF SBOM document in SPDX format</text>\n'
    out += f'Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-{sbom.root}\n'

    for pkg in sbom.packages:
        out += '\n'
        out += _package_header(pkg)
        out += _render_package(pkg)

    return out


def _file_json(pkg: Package, file: File) -> Dict[str, Any]:
    """Render a single File as an SPDX 2.2 JSON file object."""
    file_obj: Dict[str, Any] = {
        'SPDXID': _file_spdxid(pkg, file),
        'fileName': file.path,
        'checksums': [
            {'algorithm': 'SHA1', 'checksumValue': file.sha1},
            {'algorithm': 'SHA256', 'checksumValue': file.sha256},
        ],
        'licenseConcluded': file.license_concluded or 'NOASSERTION',
        'licenseInfoInFiles': sorted(file.licenses_in_file) or ['NOASSERTION'],
        'copyrightText': '\n'.join(sorted(file.copyrights)) or 'NOASSERTION',
    }
    if file.contributors:
        file_obj['fileContributors'] = sorted(file.contributors)
    return file_obj


def _package_json(pkg: Package) -> Dict[str, Any]:
    """Render a single Package as an SPDX 2.2 JSON package object."""
    pkg_obj: Dict[str, Any] = {
        'SPDXID': f'SPDXRef-{pkg.ref}',
        'name': pkg.package_name,
        'downloadLocation': pkg.download_url or 'NOASSERTION',
        'filesAnalyzed': bool(pkg.files),
        'supplier': pkg.supplier or 'NOASSERTION',
        'licenseConcluded': simplify_licenses(pkg.licenses_concluded) or 'NOASSERTION',
        'licenseDeclared': simplify_licenses(pkg.licenses_declared) or 'NOASSERTION',
        'copyrightText': '\n'.join(sorted(pkg.copyrights)) or 'NOASSERTION',
    }
    if pkg.description:
        pkg_obj['summary'] = pkg.description
    if pkg.version:
        pkg_obj['versionInfo'] = pkg.version
    if pkg.originator:
        pkg_obj['originator'] = pkg.originator

    if pkg.files:
        pkg_obj['packageVerificationCode'] = {
            'packageVerificationCodeValue': _verification_code([f.sha1 for f in pkg.files])
        }
        pkg_obj['licenseInfoFromFiles'] = sorted(pkg.licenses_from_files) or ['NOASSERTION']
        pkg_obj['hasFiles'] = [_file_spdxid(pkg, f) for f in pkg.files]

    external_refs: List[Dict[str, str]] = []
    if pkg.repository:
        external_refs.append(
            {'referenceCategory': 'OTHER', 'referenceType': 'repository', 'referenceLocator': pkg.repository}
        )
    for cpe in pkg.cpes:
        external_refs.append({'referenceCategory': 'SECURITY', 'referenceType': 'cpe23Type', 'referenceLocator': cpe})
    if pkg.purl:
        external_refs.append(
            {'referenceCategory': 'PACKAGE-MANAGER', 'referenceType': 'purl', 'referenceLocator': pkg.purl}
        )
    if external_refs:
        pkg_obj['externalRefs'] = external_refs

    comment = _package_comment(pkg)
    if comment:
        pkg_obj['comment'] = comment

    if pkg.checksum_sha256:
        pkg_obj['checksums'] = [{'algorithm': 'SHA256', 'checksumValue': pkg.checksum_sha256}]

    return pkg_obj


def _render_json(sbom: SBOM, version: str) -> str:
    """Render the SBOM as an SPDX 2.2 JSON document.

    The same data as the tag/value form, in the schema's canonical JSON shape:
    relationships and files are top-level arrays (not nested under packages).
    """
    namespace = 'http://spdx.org/spdxdocs/' + _sanitize_spdxid(sbom.name) + '-' + str(uuid.uuid4())
    created = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    relationships: List[Dict[str, str]] = [
        {
            'spdxElementId': 'SPDXRef-DOCUMENT',
            'relationshipType': 'DESCRIBES',
            'relatedSpdxElement': f'SPDXRef-{sbom.root}',
        }
    ]
    files: List[Dict[str, Any]] = []
    for pkg in sbom.packages:
        for dep in pkg.depends_on:
            relationships.append(
                {
                    'spdxElementId': f'SPDXRef-{pkg.ref}',
                    'relationshipType': 'DEPENDS_ON',
                    'relatedSpdxElement': f'SPDXRef-{dep}',
                }
            )
        for file in pkg.files:
            files.append(_file_json(pkg, file))

    document: Dict[str, Any] = {
        'spdxVersion': f'SPDX-{version}',
        'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT',
        'name': sbom.name,
        'documentNamespace': namespace,
        'creationInfo': {
            'creators': [f'Tool: {sbom.creator}'],
            'created': created,
            'comment': 'ESP-IDF SBOM document in SPDX format',
        },
        'packages': [_package_json(pkg) for pkg in sbom.packages],
        'relationships': relationships,
    }
    if files:
        document['files'] = files

    return json.dumps(document, indent=2)


def _render_jsonld(sbom: SBOM, version: str) -> str:
    """Render the model as SPDX 3.0 JSON-LD.

    Unlike SPDX 2.x, SPDX 3.0 has no tag/value form -- JSON-LD is the only
    serialization. The output validates against the official schema at
    https://spdx.org/schema/<version>/spdx-json-schema.json. The model maps to
    SPDX 3.0 elements: a software_Package per package (every CPE as a cpe23
    externalIdentifier, the PURL as software_packageUrl), suppliers/originators
    as Agent elements, the depends_on graph as dependsOn Relationships, and each
    excluded CVE as a security_Vulnerability plus a not-affected VEX relationship.
    """
    context = f'https://spdx.org/rdf/{version}/spdx-context.jsonld'
    docns = f'https://spdx.org/spdxdocs/{_sanitize_spdxid(sbom.name or "document")}-{uuid.uuid4()}'

    def sid(suffix: str) -> str:
        return f'{docns}#{suffix}'

    created = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    ci = '_:creationInfo'
    graph: List[Dict[str, Any]] = []
    element_ids: List[str] = []

    tool = sid('Agent-esp-idf-sbom')
    graph.append({'type': 'SoftwareAgent', 'spdxId': tool, 'creationInfo': ci, 'name': 'esp-idf-sbom'})
    element_ids.append(tool)
    graph.append({'type': 'CreationInfo', '@id': ci, 'specVersion': version, 'created': created, 'createdBy': [tool]})

    agents: Dict[str, str] = {}

    def agent_id(supplier: str) -> Any:
        if not supplier:
            return None
        atype, name = 'Organization', supplier
        for prefix, kind in (('Person:', 'Person'), ('Organization:', 'Organization')):
            if supplier.startswith(prefix):
                atype, name = kind, supplier[len(prefix) :].strip()
                break
        if name not in agents:
            aid = sid('Agent-' + (_sanitize_spdxid(name) or 'x'))
            agents[name] = aid
            graph.append({'type': atype, 'spdxId': aid, 'creationInfo': ci, 'name': name})
            element_ids.append(aid)
        return agents[name]

    licenses: Dict[str, str] = {}

    def license_id(expr: str) -> str:
        if expr not in licenses:
            lid = sid(f'License-{len(licenses)}')
            licenses[expr] = lid
            graph.append(
                {
                    'type': 'simplelicensing_LicenseExpression',
                    'spdxId': lid,
                    'creationInfo': ci,
                    'simplelicensing_licenseExpression': expr,
                }
            )
            element_ids.append(lid)
        return licenses[expr]

    for pkg in sbom.packages:
        pid = sid(pkg.ref)
        comp: Dict[str, Any] = {'type': 'software_Package', 'spdxId': pid, 'creationInfo': ci, 'name': pkg.package_name}
        if pkg.version:
            comp['software_packageVersion'] = pkg.version
        if pkg.description:
            comp['description'] = pkg.description
        if pkg.download_url:
            comp['software_downloadLocation'] = pkg.download_url
        if pkg.purl:
            comp['software_packageUrl'] = pkg.purl
        if pkg.copyrights:
            comp['software_copyrightText'] = '\n'.join(sorted(pkg.copyrights))
        if pkg.cpes:
            comp['externalIdentifier'] = [
                {'type': 'ExternalIdentifier', 'externalIdentifierType': 'cpe23', 'identifier': cpe} for cpe in pkg.cpes
            ]
        supplier = agent_id(pkg.supplier)
        if supplier:
            comp['suppliedBy'] = supplier
        originator = agent_id(pkg.originator)
        if originator:
            comp['originatedBy'] = [originator]
        if pkg.checksum_sha256:
            comp['verifiedUsing'] = [{'type': 'Hash', 'algorithm': 'sha256', 'hashValue': pkg.checksum_sha256}]
        if pkg.repository:
            comp['externalRef'] = [{'type': 'ExternalRef', 'externalRefType': 'vcs', 'locator': [pkg.repository]}]
        if pkg.cve_keywords:
            # SPDX 3.0 has no native slot for the cve-keywords search hints (the
            # cve-exclude-list goes to VEX), so carry them as a YAML comment that
            # _parse_jsonld reads back, mirroring the SPDX 2.x PackageComment.
            comp['comment'] = yaml.dump({'cve-keywords': pkg.cve_keywords})
        graph.append(comp)
        element_ids.append(pid)

    rel_n = 0
    for pkg in sbom.packages:
        if pkg.depends_on:
            rid = sid(f'Relationship-{rel_n}')
            rel_n += 1
            graph.append(
                {
                    'type': 'Relationship',
                    'spdxId': rid,
                    'creationInfo': ci,
                    'from': sid(pkg.ref),
                    'relationshipType': 'dependsOn',
                    'to': [sid(dep) for dep in pkg.depends_on],
                }
            )
            element_ids.append(rid)

    has_licensing = False
    lic_rel_n = 0
    for pkg in sbom.packages:
        license_rels = (
            ('hasConcludedLicense', pkg.licenses_concluded),
            ('hasDeclaredLicense', pkg.licenses_declared),
        )
        for reltype, exprs in license_rels:
            expr = simplify_licenses(exprs)
            if not expr:
                continue
            has_licensing = True
            lrid = sid(f'LicenseRel-{lic_rel_n}')
            lic_rel_n += 1
            graph.append(
                {
                    'type': 'Relationship',
                    'spdxId': lrid,
                    'creationInfo': ci,
                    'from': sid(pkg.ref),
                    'relationshipType': reltype,
                    'to': [license_id(expr)],
                }
            )
            element_ids.append(lrid)

    for pkg in sbom.packages:
        if not pkg.files:
            continue
        file_ids = []
        for i, f in enumerate(pkg.files):
            fid = sid(f'{pkg.ref}-File-{i}')
            felem: Dict[str, Any] = {
                'type': 'software_File',
                'spdxId': fid,
                'creationInfo': ci,
                'name': f.path,
                'verifiedUsing': [
                    {'type': 'Hash', 'algorithm': 'sha1', 'hashValue': f.sha1},
                    {'type': 'Hash', 'algorithm': 'sha256', 'hashValue': f.sha256},
                ],
            }
            if f.copyrights:
                felem['software_copyrightText'] = '\n'.join(sorted(f.copyrights))
            graph.append(felem)
            element_ids.append(fid)
            file_ids.append(fid)
            if f.license_concluded:
                has_licensing = True
                frid = sid(f'{pkg.ref}-File-{i}-License')
                graph.append(
                    {
                        'type': 'Relationship',
                        'spdxId': frid,
                        'creationInfo': ci,
                        'from': fid,
                        'relationshipType': 'hasConcludedLicense',
                        'to': [license_id(f.license_concluded)],
                    }
                )
                element_ids.append(frid)
        crid = sid(f'{pkg.ref}-Contains')
        graph.append(
            {
                'type': 'Relationship',
                'spdxId': crid,
                'creationInfo': ci,
                'from': sid(pkg.ref),
                'relationshipType': 'contains',
                'to': file_ids,
            }
        )
        element_ids.append(crid)

    has_security = False
    for pkg in sbom.packages:
        for entry in pkg.cve_exclude_list:
            has_security = True
            vid = sid(f'Vuln-{pkg.ref}-{entry["cve"]}')
            graph.append(
                {
                    'type': 'security_Vulnerability',
                    'spdxId': vid,
                    'creationInfo': ci,
                    'externalIdentifier': [
                        {'type': 'ExternalIdentifier', 'externalIdentifierType': 'cve', 'identifier': entry['cve']}
                    ],
                }
            )
            element_ids.append(vid)
            xid = sid(f'Vex-{pkg.ref}-{entry["cve"]}')
            graph.append(
                {
                    'type': 'security_VexNotAffectedVulnAssessmentRelationship',
                    'spdxId': xid,
                    'creationInfo': ci,
                    'from': vid,
                    'relationshipType': 'doesNotAffect',
                    'to': [sid(pkg.ref)],
                    'security_impactStatement': entry['reason'],
                }
            )
            element_ids.append(xid)

    profiles = ['core', 'software']
    if has_licensing:
        profiles.append('simpleLicensing')
    if has_security:
        profiles.append('security')
    graph.append(
        {
            'type': 'SpdxDocument',
            'spdxId': sid('SPDXRef-DOCUMENT'),
            'creationInfo': ci,
            'name': sbom.name,
            'profileConformance': profiles,
            'dataLicense': 'https://spdx.org/licenses/CC0-1.0',
            'rootElement': [sid(sbom.root)],
            'element': element_ids,
        }
    )
    return json.dumps({'@context': context, '@graph': graph}, indent=2)


def render(sbom: SBOM, format: str = 'tagvalue', version: str = '2.2') -> str:
    """Render a format-neutral SBOM as an SPDX document.

    :param sbom: the SBOM model to serialize
    :param format: 'tagvalue' or 'json' for SPDX 2.x, 'json-ld' for SPDX 3.0 JSON-LD
    :param version: the SPDX spec version to emit
    :returns: the serialized SPDX document
    """
    if format == 'tagvalue':
        return _render_tagvalue(sbom, version)
    if format == 'json':
        return _render_json(sbom, version)
    if format == 'json-ld':
        return _render_jsonld(sbom, version)
    raise ValueError(f'unsupported SPDX format: {format!r}')


# ===========================================================================
# Parse: SPDX serialization -> format-neutral SBOM model
#
# Inverse of render. Reconstructs the package fields the model carries that
# consumers of a loaded SBOM need -- identity (ref/name/kind), version, CPEs,
# PURL, repository, the structured cve-exclude-list / cve-keywords and the
# depends_on edges. Licenses, copyrights and files are not recovered (no current
# consumer of a parsed SBOM needs them; render stored licenses pre-simplified, so
# the raw expression sets cannot be reconstructed anyway).
# ===========================================================================


def _unref(spdxid: str) -> str:
    """Strip the SPDXRef- prefix from an SPDXID, leaving the model ref."""
    prefix = 'SPDXRef-'
    return spdxid[len(prefix) :] if spdxid.startswith(prefix) else spdxid


def _package_from_tags(spdxid: str, tags: Dict[str, List[str]]) -> Package:
    ref = _unref(spdxid)
    # The SPDXID is SPDXRef-<MARK>-<sanitized name>; recover kind and name from it.
    kind, name = kind_and_name(ref)

    cpes: List[str] = []
    purl = ''
    repository = ''
    for ext in tags.get('ExternalRef', []):
        if ext.startswith('SECURITY cpe23Type '):
            cpes.append(ext.split(' ', 2)[2])
        elif ext.startswith('PACKAGE-MANAGER purl '):
            purl = ext.split(' ', 2)[2]
        elif ext.startswith('OTHER repository '):
            repository = ext.split(' ', 2)[2]

    depends_on: List[str] = []
    for rel in tags.get('Relationship', []):
        _, sep, dst = rel.partition(' DEPENDS_ON ')
        if sep:
            depends_on.append(_unref(dst.strip()))

    comment = parse_package_comment(tags)

    def value(tag: str) -> str:
        return tags[tag][0] if tag in tags else ''

    supplier = value('PackageSupplier')
    download_url = value('PackageDownloadLocation')
    summary = value('PackageSummary')
    checksum = value('PackageChecksum')

    return Package(
        ref=ref,
        name=name,
        package_name=tags['PackageName'][0],
        kind=kind,
        version=value('PackageVersion'),
        description=summary[len('<text>') : -len('</text>')] if summary.startswith('<text>') else summary,
        supplier='' if supplier == 'NOASSERTION' else supplier,
        originator=value('PackageOriginator'),
        download_url='' if download_url == 'NOASSERTION' else download_url,
        repository=repository,
        purl=purl,
        cpes=cpes,
        checksum_sha256=checksum[len('SHA256: ') :] if checksum.startswith('SHA256: ') else checksum,
        cve_exclude_list=comment.get('cve-exclude-list') or [],
        cve_keywords=comment.get('cve-keywords') or [],
        depends_on=depends_on,
    )


def _parse_tagvalue(text: str) -> SBOM:
    raw = parse_packages(text)
    packages = [_package_from_tags(spdxid, tags) for spdxid, tags in raw.items()]

    # Recover the document name, the DESCRIBES root ref and the producing tool
    # from the header.
    name = ''
    root = ''
    creator = ''
    for line in text.splitlines():
        line = line.strip()
        if not name and line.startswith('DocumentName:'):
            name = line.split(':', 1)[1].strip()
        elif not root and line.startswith('Relationship:') and ' DESCRIBES ' in line:
            root = _unref(line.split(' DESCRIBES ', 1)[1].strip())
        elif not creator and line.startswith('Creator: Tool:'):
            creator = line[len('Creator: Tool:') :].strip()
        if name and root and creator:
            break
    # The project package is emitted first and is the DESCRIBES target; fall back
    # to it if the header did not carry the information.
    if not root and packages:
        root = packages[0].ref
    if not name and packages:
        name = packages[0].package_name

    return SBOM(name=name, root=root, packages=packages, creator=creator)


def _comment_to_dict(comment: str) -> Dict[str, Any]:
    """Parse a package comment into the cve-exclude-list / cve-keywords dict.
    esp-idf-sbom stores that data as bare YAML in the comment; a comment from
    another tool is ordinary prose, so anything that is not a YAML mapping is
    treated as no data rather than allowed to raise. Tolerates a <text>...</text>
    wrapper just in case."""
    if not comment:
        return {}
    if comment.startswith('<text>') and comment.endswith('</text>'):
        comment = comment[len('<text>') : -len('</text>')]
    try:
        data = yaml.safe_load(comment)
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _package_from_json(obj: Dict[str, Any], depends_on: List[str]) -> Package:
    ref = _unref(obj.get('SPDXID', ''))
    kind, name = kind_and_name(ref)

    cpes: List[str] = []
    purl = ''
    repository = ''
    for ext in obj.get('externalRefs', []):
        category = ext.get('referenceCategory')
        ref_type = ext.get('referenceType')
        locator = ext.get('referenceLocator', '')
        if category == 'SECURITY' and ref_type == 'cpe23Type':
            cpes.append(locator)
        elif ref_type == 'purl':
            purl = locator
        elif ref_type == 'repository':
            repository = locator

    checksum = ''
    for entry in obj.get('checksums', []):
        if entry.get('algorithm') == 'SHA256':
            checksum = entry.get('checksumValue', '')

    comment = _comment_to_dict(obj.get('comment', ''))
    supplier = obj.get('supplier', '')
    download_url = obj.get('downloadLocation', '')

    return Package(
        ref=ref,
        name=name,
        package_name=obj.get('name', ''),
        kind=kind,
        version=obj.get('versionInfo', ''),
        description=obj.get('summary', ''),
        supplier='' if supplier == 'NOASSERTION' else supplier,
        originator=obj.get('originator', ''),
        download_url='' if download_url == 'NOASSERTION' else download_url,
        repository=repository,
        purl=purl,
        cpes=cpes,
        checksum_sha256=checksum,
        cve_exclude_list=comment.get('cve-exclude-list') or [],
        cve_keywords=comment.get('cve-keywords') or [],
        depends_on=depends_on,
    )


def _parse_json(text: str) -> SBOM:
    document = json.loads(text)

    root = ''
    depends_on: Dict[str, List[str]] = {}
    for rel in document.get('relationships', []):
        rel_type = rel.get('relationshipType')
        src = rel.get('spdxElementId', '')
        dst = rel.get('relatedSpdxElement', '')
        if rel_type == 'DESCRIBES' and src == 'SPDXRef-DOCUMENT':
            root = _unref(dst)
        elif rel_type == 'DEPENDS_ON':
            depends_on.setdefault(src, []).append(_unref(dst))

    packages = [
        _package_from_json(obj, depends_on.get(obj.get('SPDXID', ''), [])) for obj in document.get('packages', [])
    ]

    # The producing tool, used only for the provenance note in cmd_check.
    creator = ''
    for c in document.get('creationInfo', {}).get('creators', []):
        if isinstance(c, str) and c.startswith('Tool:'):
            creator = c[len('Tool:') :].strip()
            break

    name = document.get('name', '')
    if not root and packages:
        root = packages[0].ref
    if not name and packages:
        name = packages[0].package_name

    return SBOM(name=name, root=root, packages=packages, creator=creator)


def _parse_jsonld(text: str) -> SBOM:
    """Recover the scan-relevant parts of an SPDX 3.0 JSON-LD document: the
    packages with their CPEs, the dependsOn graph and the not-affected VEX
    statements (the inverse of _render_jsonld; like the other parsers it does not
    recover everything, only what check needs)."""
    graph = json.loads(text).get('@graph', [])

    def _id(x: Any) -> str:
        # A JSON-LD reference is the target element's spdxId (its @id). Conformant
        # SPDX 3.0 writes it as a bare IRI string; tolerate the expanded
        # {'@id': ...} object form too. The full id is what we key on -- no
        # fragment stripping, so ids from a foreign namespace stay unique and
        # cannot collide, and a 'to' that points at us matches our spdxId exactly.
        if isinstance(x, str):
            return x
        if isinstance(x, dict):
            return str(x.get('@id', '') or x.get('spdxId', ''))
        return ''

    def _as_list(x: Any) -> List[Any]:
        # Relationship 'to'/'rootElement' are lists of references; tolerate a tool
        # that serialized a single target as a bare value instead of a 1-item list.
        if isinstance(x, list):
            return x
        return [] if x is None else [x]

    def ids_of(element: Dict[str, Any], idtype: str) -> List[str]:
        return [
            x.get('identifier', '')
            for x in element.get('externalIdentifier', [])
            if x.get('externalIdentifierType') == idtype
        ]

    # vulnerability spdxId -> CVE id
    vuln_cve: Dict[str, str] = {}
    for e in graph:
        if e.get('type') == 'security_Vulnerability':
            vuln_cve[_id(e.get('spdxId'))] = next(iter(ids_of(e, 'cve')), '')

    depends: Dict[str, List[str]] = {}
    excludes: Dict[str, List[Dict[str, str]]] = {}
    doc_name = ''
    creator = ''
    root = ''
    for e in graph:
        t = e.get('type')
        if t == 'Relationship' and e.get('relationshipType') == 'dependsOn':
            depends.setdefault(_id(e.get('from')), []).extend(_id(d) for d in _as_list(e.get('to')))
        elif t == 'security_VexNotAffectedVulnAssessmentRelationship':
            entry = {'cve': vuln_cve.get(_id(e.get('from')), ''), 'reason': e.get('security_impactStatement', '')}
            for to in _as_list(e.get('to')):
                excludes.setdefault(_id(to), []).append(entry)
        elif t == 'SpdxDocument':
            doc_name = e.get('name', '')
            roots = _as_list(e.get('rootElement'))
            if roots:
                root = _id(roots[0])
        elif t in ('SoftwareAgent', 'Tool') and not creator:
            # The producing tool; used only to tell whether this SBOM came from
            # esp-idf-sbom (see the provenance note in cmd_check).
            creator = e.get('name', '')

    packages: List[Package] = []
    for e in graph:
        if e.get('type') != 'software_Package':
            continue
        ref = _id(e.get('spdxId'))
        # kind/name are cosmetic on the load path (check keys on
        # package_name/cpes/version); derive them best-effort from the id
        # fragment of our own KIND-name scheme, defaulting to COMPONENT.
        kind, name = kind_and_name(ref.rsplit('#', 1)[-1])
        cpes = ids_of(e, 'cpe23')
        cve_keywords: List[str] = []
        comment = e.get('comment', '')
        if comment:
            try:
                data = yaml.safe_load(comment)
            except yaml.YAMLError:
                data = None
            if isinstance(data, dict):
                cve_keywords = data.get('cve-keywords', []) or []
        packages.append(
            Package(
                ref=ref,
                name=name,
                package_name=e.get('name', ''),
                kind=kind,
                version=e.get('software_packageVersion', ''),
                purl=e.get('software_packageUrl', ''),
                cpes=cpes,
                cve_exclude_list=excludes.get(ref, []),
                cve_keywords=cve_keywords,
                depends_on=depends.get(ref, []),
            )
        )

    if not root and packages:
        root = packages[0].ref
    if not doc_name and packages:
        doc_name = packages[0].package_name
    return SBOM(name=doc_name, root=root, packages=packages, creator=creator)


def parse(text: str, format: str = 'tagvalue') -> SBOM:
    """Parse an SPDX document into the format-neutral SBOM model.

    :param text: the SPDX document
    :param format: 'tagvalue'/'json' for SPDX 2.x, 'json-ld' for SPDX 3.0 JSON-LD
    """
    if format == 'tagvalue':
        return _parse_tagvalue(text)
    if format == 'json':
        return _parse_json(text)
    if format == 'json-ld':
        return _parse_jsonld(text)
    raise ValueError(f'unsupported SPDX format: {format!r}')


def parse_packages(buf: str) -> Dict[str, Dict[str, List[str]]]:
    """Very dummy SPDX file parser. Returns dictionary, where key is
    package SPDXID and value is dictionary with SPDX tag/values."""
    in_package = False
    in_text = False
    idx = -1
    packages: Dict[int, Dict[str, List[str]]] = {}
    tag = ''
    val = ''

    def add_tag_value(tag: str, val: str):
        if not in_package:
            return

        if tag not in packages[idx]:
            packages[idx][tag] = []

        packages[idx][tag].append(val)

    lines = buf.splitlines(keepends=True)
    for line in lines:
        if in_text:
            val += line
            if '</text>' not in line:
                # still in text value
                continue
            val = val.rstrip()
            in_text = False
            add_tag_value(tag, val)

        if not line.strip() or line[0] == '#':
            # skip empty lines or comments
            continue

        if ':' not in line:
            # line not in tag:value format
            continue

        tag, val = line.split(':', maxsplit=1)

        tag = tag.strip()
        if tag == 'FileName':
            # files are listed after package, so this is
            # end of current package if any
            in_package = False
            continue

        val = val.lstrip()
        if val.startswith('<text>') and '</text>' not in val:
            # text value may have multiple lines
            in_text = True
            continue

        val = val.rstrip()

        if tag == 'PackageName':
            in_package = True
            idx += 1
            packages[idx] = {}

        add_tag_value(tag, val)

    spdx_packages = {pkg['SPDXID'][0]: pkg for pkg in packages.values()}
    log.debug('parsed spdx packages:')
    log.debug(json.dumps(spdx_packages, indent=4))
    return spdx_packages


def parse_package_comment(pkg: Dict[str, List[str]]) -> Dict[str, Any]:
    if 'PackageComment' not in pkg:
        return {}
    # _comment_to_dict strips the <text> wrapper and tolerates non-YAML prose.
    return _comment_to_dict(pkg['PackageComment'][0])
