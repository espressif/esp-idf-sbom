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


def _render_file(pkg: Package, file: File) -> str:
    """Render a single File as SPDX File Information tag/values."""
    # file.path is './' + relpath; the SPDXID is built from the bare relpath.
    relpath = file.path[2:] if file.path.startswith('./') else file.path
    # The builder prefixes per-file SPDXIDs to avoid collisions: the project
    # binary with the project name alone, every other package with its name
    # doubled (SBOMPackage.get_files passes f'{name}-{name}').
    if pkg.kind is PackageKind.PROJECT:
        prefix = pkg.name
    else:
        prefix = f'{pkg.name}-{pkg.name}'

    out = ''
    out += f'FileName: {file.path}\n'
    out += f'SPDXID: SPDXRef-FILE-{_sanitize_spdxid(f"{prefix}-{relpath}")}\n'
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


def render(sbom: SBOM, format: str = 'tagvalue', version: str = '2.2') -> str:
    """Render a format-neutral SBOM as an SPDX document.

    :param sbom: the SBOM model to serialize
    :param format: 'tagvalue' for SPDX 2.x tag/value
    :param version: the SPDX spec version to emit
    :returns: the serialized SPDX document
    """
    if format == 'tagvalue':
        return _render_tagvalue(sbom, version)
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


def parse(text: str, format: str = 'tagvalue') -> SBOM:
    """Parse an SPDX document into the format-neutral SBOM model."""
    if format != 'tagvalue':
        raise NotImplementedError('only SPDX tag/value parsing is implemented')

    raw = parse_packages(text)
    packages = [_package_from_tags(spdxid, tags) for spdxid, tags in raw.items()]

    # Recover the document name and the DESCRIBES root ref from the header.
    name = ''
    root = ''
    for line in text.splitlines():
        line = line.strip()
        if not name and line.startswith('DocumentName:'):
            name = line.split(':', 1)[1].strip()
        elif not root and line.startswith('Relationship:') and ' DESCRIBES ' in line:
            root = _unref(line.split(' DESCRIBES ', 1)[1].strip())
        if name and root:
            break
    # The project package is emitted first and is the DESCRIBES target; fall back
    # to it if the header did not carry the information.
    if not root and packages:
        root = packages[0].ref
    if not name and packages:
        name = packages[0].package_name

    return SBOM(name=name, root=root, packages=packages)


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
    comment_dict: Dict[str, Any] = {}
    if 'PackageComment' not in pkg:
        return comment_dict

    comment = pkg['PackageComment'][0]
    comment = comment[len('<text>') : -len('</text>')]
    comment_dict = yaml.safe_load(comment)
    return comment_dict
