# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Format-neutral VEX data model for esp-idf-sbom.

This is the VEX counterpart of sbom.py. build() creates this model from an SBOM
model. Backends render it to a VEX format, or parse a VEX format back into it.
The VEX embedded in an SBOM and a standalone VEX file are both rendered from
here, so the two cannot differ.

The status, justification and response values are in vexvalues.py.

A statement has a status, it is not just an excluded CVE. esp-idf-sbom writes
only not_affected today, but with an explicit status, check can later report
affected or under_investigation without any backend change.
"""

import datetime
import re
from dataclasses import dataclass
from dataclasses import field
from dataclasses import fields
from typing import List
from typing import Optional
from typing import Tuple

from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom import utils
from esp_idf_sbom.libsbom.sbom import SBOM
from esp_idf_sbom.libsbom.sbom import Organization
from esp_idf_sbom.libsbom.sbom import Package
from esp_idf_sbom.libsbom.sbom import VexAssessment
from esp_idf_sbom.libsbom.vexvalues import VexJustification as VexJustification  # re-export for the backends
from esp_idf_sbom.libsbom.vexvalues import VexResponse as VexResponse  # re-export for the backends
from esp_idf_sbom.libsbom.vexvalues import VexStatus as VexStatus  # re-export for the backends


@dataclass
class VexProduct:
    """What a statement is about.

    A product has two identities and each format uses only one of them.
    CycloneDX and SPDX 3.0 point to a component in one SBOM document, so they
    use ref. OpenVEX names the product by purl and CPE, so it works with an SBOM
    in any format, including SPDX 2.2, which has no VEX format of its own.
    """

    ref: str = ''  # Package.ref, the id used inside the SBOM
    purl: str = ''
    cpes: List[str] = field(default_factory=list)
    name: str = ''
    version: str = ''


@dataclass
class VexStatement(VexAssessment):
    """One assessment: this vulnerability has this status for these products."""

    products: List[VexProduct] = field(default_factory=list)
    # The NVD page of the CVE. CISA requires the description of the vulnerability or
    # a link to it.
    nvd_url: str = ''


@dataclass
class Vex:
    """A VEX document: statements plus the id of the SBOM they describe.

    The document id, version and times are read from the file, so that an update
    can keep the id and increase the version. build() leaves them empty, and the
    backend then writes a new document: a new id, version 1 and the current time.
    """

    statements: List[VexStatement] = field(default_factory=list)
    # The id of this VEX document: the CycloneDX serialNumber or the OpenVEX @id.
    doc_id: str = ''
    doc_version: int = 1
    # When the document was first issued and last updated, as the file writes the
    # time. CycloneDX has only metadata.timestamp, which is the last update.
    first_issued: str = ''
    last_updated: str = ''
    sbom_id: str = ''  # the SBOM's serialNumber / document namespace
    # The SBOM document version. A CycloneDX BOM-Link points to one version of a
    # document, so the link needs it too.
    sbom_version: int = 1
    sbom_name: str = ''
    # Who made these statements, as the parsed file records it. Empty if the file
    # does not say, or if the model was built and not parsed. Same as SBOM.creator:
    # render ignores it and writes the manufacturer.
    author: str = ''
    # The author of the statements: the manufacturer from the document key of the
    # project manifest, as SBOM.manufacturer. Empty if the manifest does not say.
    manufacturer: Organization = field(default_factory=Organization)


_FRACTION_RE = re.compile(r'\.(\d+)')


def parse_time(value: str) -> Optional[datetime.datetime]:
    """Read an ISO 8601 time, as VEX and SBOM files write it. Return None when it
    cannot be read. A time without a time zone is in UTC.

    Python before 3.11 reads a fraction of a second only with 3 or 6 digits, but
    go-vex, for example, writes up to 9. So the fraction is cut or filled to 6
    digits first.
    """
    value = _FRACTION_RE.sub(lambda m: '.' + m.group(1)[:6].ljust(6, '0'), value.replace('Z', '+00:00'))
    try:
        time = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if time.tzinfo is None:
        time = time.replace(tzinfo=datetime.timezone.utc)
    return time


def _product(pkg: Package) -> VexProduct:
    return VexProduct(
        ref=pkg.ref,
        purl=pkg.purl,
        cpes=list(pkg.cpes),
        name=pkg.package_name,
        version=pkg.version,
    )


_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}')


def _nvd_url(vulnerability: str) -> str:
    """The NVD page of a CVE. Other ids have no NVD page."""
    return f'https://nvd.nist.gov/vuln/detail/{vulnerability}' if _CVE_RE.fullmatch(vulnerability) else ''


def _statement(assessment: VexAssessment, pkg: Package) -> VexStatement:
    """The statement for one assessment of a package. The package is the product."""
    values = {f.name: getattr(assessment, f.name) for f in fields(VexAssessment)}
    return VexStatement(**values, products=[_product(pkg)], nvd_url=_nvd_url(assessment.vulnerability))


def build(sbom: SBOM, sbom_id: str = '') -> Vex:
    """Create a VEX model from an SBOM model. This is the VEX side of sbom.build().

    Each assessment becomes one statement for its own package. Statements are not
    merged across packages, even for the same CVE with the same reason, because
    then it would not be clear which package each reason was written for.

    :param sbom: the SBOM model to read the assessments from
    :param sbom_id: id of the document the SBOM was read from. Backends that link
        a standalone VEX to the SBOM need it. Leave it empty for embedded VEX.
    """
    statements = [_statement(assessment, pkg) for pkg in sbom.packages for assessment in pkg.assessments]

    return Vex(statements=statements, sbom_id=sbom_id, sbom_name=sbom.name, manufacturer=sbom.manufacturer)


def _assessment(statement: VexStatement) -> VexAssessment:
    """The statement without its products."""
    return VexAssessment(**{f.name: getattr(statement, f.name) for f in fields(VexAssessment)})


def _cpe_key(cpe: str) -> Tuple[str, str]:
    """The part, vendor and product of a CPE, and its version, without case."""
    parts = cpe.lower().split(':')
    return ':'.join(parts[2:5]), parts[5] if len(parts) > 5 else '*'


def _cpe_matches(cpe: str, package_cpes: List[str]) -> bool:
    """Whether a CPE names a package with these CPEs.

    Part, vendor and product are compared without case, also for the aliases of
    the CPE. The version is compared only when the CPE has one. A CPE from an
    NA-version match in the check report has '-', so it has none. The other
    fields are not compared.
    """
    wanted = [_cpe_key(alias) for alias in utils.expand_cpe_aliases([cpe])]
    for name, version in (_cpe_key(package_cpe) for package_cpe in package_cpes):
        for wanted_name, wanted_version in wanted:
            if name == wanted_name and wanted_version in ('*', '-', version):
                return True
    return False


def find_packages(sbom: SBOM, product: VexProduct) -> List[Package]:
    """The packages of the SBOM that a VEX product names.

    The product is looked up by its ref, then by its PURL, then by its CPEs and
    last by its name. The first of these that finds a package is used. A ref
    names one package. A PURL, a CPE or a name can name more than one, for
    example two copies of the same library, and then all of them are returned.
    """
    lookups = (
        (product.ref, lambda pkg: pkg.ref == product.ref),
        (product.purl, lambda pkg: pkg.purl == product.purl),
        (product.cpes, lambda pkg: any(_cpe_matches(cpe, pkg.cpes) for cpe in product.cpes)),
        (product.name, lambda pkg: pkg.package_name == product.name),
    )
    for value, matches in lookups:
        if not value:
            continue
        found = [pkg for pkg in sbom.packages if matches(pkg)]
        if found:
            return found
    return []


def apply(sbom: SBOM, vexdoc: Vex) -> None:
    """Merge the statements of a VEX document into the SBOM model.

    The statements end up in Package.assessments, which is where every consumer
    of the model already reads them from, so nothing downstream has to know a
    VEX file was involved. Statements of all statuses are kept.

    The packages of a statement are found with find_packages(). Formats that
    point into an SBOM document give a ref, the others give PURL and CPE.
    """
    unmatched = 0
    for statement in vexdoc.statements:
        for product in statement.products:
            packages = find_packages(sbom, product)
            if not packages:
                unmatched += 1
            for pkg in packages:
                # The VEX file is the newer document, so it wins over an
                # assessment of the same CVE already in the SBOM.
                assessments = [a for a in pkg.assessments if a.vulnerability != statement.vulnerability]
                assessments.append(_assessment(statement))
                pkg.assessments = assessments

    if unmatched:
        # Not an error. A VEX file may cover a whole product line, so it can name
        # components that this SBOM does not contain.
        log.warn(f'{unmatched} VEX statement(s) name a component that is not in the SBOM; they were ignored.')
