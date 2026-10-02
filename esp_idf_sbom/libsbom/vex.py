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

import re
from dataclasses import dataclass
from dataclasses import field
from dataclasses import fields
from typing import List
from typing import Optional

from esp_idf_sbom.libsbom import log
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


def apply(sbom: SBOM, vexdoc: Vex) -> None:
    """Merge the statements of a VEX document into the SBOM model.

    The statements end up in Package.assessments, which is where every consumer
    of the model already reads them from, so nothing downstream has to know a
    VEX file was involved. Statements of all statuses are kept.

    Products are matched by ref first, then by PURL, then by CPE. Formats that
    point into an SBOM document give a ref, the others give PURL and CPE.
    """
    by_ref = {pkg.ref: pkg for pkg in sbom.packages}
    by_purl = {pkg.purl: pkg for pkg in sbom.packages if pkg.purl}
    by_cpe = {cpe: pkg for pkg in sbom.packages for cpe in pkg.cpes}

    def find(product: VexProduct) -> Optional[Package]:
        pkg = by_ref.get(product.ref) if product.ref else None
        if pkg is None and product.purl:
            pkg = by_purl.get(product.purl)
        for cpe in product.cpes:
            if pkg is not None:
                break
            pkg = by_cpe.get(cpe)
        return pkg

    unmatched = 0
    for statement in vexdoc.statements:
        for product in statement.products:
            pkg = find(product)
            if pkg is None:
                unmatched += 1
                continue
            # The VEX file is the newer document, so it wins over an assessment
            # of the same CVE already in the SBOM.
            assessments = [a for a in pkg.assessments if a.vulnerability != statement.vulnerability]
            assessments.append(_assessment(statement))
            pkg.assessments = assessments

    if unmatched:
        # Not an error. A VEX file may cover a whole product line, so it can name
        # components that this SBOM does not contain.
        log.warn(f'{unmatched} VEX statement(s) name a component that is not in the SBOM; they were ignored.')
