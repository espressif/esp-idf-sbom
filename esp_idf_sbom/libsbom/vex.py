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

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom.sbom import SBOM
from esp_idf_sbom.libsbom.sbom import Package
from esp_idf_sbom.libsbom.vexvalues import VexJustification
from esp_idf_sbom.libsbom.vexvalues import VexResponse
from esp_idf_sbom.libsbom.vexvalues import VexStatus


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
class VexStatement:
    """One assessment: this vulnerability has this status for these products."""

    vulnerability: str  # CVE id
    status: VexStatus
    products: List[VexProduct] = field(default_factory=list)
    justification: Optional[VexJustification] = None
    response: List[VexResponse] = field(default_factory=list)
    impact_statement: str = ''  # why not affected, the reason from the manifest
    action_statement: str = ''  # what to do, CISA requires it for the affected status


@dataclass
class Vex:
    """A VEX document: statements plus the id of the SBOM they describe.

    Like the SBOM model, this model has no id of its own. The backend creates the
    VEX document id when it renders. The SBOM id is different, it describes the
    input file, and every backend that links back to the SBOM needs it, so it is
    stored here.
    """

    statements: List[VexStatement] = field(default_factory=list)
    sbom_id: str = ''  # the SBOM's serialNumber / document namespace
    # The SBOM document version. A CycloneDX BOM-Link points to one version of a
    # document, so the link needs it too.
    sbom_version: int = 1
    sbom_name: str = ''
    # Who made these statements, as the parsed file records it. Empty if the file
    # does not say, or if the model was built and not parsed. Same as SBOM.creator:
    # render ignores it and writes the tool name.
    author: str = ''


def _product(pkg: Package) -> VexProduct:
    return VexProduct(
        ref=pkg.ref,
        purl=pkg.purl,
        cpes=list(pkg.cpes),
        name=pkg.package_name,
        version=pkg.version,
    )


def _justification(entry: Dict[str, Any]) -> Optional[VexJustification]:
    """The justification of a cve-exclude-list entry. Manifests are validated, but
    an excluded_cves.yaml file outside this repository is not, so an unknown value
    is skipped."""
    value = entry.get('justification')
    if value is None:
        return None
    try:
        return VexJustification(value)
    except ValueError:
        log.warn(f'Ignoring unknown justification "{value}" for {entry["cve"]}.')
        return None


def build(sbom: SBOM, sbom_id: str = '') -> Vex:
    """Create a VEX model from an SBOM model. This is the VEX side of sbom.build().

    Each cve-exclude-list entry becomes one not-affected statement for its own
    package. Entries are not merged across packages, even for the same CVE with
    the same reason, because then it would not be clear which package each reason
    was written for.

    :param sbom: the SBOM model to read the exclusions from
    :param sbom_id: id of the document the SBOM was read from. Backends that link
        a standalone VEX to the SBOM need it. Leave it empty for embedded VEX.
    """
    statements = [
        VexStatement(
            vulnerability=entry['cve'],
            status=VexStatus.NOT_AFFECTED,
            products=[_product(pkg)],
            justification=_justification(entry),
            # The CVE does not affect this version, so no fix is planned.
            response=[VexResponse.WILL_NOT_FIX],
            impact_statement=entry['reason'],
        )
        for pkg in sbom.packages
        for entry in pkg.cve_exclude_list
    ]

    return Vex(statements=statements, sbom_id=sbom_id, sbom_name=sbom.name)


# Statuses that say the CVE does not apply to the product. not_affected means it
# was never affected, fixed means the product carries the fix. grype and trivy
# both filter on these two. The other two say the CVE does apply, or that nobody
# knows yet, so they must not silence anything.
_SUPPRESSING = (VexStatus.NOT_AFFECTED, VexStatus.FIXED)


def _reason(statement: VexStatement) -> str:
    """The text reported for a suppressed CVE.

    A not_affected statement carries an impact statement or a justification. A
    fixed one needs neither, so fall back to the status itself.
    """
    if statement.impact_statement:
        return statement.impact_statement
    if statement.justification is not None:
        return statement.justification.value
    return statement.status.value


def apply(sbom: SBOM, vexdoc: Vex) -> None:
    """Merge the statements of a VEX document into the SBOM model.

    The statements end up in Package.cve_exclude_list, which is where every
    consumer of the model already reads them from, so nothing downstream has to
    know a VEX file was involved. Only the statuses in _SUPPRESSING are used.

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
        if statement.status not in _SUPPRESSING:
            continue
        for product in statement.products:
            pkg = find(product)
            if pkg is None:
                unmatched += 1
                continue
            # The VEX file is the newer document, so it wins over an exclusion
            # of the same CVE already in the SBOM.
            entries = [e for e in pkg.cve_exclude_list if e['cve'] != statement.vulnerability]
            entries.append({'cve': statement.vulnerability, 'reason': _reason(statement)})
            pkg.cve_exclude_list = entries

    if unmatched:
        # Not an error. A VEX file may cover a whole product line, so it can name
        # components that this SBOM does not contain.
        log.warn(f'{unmatched} VEX statement(s) name a component that is not in the SBOM; they were ignored.')
