# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""The values of the VEX model: statuses, justifications and responses.

A value keeps only an id. The id means nothing outside this module. The tables
of each class give the names of a value:

* The constructor takes a CISA or a CycloneDX name, for example
  VexStatus('affected') or VexStatus('exploitable'). Both give the same status.
* str() gives the name that esp-idf-sbom writes in its own fields: the check
  report and the SPDX 2.2 package comment.
* .cisa and .cyclonedx give the name that a format uses. OpenVEX and SPDX 3.0.1
  use the CISA name.

The code asks a value what it means, for example status.is_affected. It does not
compare names.

This module imports nothing from esp_idf_sbom. So mft.py, which sbom.py imports,
and test/validate_excluded_cves.py can use the values too, not only vex.py.
"""

from typing import ClassVar
from typing import Dict
from typing import List


class _VexValue:
    """A value of the VEX model. _NAMES maps each id to the names that the
    constructor takes, and str() gives the first one."""

    _NAMES: ClassVar[Dict[str, List[str]]]

    def __init__(self, name: str) -> None:
        for key, names in self._NAMES.items():
            if name in names:
                self._id = key
                return
        raise ValueError(f'"{name}" is not a {type(self).__name__}.')

    @classmethod
    def names(cls) -> List[str]:
        """All names that the constructor takes."""
        return [name for names in cls._NAMES.values() for name in names]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and other._id == self._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __str__(self) -> str:
        return self._NAMES[self._id][0]

    def __repr__(self) -> str:
        return f'{type(self).__name__}({str(self)!r})'


class VexStatus(_VexValue):
    """Status of a product for a vulnerability: the four CISA statuses, and
    false_positive and resolved_with_pedigree, which only CycloneDX has. The other
    CycloneDX states mean the same as a CISA status, for example exploitable means
    affected, so they give that status."""

    _NAMES = {
        'NOT_AFFECTED': ['not_affected'],
        'AFFECTED': ['affected', 'exploitable'],
        'FIXED': ['fixed', 'resolved'],
        'UNDER_INVESTIGATION': ['under_investigation', 'in_triage'],
        'FALSE_POSITIVE': ['false_positive'],
        'RESOLVED_WITH_PEDIGREE': ['resolved_with_pedigree'],
    }
    # CISA has no false_positive and no resolved_with_pedigree, so they are written
    # as not_affected and fixed.
    _CISA = {
        'NOT_AFFECTED': 'not_affected',
        'AFFECTED': 'affected',
        'FIXED': 'fixed',
        'UNDER_INVESTIGATION': 'under_investigation',
        'FALSE_POSITIVE': 'not_affected',
        'RESOLVED_WITH_PEDIGREE': 'fixed',
    }
    _CYCLONEDX = {
        'NOT_AFFECTED': 'not_affected',
        'AFFECTED': 'exploitable',
        'FIXED': 'resolved',
        'UNDER_INVESTIGATION': 'in_triage',
        'FALSE_POSITIVE': 'false_positive',
        'RESOLVED_WITH_PEDIGREE': 'resolved_with_pedigree',
    }

    @property
    def cisa(self) -> str:
        """The CISA status, which OpenVEX and SPDX 3.0.1 use."""
        return self._CISA[self._id]

    @property
    def cyclonedx(self) -> str:
        """The CycloneDX analysis state."""
        return self._CYCLONEDX[self._id]

    @property
    def is_not_affected(self) -> bool:
        """Whether the product is not affected. A false positive is not affected too."""
        return self._id in ('NOT_AFFECTED', 'FALSE_POSITIVE')

    @property
    def is_affected(self) -> bool:
        """Whether the product is affected."""
        return self._id == 'AFFECTED'

    @property
    def is_fixed(self) -> bool:
        """Whether the product carries the fix. resolved_with_pedigree is fixed too."""
        return self._id in ('FIXED', 'RESOLVED_WITH_PEDIGREE')

    @property
    def is_under_investigation(self) -> bool:
        """Whether it is not known yet if the product is affected."""
        return self._id == 'UNDER_INVESTIGATION'

    @property
    def allows_justification(self) -> bool:
        """Whether a justification can say why the product is not affected: for
        not_affected and false_positive. OpenVEX and SPDX 3.0.1 write false_positive
        as not_affected, and CISA and SPDX 3.0.1 have justifications only for
        not_affected. CycloneDX does not tie a justification to a state."""
        return self._id in ('NOT_AFFECTED', 'FALSE_POSITIVE')

    @property
    def suppresses(self) -> bool:
        """Whether the status says that the CVE does not apply to the product.

        not_affected means it was never affected, fixed means the product carries
        the fix. grype and trivy both filter on these two. false_positive counts as
        not_affected, and resolved_with_pedigree as fixed. affected and
        under_investigation say that the CVE does apply, or that nobody knows yet,
        so they must not hide anything.
        """
        return self.is_not_affected or self.is_fixed


class VexJustification(_VexValue):
    """Why a product is not affected: one of the five CISA justifications or one
    of the nine CycloneDX justifications. Used only with the not_affected status.

    Neither set can say all that the other can. CISA has two values where
    CycloneDX has only code_not_present, and CycloneDX has five values where CISA
    has only vulnerable_code_cannot_be_controlled_by_adversary. So the model
    keeps the value as it was given.
    """

    _NAMES = {
        # CISA
        'COMPONENT_NOT_PRESENT': ['component_not_present'],
        'VULNERABLE_CODE_NOT_PRESENT': ['vulnerable_code_not_present'],
        'VULNERABLE_CODE_NOT_IN_EXECUTE_PATH': ['vulnerable_code_not_in_execute_path'],
        'VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY': ['vulnerable_code_cannot_be_controlled_by_adversary'],
        'INLINE_MITIGATIONS_ALREADY_EXIST': ['inline_mitigations_already_exist'],
        # CycloneDX
        'CODE_NOT_PRESENT': ['code_not_present'],
        'CODE_NOT_REACHABLE': ['code_not_reachable'],
        'REQUIRES_CONFIGURATION': ['requires_configuration'],
        'REQUIRES_DEPENDENCY': ['requires_dependency'],
        'REQUIRES_ENVIRONMENT': ['requires_environment'],
        'PROTECTED_BY_COMPILER': ['protected_by_compiler'],
        'PROTECTED_AT_RUNTIME': ['protected_at_runtime'],
        'PROTECTED_AT_PERIMETER': ['protected_at_perimeter'],
        'PROTECTED_BY_MITIGATING_CONTROL': ['protected_by_mitigating_control'],
    }
    # CISA has none of the CycloneDX values, so each of them is written as the CISA
    # value closest to it.
    _CISA = {
        'COMPONENT_NOT_PRESENT': 'component_not_present',
        'VULNERABLE_CODE_NOT_PRESENT': 'vulnerable_code_not_present',
        'VULNERABLE_CODE_NOT_IN_EXECUTE_PATH': 'vulnerable_code_not_in_execute_path',
        'VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY': 'vulnerable_code_cannot_be_controlled_by_adversary',
        'INLINE_MITIGATIONS_ALREADY_EXIST': 'inline_mitigations_already_exist',
        'CODE_NOT_PRESENT': 'vulnerable_code_not_present',
        'CODE_NOT_REACHABLE': 'vulnerable_code_not_in_execute_path',
        'REQUIRES_CONFIGURATION': 'vulnerable_code_cannot_be_controlled_by_adversary',
        'REQUIRES_DEPENDENCY': 'vulnerable_code_cannot_be_controlled_by_adversary',
        'REQUIRES_ENVIRONMENT': 'vulnerable_code_cannot_be_controlled_by_adversary',
        'PROTECTED_BY_COMPILER': 'inline_mitigations_already_exist',
        'PROTECTED_AT_RUNTIME': 'vulnerable_code_cannot_be_controlled_by_adversary',
        'PROTECTED_AT_PERIMETER': 'vulnerable_code_cannot_be_controlled_by_adversary',
        'PROTECTED_BY_MITIGATING_CONTROL': 'inline_mitigations_already_exist',
    }
    # CycloneDX has none of the CISA values, so each of them is written as the
    # CycloneDX value closest to it. component_not_present and
    # vulnerable_code_not_present are both code_not_present.
    _CYCLONEDX = {
        'COMPONENT_NOT_PRESENT': 'code_not_present',
        'VULNERABLE_CODE_NOT_PRESENT': 'code_not_present',
        'VULNERABLE_CODE_NOT_IN_EXECUTE_PATH': 'code_not_reachable',
        'VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY': 'protected_at_runtime',
        'INLINE_MITIGATIONS_ALREADY_EXIST': 'protected_by_mitigating_control',
        'CODE_NOT_PRESENT': 'code_not_present',
        'CODE_NOT_REACHABLE': 'code_not_reachable',
        'REQUIRES_CONFIGURATION': 'requires_configuration',
        'REQUIRES_DEPENDENCY': 'requires_dependency',
        'REQUIRES_ENVIRONMENT': 'requires_environment',
        'PROTECTED_BY_COMPILER': 'protected_by_compiler',
        'PROTECTED_AT_RUNTIME': 'protected_at_runtime',
        'PROTECTED_AT_PERIMETER': 'protected_at_perimeter',
        'PROTECTED_BY_MITIGATING_CONTROL': 'protected_by_mitigating_control',
    }

    @property
    def cisa(self) -> str:
        """The CISA justification, which OpenVEX and SPDX 3.0.1 use."""
        return self._CISA[self._id]

    @property
    def cyclonedx(self) -> str:
        """The CycloneDX justification."""
        return self._CYCLONEDX[self._id]


class VexResponse(_VexValue):
    """What the supplier does about the vulnerability: the five CycloneDX values.
    CISA has no such field, so only CycloneDX writes it."""

    _NAMES = {
        'CAN_NOT_FIX': ['can_not_fix'],
        'WILL_NOT_FIX': ['will_not_fix'],
        'UPDATE': ['update'],
        'ROLLBACK': ['rollback'],
        'WORKAROUND_AVAILABLE': ['workaround_available'],
    }
    _CYCLONEDX = {
        'CAN_NOT_FIX': 'can_not_fix',
        'WILL_NOT_FIX': 'will_not_fix',
        'UPDATE': 'update',
        'ROLLBACK': 'rollback',
        'WORKAROUND_AVAILABLE': 'workaround_available',
    }

    @property
    def cyclonedx(self) -> str:
        """The CycloneDX response."""
        return self._CYCLONEDX[self._id]
