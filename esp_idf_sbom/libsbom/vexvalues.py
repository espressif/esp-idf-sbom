# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""The values of the VEX model: statuses, justifications and responses.

The model uses the CISA vocabulary: four statuses and five justifications.
OpenVEX and the SPDX 3.0.1 security profile use it as it is. Only the CycloneDX
backend has to map it to its own six states and nine justifications. The
response is the exception: CISA has no such field, so the model uses the five
CycloneDX values, and only CycloneDX writes it.

This module imports nothing from esp_idf_sbom. So mft.py, which sbom.py imports,
and test/validate_excluded_cves.py can use the values too, not only vex.py.
"""

from enum import Enum


class VexStatus(Enum):
    """Status of a product for a vulnerability. These are the four CISA statuses."""

    NOT_AFFECTED = 'not_affected'
    AFFECTED = 'affected'
    FIXED = 'fixed'
    UNDER_INVESTIGATION = 'under_investigation'


class VexJustification(Enum):
    """Why a product is not affected. These are the five CISA justifications.
    Used only with the not_affected status."""

    COMPONENT_NOT_PRESENT = 'component_not_present'
    VULNERABLE_CODE_NOT_PRESENT = 'vulnerable_code_not_present'
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = 'vulnerable_code_not_in_execute_path'
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = 'vulnerable_code_cannot_be_controlled_by_adversary'
    INLINE_MITIGATIONS_ALREADY_EXIST = 'inline_mitigations_already_exist'


class VexResponse(Enum):
    """What the supplier does about the vulnerability. These are the five
    CycloneDX values."""

    CAN_NOT_FIX = 'can_not_fix'
    WILL_NOT_FIX = 'will_not_fix'
    UPDATE = 'update'
    ROLLBACK = 'rollback'
    WORKAROUND_AVAILABLE = 'workaround_available'
