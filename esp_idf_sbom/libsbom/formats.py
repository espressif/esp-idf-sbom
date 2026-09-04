# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Output formats and the parse side dispatchers.

This module sits above the backends: it knows every format esp-idf-sbom can write
and read, and the backends know nothing about it. That is why the format tables
and the load functions live here and not in sbom.py or vex.py. Those hold the
models, which the backends import, so a dispatcher inside them would have to
import the backends back and could only do so at call time.

    sbom.py, vex.py            the models
    cyclonedx, spdx, openvex   the backends, they import the models
    formats.py                 the tables and the dispatchers, they import the backends
"""

import json
import sys
from typing import Any
from typing import Dict
from typing import NamedTuple

from esp_idf_sbom.libsbom import cyclonedx
from esp_idf_sbom.libsbom import openvex
from esp_idf_sbom.libsbom import spdx
from esp_idf_sbom.libsbom import vex
from esp_idf_sbom.libsbom.sbom import SBOM


class SbomFormat(NamedTuple):
    """One create --format choice: the backend that renders it, the backend's
    render encoding, the spec version to emit, and the conventional file
    extension (used e.g. by the idf.py wrapper to name the output file)."""

    backend: Any
    encoding: str
    version: str
    ext: str


# Maps each create --format choice to its SbomFormat. A bare name (e.g. spdx-json)
# is an alias for the latest supported version of that format; pinning a specific
# version uses an @version suffix (e.g. spdx-json@2.2). The bare alias may advance
# to a newer version on a major esp-idf-sbom release (a breaking change), so pin
# name@version for reproducible output. Adding a format or a version is just another
# row here; --format derives its accepted values from these keys.
SBOM_FORMATS: Dict[str, SbomFormat] = {
    'spdx-tag-value': SbomFormat(spdx, 'tagvalue', '2.2', '.spdx'),
    'spdx-tag-value@2.2': SbomFormat(spdx, 'tagvalue', '2.2', '.spdx'),
    'spdx-json': SbomFormat(spdx, 'json', '2.2', '.spdx.json'),
    'spdx-json@2.2': SbomFormat(spdx, 'json', '2.2', '.spdx.json'),
    'spdx-json-ld': SbomFormat(spdx, 'json-ld', '3.0.1', '.spdx.jsonld'),
    'spdx-json-ld@3.0.1': SbomFormat(spdx, 'json-ld', '3.0.1', '.spdx.jsonld'),
    'cyclonedx-json': SbomFormat(cyclonedx, 'json', '1.6', '.cdx.json'),
    'cyclonedx-json@1.6': SbomFormat(cyclonedx, 'json', '1.6', '.cdx.json'),
}


class VexFormat(NamedTuple):
    """One create --vex choice that writes a file. Same as SbomFormat, plus "linked".

    A linked format points to the SBOM document. A CycloneDX VEX uses a BOM-Link
    built from the SBOM serialNumber, so it needs a CycloneDX SBOM. OpenVEX names
    products by PURL and CPE and works with any SBOM format."""

    backend: Any
    encoding: str
    version: str
    linked: bool
    ext: str


# --vex values that are not a format: the VEX goes into the SBOM, or nowhere.
VEX_IN_SBOM = ('embed', 'none')

VEX_FORMATS: Dict[str, VexFormat] = {
    'openvex': VexFormat(openvex, 'json', '0.2.0', False, '.openvex.json'),
    'openvex@0.2.0': VexFormat(openvex, 'json', '0.2.0', False, '.openvex.json'),
    'cyclonedx-json': VexFormat(cyclonedx, 'json', '1.6', True, '.vex.cdx.json'),
    'cyclonedx-json@1.6': VexFormat(cyclonedx, 'json', '1.6', True, '.vex.cdx.json'),
}


def load_sbom(path: str) -> SBOM:
    """Read an SBOM file (or stdin when path is '-'), detect its format and parse
    it into the format-neutral model.

    This is the parse side entry point, mirroring sbom.build() on the gather side.
    """
    if path == '-':
        text = sys.stdin.read()
    else:
        with open(path) as f:
            text = f.read()

    # Parse the structure first and dispatch on the top-level keys, rather than
    # substring-matching the raw text (which misroutes a JSON SBOM that merely
    # mentions e.g. "SPDXID:" in a path or description). Tag/value SPDX is the
    # only non-JSON serialization, so it is the fallback.
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None

    if isinstance(obj, dict):
        if 'bomFormat' in obj:
            return cyclonedx.parse(text)
        if '@context' in obj or '@graph' in obj:
            return spdx.parse(text, format='json-ld')
        if 'spdxVersion' in obj:
            return spdx.parse(text, format='json')
        raise ValueError('unrecognized JSON SBOM format')

    if 'SPDXVersion:' in text or 'SPDXID:' in text:
        return spdx.parse(text)
    raise ValueError('unrecognized SBOM format')


def load_vex(path: str) -> vex.Vex:
    """Read a VEX file, detect its format and parse it into the model.

    This is the parse side entry point, like load_sbom() for SBOM files. Unlike
    load_sbom() it does not read standard input, because that is where the SBOM
    itself is read from.
    """
    with open(path) as f:
        text = f.read()

    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError('unrecognized VEX format')
    if 'openvex.dev' in str(obj.get('@context', '')):
        return openvex.parse_vex(text)
    if obj.get('bomFormat') == 'CycloneDX':
        return cyclonedx.parse_vex(text)
    raise ValueError('unrecognized VEX format')
