#!/usr/bin/env python

# SPDX-FileCopyrightText: 2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import re
import sys

import yaml

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')

for fn in sys.argv[1:]:
    with open(fn, 'r') as f:
        cves = yaml.safe_load(f)
    for cve in cves:
        match = CVE_RE.match(cve)
        if not match:
            sys.exit(f'{cve} does not match CVE format')
