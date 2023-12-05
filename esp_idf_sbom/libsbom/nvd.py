# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
NVD National Vulnerability Database checker
"""

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List

from esp_idf_sbom.libsbom import log

HINT = '''\
NVD REST API five requests in a rolling 30 second window reached.
To overcome this limitation you may request NVD API key at
https://nvd.nist.gov/developers/request-an-api-key and set the NVDAPIKEY
environmental variable. For more information please see
https://nvd.nist.gov/developers/start-here, section "Rate Limits".'''
WARNED = False


# https://nvd.nist.gov/developers/vulnerabilities
def check(cpe: str) -> List[Dict[str, Any]]:
    """Checks given CPE against NVD and returns its reponse.
    When NVD API key is not provided, sleeps for 30 seconds to
    meet NVD's 5 requests per rolling 30 seconds windows limit.
    """
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    vulns = []
    start_idx = 0
    unavailable_cnt = 0
    apikey = os.environ.get('NVDAPIKEY')
    global WARNED

    while True:
        url = f'{base_url}?cpeName={cpe}&startIndex={start_idx}'
        req = urllib.request.Request(url)
        if apikey:
            req.add_header('apikey', apikey)

        log.debug(f'NVD request url: {url}')
        log.debug('NVD request headers:')
        log.debug('\n'.join([f'{h}: {v}' for h, v in req.header_items()]))

        try:
            res = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # https://nvd.nist.gov/developers/start-here Rate Limits
                if not WARNED:
                    log.warn(HINT)
                    WARNED = True
                log.warn(f'Sleeping for 30 seconds...')
                time.sleep(30)
                continue
            elif e.code == 503 and unavailable_cnt < 3:
                unavailable_cnt += 1
                log.warn(f'NVD server unavailable(503). Retrying({unavailable_cnt}) in 10 seconds...')
                time.sleep(10)
                continue

            raise RuntimeError(f'HTTP GET for "{url}" returned error: "{e}"')

        data = json.loads(res.read().decode())

        log.debug('NVD response:')
        log.debug(json.dumps(data, indent=4))

        vulns += data['vulnerabilities']

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

    return vulns
