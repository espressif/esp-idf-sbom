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


def nvd_request(params: str) -> List[Dict[str, Any]]:
    """When NVD API key is not provided, sleeps for 30 seconds to
    meet NVD's 5 requests per rolling 30 seconds windows limit.
    """
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    vulns = []
    start_idx = 0
    unavailable_cnt = 0
    apikey = os.environ.get('NVDAPIKEY')
    global WARNED

    while True:
        url = f'{base_url}?{params}&startIndex={start_idx}'
        req = urllib.request.Request(url)
        if apikey:
            req.add_header('apikey', apikey)

        log.debug(f'NVD request url: {url}')
        log.debug('NVD request headers:')
        log.debug('\n'.join([f'{h}: {v}' for h, v in req.header_items()]))

        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                data = json.loads(res.read().decode())

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

        except OSError as e:
            # We may encounter a read error from the underlying socket. If that happens,
            # allow up to 3 retries along with 503 HTTP error.
            unavailable_cnt += 1
            log.warn(f'Unable to read response from NVD server: {e}. Retrying({unavailable_cnt}).')
            if unavailable_cnt < 3:
                continue
            raise

        log.debug('NVD response:')
        log.debug(json.dumps(data, indent=4))

        vulns += data['vulnerabilities']

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

    return vulns


# https://nvd.nist.gov/developers/vulnerabilities
def check(cpe: str, search_name: bool=False) -> List[Dict[str, Any]]:
    """Checks given CPE against NVD and returns its reponse."""

    # Check vulnerabilities that have already been processed in the NVD and have an assigned CPE.
    cpe_vulns = nvd_request(f'cpeName={cpe}')

    if not search_name:
        return cpe_vulns

    # Check for vulnerabilities using the package name from CPE and do keywordSearch.
    pkg_name = cpe.split(':')[4]
    keyword_vulns = nvd_request(f'keywordSearch={pkg_name}')

    for vuln in keyword_vulns:
        if vuln['cve']['vulnStatus'] in ['Received', 'Awaiting Analysis', 'Undergoing Analysis']:
            # CVE not analyzed in NVD, include it in the results.
            cpe_vulns.append(vuln)

    return cpe_vulns
