# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
NVD National Vulnerability Database checker
"""

import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

import yaml

from esp_idf_sbom.libsbom import CPE, git, log, utils

HINT = '''\
NVD REST API five requests in a rolling 30 second window reached.
To overcome this limitation you may request NVD API key at
https://nvd.nist.gov/developers/request-an-api-key and set the NVDAPIKEY
environmental variable. For more information please see
https://nvd.nist.gov/developers/start-here, section "Rate Limits".'''
WARNED = False

NVD_MIRROR_URL = 'https://github.com/espressif/esp-nvd-mirror.git'


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

        # NVD recommends waiting for six seconds between requests.
        # https://nvd.nist.gov/developers/start-here
        time.sleep(6)
        try:
            with urllib.request.urlopen(req, timeout=60) as res:
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
            if unavailable_cnt < 3:
                unavailable_cnt += 1
                log.warn(f'Unable to read response from NVD server: {e}. Retrying({unavailable_cnt}) in 10 second...')
                time.sleep(10)
                continue
            raise

        log.debug('NVD response:')
        log.debug(json.dumps(data, indent=4))

        vulns += data['vulnerabilities']

        start_idx += int(data['resultsPerPage'])
        if int(data['totalResults']) == start_idx:
            break

    return vulns


def get_excluded_cves(cache: Dict[str, Dict[str, Any]]={}) -> Dict[str, Any]:
    """Retrieve the YAML file from the esp-idf-sbom repository, which includes a list of excluded CVEs."""

    if 'cves' in cache:
        # Download the excluded CVEs once per script run, not for each check.
        return cache['cves']

    cves: Dict[str, Any] = {}
    url = 'https://raw.githubusercontent.com/espressif/esp-idf-sbom/master/excluded_cves.yaml'
    req = urllib.request.Request(url)

    for retry in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                cves = yaml.safe_load(res.read().decode())
            break

        except urllib.error.HTTPError as e:
            log.warn(f'Cannot download list of excluded CVEs: {e}. Retrying({retry}) ...')

        except yaml.YAMLError as e:
            log.warn(f'Cannot load list of excluded CVEs: {e}')
            break
    else:
        log.warn(f'Failed to download list of excluded CVEs')

    cache['cves'] = cves
    return cves


# https://nvd.nist.gov/developers/vulnerabilities
def check_cpe(cpe: str, localdb: bool=False) -> List[Dict[str, Any]]:
    """Check given CPE against NVD data."""

    # Check vulnerabilities that have already been processed in the NVD and have an assigned CPE.
    if localdb:
        cpe_vulns = repo_check(cpe)
    else:
        cpe = urllib.parse.quote(cpe)
        cpe_vulns = nvd_request(f'cpeName={cpe}')

    return cpe_vulns


def check_keyword(keyword: str, localdb: bool=False) -> List[Dict[str, Any]]:
    """Check given keyword against CVE description."""

    cpe_vulns: List[Dict[str, Any]] = []

    # Obtain the list of excluded CVEs to filter them out from the unanalyzed CVEs provided by NVD.
    excluded_cves = get_excluded_cves()

    if localdb:
        keyword_vulns = repo_keyword(keyword)
    else:
        keyword = urllib.parse.quote(keyword)
        keyword_vulns = nvd_request(f'keywordSearch={keyword}&keywordExactMatch')

    for vuln in keyword_vulns:
        if vuln['cve']['vulnStatus'] in ['Received', 'Awaiting Analysis', 'Undergoing Analysis']:
            # CVE not analyzed in NVD, include it in the results.
            if vuln['cve']['id'] in excluded_cves:
                # This CVE was previously analyzed and determined to be a false positive, unrelated to ESP-IDF.
                continue
            cpe_vulns.append(vuln)

    return cpe_vulns


def local_db_path() -> str:
    dst_path = Path.home() / '.esp-idf-sbom' / 'nvd'
    dst_path.mkdir(parents=True, exist_ok=True)
    return str(dst_path)


def local_db_version() -> str:
    db_path = local_db_path()
    cmd = ['git', '-C', db_path, 'rev-parse', 'HEAD']
    rv, stdout, stderr = utils.run(cmd, die=True)
    sha = stdout.strip()
    return f'{NVD_MIRROR_URL}@{sha}'


# Scanning is performed for each CPE individually, primarily because the NVD REST
# API does not support querying multiple CPEs in a single request. When using a
# local NVD mirror, this would require searching through the git repository for
# each CPE, which is time-consuming. To address this, a cache is used to search
# for all CPEs at once locally and store the relevant CVEs in cache. Subsequently,
# scanning is still done per CPE, as with the NVD REST API, but it uses this
# local cache.
CVE_CACHE: List[Dict[str, Any]] = []


def cache_cves(cpes: List[str], keywords: List[str]) -> None:
    if not git.get_gitdir(local_db_path()):
        raise RuntimeError('Local NVD mirror repository not found. Please use the sync-db command.')

    if not cpes and not keywords:
        return

    global CVE_CACHE
    cpe_bases = [':'.join(cpe.split(':')[:5]) + ':' for cpe in cpes]

    repo = local_db_path()

    # -l - Show only file names
    # -i - Ignore case differences between the patterns
    # -F - Use fixed strings for patterns (don’t interpret pattern as a regex
    cmd = ['git', '-C', repo, 'grep', '-l', '-i', '-F']
    for cpe_base in cpe_bases:
        cmd += ['-e', cpe_base]
    for keyword in keywords:
        cmd += ['-e', keyword]
    cmd += ['HEAD', '--', 'cve']

    rv, stdout, stderr = utils.run(cmd)
    if rv not in [0,1]:
        # git fatal error
        raise RuntimeError(stderr)
    for cve_fn in stdout.splitlines():
        rv, stdout, stderr = utils.run(['git', '-C', repo, 'show', cve_fn], die=True)
        cve = json.loads(stdout)
        CVE_CACHE.append(cve)


def get_cves_for_cpe(cpe: str) -> List[Dict[str, Any]]:
    global CVE_CACHE
    res: List[Dict[str, Any]] = []
    cpe_base = ':'.join(cpe.split(':')[:5])

    for cve in CVE_CACHE:
        if 'configurations' not in cve['cve']:
            # There was no configuration, so the CVE has not been analyzed yet.
            continue

        configurations = cve['cve']['configurations']

        for configuration in configurations:
            for node in configuration['nodes']:
                for cpe_match in node['cpeMatch']:
                    criteria = cpe_match['criteria'].lower()
                    if criteria.startswith(cpe_base):
                        res.append(cve)
                        break
                else:
                    continue
                break
            else:
                continue
            break

    return res


def get_match_criteria(criteria_id: str) -> List[str]:
    repo = local_db_path()
    criteria_fn = f'HEAD:cpematch/{criteria_id[:2]}/{criteria_id}.json'

    rv, stdout, stderr = utils.run(['git', '-C', repo, 'show', criteria_fn])
    if rv:
        log.warn(f'Match Criteria {criteria_id}: File not found')
        return []

    match_criteria = json.loads(stdout)
    if 'matches' not in match_criteria['matchString']:
        return [match_criteria['matchString']['criteria']]

    return [match['cpeName'] for match in match_criteria['matchString']['matches']]


def evaluate_cpematch(cpe: str, cpe_match: Dict[str, Any]) -> bool:
    if not cpe_match['vulnerable']:
        return False

    criteria = cpe_match['criteria']
    if CPE.compare(cpe, criteria) not in [CPE.AV_REL_EQUAL, CPE.AV_REL_SUBSET]:
        # If cpe is not a subset of the criteria, skip matching with CPE names (targets)
        # from the match criteria. We can likely return True immediately if cpe and
        # criteria are AV_REL_EQUAL.
        return False

    criteria_id = cpe_match['matchCriteriaId']
    targets = get_match_criteria(criteria_id)
    if not targets:
        log.warn(f'No CPE Names found for {criteria_id}. CPE {cpe} has not been evaluated.')
        return False

    for target in targets:
        try:
            if CPE.match(cpe, target):
                return True
        except RuntimeError as e:
            log.warn(e)
            continue

    return False


def evaluate_node(cpe: str, node: Dict[str, Any]) -> bool:
    res_list: List[bool] = []
    res: bool = False

    operator = node.get('operator')
    negate = node.get('negate', False)

    for cpe_match in node['cpeMatch']:
        cpe_match_res = evaluate_cpematch(cpe, cpe_match)
        if operator == 'AND' and not cpe_match_res:
            # Short-circuit evaluation
            res = False
            break
        if operator == 'OR' and cpe_match_res:
            # Short-circuit evaluation
            res = True
            break
        res_list.append(cpe_match_res)
    else:
        if operator == 'AND':
            res = all(res_list)
        else:
            res = any(res_list)

    return not res if negate else res


def is_configuration_vulnerable(cpe: str, configuration: Dict[str, Any]) -> bool:
    # Applicability Language implementation
    res_list: List[bool] = []
    res: bool = False

    operator = configuration.get('operator')
    negate = configuration.get('negate', False)

    for node in configuration['nodes']:
        node_res = evaluate_node(cpe, node)
        if operator == 'AND' and not node_res:
            # Short-circuit evaluation
            res = False
            break
        if operator == 'OR' and node_res:
            # Short-circuit evaluation
            res = True
            break
        res_list.append(node_res)
    else:
        if operator == 'AND':
            res = all(res_list)
        elif operator == 'OR':
            res = any(res_list)
        else:
            assert len(res_list) == 1
            res = res_list[0]

    return not res if negate else res


def vercmp(ver1: str, ver2: str) -> int:
    # -1 ver1 < ver2
    #  0 ver1 == ver2
    #  1 ver1 > ver2
    v1_parts = [part for part in ver1.split('.')]
    v2_parts = [part for part in ver2.split('.')]

    # compare each part
    for p1, p2 in zip(v1_parts, v2_parts):
        try:
            # try to compare parts as int
            if int(p1) < int(p2):
                return -1
            elif int(p1) > int(p2):
                return 1
        except ValueError:
            # fallback to string
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1

    # if all compared parts are equal, compare lengths
    if len(v1_parts) < len(v2_parts):
        return -1
    elif len(v1_parts) > len(v2_parts):
        return 1
    else:
        return 0    # versions are equal


def is_version_vulnerable(cpe: str, configuration: Dict[str, Any]) -> bool:
    cpe_base = ':'.join(cpe.split(':')[:5])
    cpe_ver = cpe.split(':')[5]

    for node in configuration['nodes']:
        for cpe_match in node['cpeMatch']:
            if not cpe_match['vulnerable']:
                # skip, cpe_match not vulnerable
                continue

            if not cpe_match['criteria'].startswith(cpe_base):
                # skip, not cpe we want to check
                continue

            versionStartExcluding = cpe_match.get('versionStartExcluding')
            versionStartIncluding = cpe_match.get('versionStartIncluding')
            versionEndExcluding = cpe_match.get('versionEndExcluding')
            versionEndIncluding = cpe_match.get('versionEndIncluding')

            if not any((versionStartExcluding, versionStartIncluding,
                       versionEndExcluding, versionEndIncluding)):
                # If there is no version range information available, compare
                # the version from the CPE with the version from cpeMatch
                # criteria.
                criteria_ver = cpe_match['criteria'].split(':')[5]
                if criteria_ver == cpe_ver:
                    return True

                # skip, no version information
                continue

            if versionStartExcluding and vercmp(cpe_ver, versionStartExcluding) <= 0:
                continue
            if versionStartIncluding and vercmp(cpe_ver, versionStartIncluding) < 0:
                continue
            if versionEndExcluding and vercmp(cpe_ver, versionEndExcluding) >= 0:
                continue
            if versionEndIncluding and vercmp(cpe_ver, versionEndIncluding) > 0:
                continue

            return True

    return False


def repo_check(cpe: str) -> List[Dict[str, Any]]:
    res: List[Dict[str, Any]] = []

    cves = get_cves_for_cpe(cpe)
    for cve in cves:
        for configuration in cve['cve']['configurations']:
            if is_configuration_vulnerable(cpe, configuration):
                res.append(cve)
                break
            # No CPE match found for CVE using configuration evaluation and matchStrings.
            # Try to compare the version in given CPE with version ranges in cpeMatch.
            # This is a fallback approach in case the tested CPE is not listed in matchString.
            if is_version_vulnerable(cpe, configuration):
                res.append(cve)
                break
    return res


def repo_keyword(keyword: str) -> List[Dict[str, Any]]:
    global CVE_CACHE
    res: List[Dict[str, Any]] = []

    # Ignore all re special characters in keyword.
    keyword = re.escape(keyword)

    for cve in CVE_CACHE:
        for desc in cve['cve']['descriptions']:
            value = desc['value']
            # This should emulate the keywordSearch parameter of the NVD API.
            # Keyword search operates as though a wildcard is placed after each
            # keyword provided. For example, providing "circle" will return results
            # such as "circles" but not "encircle".
            if re.search(rf'(\s|^){keyword}', value, re.IGNORECASE):
                res.append(cve)
                break
    return res


def sync() -> int:
    dst = local_db_path()
    if not git.get_gitdir(dst):
        log.eprint(f'Cloning NVD data from repository {NVD_MIRROR_URL} to {dst}. This may take some time.')
        cmd = ['git', 'clone', '--bare', '--depth', '1', '--single-branch', '--branch',
               'master', '--no-tags', NVD_MIRROR_URL, dst]
    else:
        log.eprint(f'Synchronizing NVD data from the remote repository {NVD_MIRROR_URL} to {dst}.')
        cmd = ['git', '-C', dst, 'fetch', '--depth', '1', '--force', '--no-tags',
               'origin', 'master:master']

    rv, _, _ = utils.run(cmd, stdout=False, stderr=False)
    return rv
