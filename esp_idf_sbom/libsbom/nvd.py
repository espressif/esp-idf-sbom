# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
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
from typing import Any
from typing import Dict
from typing import List

import yaml

from esp_idf_sbom.libsbom import CPE
from esp_idf_sbom.libsbom import git
from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom import utils

HINT = """\
NVD REST API five requests in a rolling 30 second window reached.
To overcome this limitation you may request NVD API key at
https://nvd.nist.gov/developers/request-an-api-key and set the NVDAPIKEY
environmental variable. For more information please see
https://nvd.nist.gov/developers/start-here, section "Rate Limits"."""
WARNED = False

NVD_MIRROR_URL = 'https://github.com/espressif/esp-nvd-mirror.git'

# On-disk cache for excluded_cves.yaml. The file is refreshed from the upstream
# repository at most once per EXCLUDED_CVES_TTL_SECONDS; within that window the
# cached copy is used directly. On fetch failure we fall back to the cached
# copy (even if stale) so offline scans don't lose previously-known exclusions.
EXCLUDED_CVES_URL = 'https://raw.githubusercontent.com/espressif/esp-idf-sbom/master/excluded_cves.yaml'
EXCLUDED_CVES_CACHE_PATH = Path.home() / '.esp-idf-sbom' / 'excluded_cves.yaml'
EXCLUDED_CVES_TTL_SECONDS = 3600

# When True, get_excluded_cves() skips the upstream fetch and uses only the
# on-disk cache (returning an empty mapping if the cache does not exist). Set
# from the --no-sync-excluded-cves CLI flag for fully air-gapped runs.
EXCLUDED_CVES_NO_SYNC = False


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
                log.warn('Sleeping for 30 seconds...')
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


def get_excluded_cves(cache: Dict[str, Dict[str, Any]] = {}) -> Dict[str, Any]:
    """Retrieve the YAML file from the esp-idf-sbom repository, which includes a list of excluded CVEs.

    The file is a top-level mapping keyed by CVE ID. The value can be either:

    * a string -- the CVE is unrelated to any Espressif product. The string is
      the reason. Filtered at the NVD-query layer in :func:`check_cpe` and
      :func:`check_keyword`; never appears in scan output. See
      :func:`get_globally_excluded_cves`.

    * a mapping with ``cpes`` and ``reason`` -- the CVE does apply to an
      Espressif product but is considered handled (e.g. patched) for the CPEs
      in ``cpes``. The scan still reports the CVE for matching CPEs but marks
      it as EXCLUDED with the given reason. Each entry in ``cpes`` carries a
      ``cpe`` plus optional ``versionStartIncluding`` / ``versionStartExcluding``
      / ``versionEndIncluding`` / ``versionEndExcluding`` fields, mirroring
      NVD's own ``cpeMatch`` shape. See :func:`get_excluded_cves_for_cpe`.
    """

    if 'cves' in cache:
        # Read the excluded CVEs once per script run.
        return cache['cves']

    cache_path = EXCLUDED_CVES_CACHE_PATH
    cves: Dict[str, Any] = {}

    # 1) On-disk cache is fresh -- use it directly without hitting the network.
    if cache_path.is_file():
        age = time.time() - cache_path.stat().st_mtime
        if age < EXCLUDED_CVES_TTL_SECONDS:
            try:
                with open(cache_path) as f:
                    cves = yaml.safe_load(f) or {}
                cache['cves'] = cves
                return cves
            except (yaml.YAMLError, OSError) as e:
                log.warn(f'Cannot read cached excluded CVEs from {cache_path}: {e}')

    # 2) Cache stale or missing -- fetch from upstream and refresh the cache.
    #    Skipped entirely when sync is disabled (--no-sync-excluded-cves), so
    #    the code falls through to step 3 and uses whatever is on disk.
    fetched = False
    if not EXCLUDED_CVES_NO_SYNC:
        req = urllib.request.Request(EXCLUDED_CVES_URL)
        for retry in range(1, 4):
            try:
                with urllib.request.urlopen(req, timeout=30) as res:
                    data = res.read()
                cves = yaml.safe_load(data.decode()) or {}
                try:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_bytes(data)
                except OSError as e:
                    log.warn(f'Cannot write cached excluded CVEs to {cache_path}: {e}')
                fetched = True
                break

            except urllib.error.HTTPError as e:
                log.warn(f'Cannot download list of excluded CVEs: {e}. Retrying({retry}) ...')

            except yaml.YAMLError as e:
                log.warn(f'Cannot load list of excluded CVEs: {e}')
                fetched = True
                break
        else:
            log.warn('Failed to download list of excluded CVEs')

    # 3) Fetch failed or was skipped -- fall back to the on-disk cache even if
    #    it's stale. When sync is disabled the warning is suppressed since the
    #    user explicitly opted into using whatever is on disk.
    if not fetched and cache_path.is_file():
        try:
            with open(cache_path) as f:
                cves = yaml.safe_load(f) or {}
            if not EXCLUDED_CVES_NO_SYNC:
                log.warn(f'Using stale on-disk cache for excluded CVEs at {cache_path}')
        except (yaml.YAMLError, OSError) as e:
            log.warn(f'Cannot read cached excluded CVEs from {cache_path}: {e}')

    cache['cves'] = cves
    return cves


def get_excluded_cves_for_cpe(cpe: str) -> Dict[str, str]:
    """Return ``{cve_id: reason}`` for CPE-scoped exclusions matching ``cpe``.

    These are dict-valued entries in ``excluded_cves.yaml`` whose ``cpes`` list
    contains a match for the given CPE (OR semantics, NVD ``cpeMatch`` version
    range semantics). They represent CVEs that do apply to an Espressif product
    but have been patched in specific versions -- so the scan should mark them
    as EXCLUDED for the patched (and later) versions while still reporting them
    on affected versions.

    Globally-excluded (string-valued) entries are intentionally not returned
    here; they are filtered at the NVD-query level instead.
    """
    result: Dict[str, str] = {}
    cves = get_excluded_cves()
    if not isinstance(cves, dict):
        return result

    for cve_id, value in cves.items():
        if not isinstance(value, dict):
            continue
        for entry in value.get('cpes', []) or []:
            if not isinstance(entry, dict) or 'cpe' not in entry:
                continue
            # Wrap into an NVD-shaped configuration so we can reuse is_version_vulnerable.
            cpe_match: Dict[str, Any] = {'vulnerable': True, 'criteria': entry['cpe']}
            for key in ('versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding'):
                if key in entry:
                    cpe_match[key] = entry[key]
            synth_cfg = {'nodes': [{'cpeMatch': [cpe_match]}]}
            if is_version_vulnerable(cpe, synth_cfg):
                result[cve_id] = value.get('reason', '')
                break

    return result


def get_globally_excluded_cves() -> Dict[str, str]:
    """Return ``{cve_id: reason}`` for CVEs that are unrelated to any Espressif product.

    These are the entries in ``excluded_cves.yaml`` whose value is a plain
    string. They are filtered at the NVD-query layer in :func:`check_cpe` and
    :func:`check_keyword` and never propagate to the report, regardless of how
    NVD matched them. Used for cases such as a Linux kernel CVE that mentions
    ``zlib`` or ``fmt`` in its description and gets returned by keyword search,
    or a CVE that NVD has (incorrectly) attributed to an Espressif CPE.
    """
    result: Dict[str, str] = {}
    cves = get_excluded_cves()
    if not isinstance(cves, dict):
        return result
    for cve_id, value in cves.items():
        if isinstance(value, str):
            result[cve_id] = value
    return result


# https://nvd.nist.gov/developers/vulnerabilities
def check_cpe(cpe: str, localdb: bool = False) -> List[Dict[str, Any]]:
    """Check given CPE against NVD data."""

    globally_excluded = get_globally_excluded_cves()

    # Check vulnerabilities that have already been processed in the NVD and have an assigned CPE.
    if localdb:
        vulns = repo_check(cpe)
    else:
        cpe_quoted = urllib.parse.quote(cpe)
        cpe_vulns = nvd_request(f'cpeName={cpe_quoted}')

        # The NVD REST API returns every CVE that references this CPE name in any
        # configuration, regardless of the per-cpeMatch "vulnerable" flag or version
        # range. That includes CVEs where our CPE appears only as a runtime
        # requirement (vulnerable=false, the "Running on/with" entries in the NVD
        # UI), e.g. CVE-2021-32921 listing lua under an AND with Prosody. Filter
        # these out using is_version_vulnerable, which honors cpeMatch[vulnerable]
        # and the version-range keys carried inline in the response. The local-db
        # path applies equivalent filtering through repo_check.
        vulns = []
        for cve in cpe_vulns:
            for cfg in cve['cve'].get('configurations', []):
                if is_version_vulnerable(cpe, cfg):
                    vulns.append(cve)
                    break

    # Drop CVEs that are unrelated to any Espressif product. These are listed in
    # excluded_cves.yaml as plain string entries and must never appear in scan
    # output, regardless of how NVD attributed them.
    return [v for v in vulns if v['cve']['id'] not in globally_excluded]


def check_keyword(keyword: str, localdb: bool = False) -> List[Dict[str, Any]]:
    """Check given keyword against CVE description."""

    cpe_vulns: List[Dict[str, Any]] = []

    # CVEs unrelated to any Espressif product (e.g. a Linux kernel CVE that
    # happens to mention "zlib" or "fmt"). Filter these out so they never appear
    # in keyword-search output.
    globally_excluded = get_globally_excluded_cves()

    if localdb:
        keyword_vulns = repo_keyword(keyword)
    else:
        keyword = urllib.parse.quote(keyword)
        keyword_vulns = nvd_request(f'keywordSearch={keyword}&keywordExactMatch')

    for vuln in keyword_vulns:
        if vuln['cve']['vulnStatus'] in ['Received', 'Awaiting Analysis', 'Undergoing Analysis']:
            # CVE not analyzed in NVD yet; include unless it's globally excluded.
            if vuln['cve']['id'] in globally_excluded:
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
    if rv not in [0, 1]:
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
        return 0  # versions are equal


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

            if not any((versionStartExcluding, versionStartIncluding, versionEndExcluding, versionEndIncluding)):
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
        cmd = [
            'git',
            'clone',
            '--bare',
            '--depth',
            '1',
            '--single-branch',
            '--branch',
            'master',
            '--no-tags',
            NVD_MIRROR_URL,
            dst,
        ]
    else:
        log.eprint(f'Synchronizing NVD data from the remote repository {NVD_MIRROR_URL} to {dst}.')
        cmd = ['git', '-C', dst, 'fetch', '--depth', '1', '--force', '--no-tags', 'origin', 'master:master']

    rv, _, _ = utils.run(cmd, stdout=False, stderr=False)
    return rv
