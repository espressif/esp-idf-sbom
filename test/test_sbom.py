# SPDX-FileCopyrightText: 2023-2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import shutil
import sys
from distutils.dir_util import copy_tree
from pathlib import Path
from subprocess import run
from tempfile import TemporaryDirectory
from textwrap import dedent

import pytest
from jsonschema import validate

IDF_PY_PATH = Path(os.environ['IDF_PATH']) / 'tools' / 'idf.py'


@pytest.fixture
def hello_world_build(ctx: dict = {'tmpdir': None}) -> Path:
    # build hello_world app in temporary directory and return its path
    if ctx['tmpdir']:
        return Path(ctx['tmpdir'].name)

    tmpdir = TemporaryDirectory()
    hello_world_path = Path(os.environ['IDF_PATH']) / 'examples' / 'get-started' / 'hello_world'
    copy_tree(str(hello_world_path), tmpdir.name, verbose=0)
    run([sys.executable, IDF_PY_PATH, 'fullclean'], cwd=tmpdir.name, check=True)
    run([sys.executable, IDF_PY_PATH, 'build'], cwd=tmpdir.name, check=True)
    ctx['tmpdir'] = tmpdir
    return Path(tmpdir.name)


def test_generate_sbom(hello_world_build: Path) -> None:
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True)


def test_check_sbom(hello_world_build: Path) -> None:
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '-o', output_fn, proj_desc_path], check=True)
    # Avoid using check=True, because if a vulnerability is found, esp-idf-sbom will return 1.
    # A return value of 128 indicates a fatal error.
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'check', output_fn])
    assert p.returncode in [0, 1]


def test_sbom_project_manifest(hello_world_build: Path) -> None:
    manifest = hello_world_build / 'sbom.yml'
    content = """
              name: MY-PROJECT-NAME
              version: 999.999.999
              description: testing hello_world application
              url: https://test.hello.world.org/hello_world-0.1.0.tar.gz
              cpe: cpe:2.3:a:hello_world:hello_world:{}:*:*:*:*:*:*:*
              supplier: 'Person: John Doe'
              """
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'PackageVersion: 999.999.999' in p.stdout
    assert 'PackageSummary: <text>testing hello_world application</text>' in p.stdout
    assert 'PackageDownloadLocation: https://test.hello.world.org/hello_world-0.1.0.tar.gz' in p.stdout
    assert 'ExternalRef: SECURITY cpe23Type cpe:2.3:a:hello_world:hello_world:999.999.999:*:*:*:*:*:*:*' in p.stdout
    assert 'PackageSupplier: Person: John Doe' in p.stdout
    assert 'PackageName: MY-PROJECT-NAME' in p.stdout

    manifest.unlink()


def test_sbom_subpackages(hello_world_build: Path) -> None:
    """Create two subpackages in main component and add sbom.yml
    into them. Check that the subpackages are presented in the
    generated sbom.
    main
    └── subpackage
        ├── sbom.yml
        └── subsubpackage
            └── sbom.yml
    """
    subpackage_path = hello_world_build / 'main' / 'subpackage'
    subpackage_path.mkdir(parents=True)
    (subpackage_path / 'sbom.yml').write_text('description: TEST_SUBPACKAGE')

    subsubpackage_path = subpackage_path / 'subsubpackage'
    subsubpackage_path.mkdir(parents=True)
    (subsubpackage_path / 'sbom.yml').write_text('description: TEST_SUBSUBPACKAGE')

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'TEST_SUBPACKAGE' in p.stdout
    assert 'TEST_SUBSUBPACKAGE' in p.stdout

    shutil.rmtree(subpackage_path)


def test_referenced_manifests(hello_world_build: Path) -> None:
    """This is similar test as test_sbom_subpackages, but this time
    referenced manifests are used to create subpackages. Meaning the
    sbom.yml manifests are created directly in main component directory
    and referenced from main sbom.yml.
    main
    ├── sbom.yml
    ├── subpackage.yml
    ├── subsubpackage.yml
    └── subpackage           # manifest subpackage.yml defined in main directory
        └── subsubpackage    # manifest subsubpackage.yml defined in main directory
    """

    manifest = hello_world_build / 'main' / 'sbom.yml'
    subpackage_manifest = hello_world_build / 'main' / 'subpackage.yml'
    subsubpackage_manifest = hello_world_build / 'main' / 'subsubpackage.yml'

    content = """
              manifests:
                - path: subpackage.yml
                  dest: subpackage
                - path: subsubpackage.yml
                  dest: subpackage/subsubpackage
              """
    manifest.write_text(dedent(content))
    subpackage_manifest.write_text('description: TEST_SUBPACKAGE')
    subsubpackage_manifest.write_text('description: TEST_SUBSUBPACKAGE')

    subpackage_path = hello_world_build / 'main' / 'subpackage'
    (subpackage_path / 'subsubpackage').mkdir(parents=True)

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'TEST_SUBPACKAGE' in p.stdout
    assert 'TEST_SUBSUBPACKAGE' in p.stdout

    shutil.rmtree(subpackage_path)
    manifest.unlink()
    subpackage_manifest.unlink()
    subsubpackage_manifest.unlink()


def test_embedded_manifests(hello_world_build: Path) -> None:
    """This is similar test as test_referenced_manifests, but this time
    embedded manifests are used to create subpackages. Meaning the
    sbom.yml manifest is created for the main component only and it contains
    embedded manifests for subpackage and subsubpackage.
    main
    ├── sbom.yml
    └── subpackage
        └── subsubpackage
    """

    manifest = hello_world_build / 'main' / 'sbom.yml'

    content = """
              manifests:
                - manifest:
                    name: TEST_SUBPACKAGE
                  dest: subpackage
                - manifest:
                    name: TEST_SUBSUBPACKAGE
                  dest: subpackage/subsubpackage
              """
    manifest.write_text(dedent(content))

    subpackage_path = hello_world_build / 'main' / 'subpackage'
    (subpackage_path / 'subsubpackage').mkdir(parents=True)

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'TEST_SUBPACKAGE' in p.stdout
    assert 'TEST_SUBSUBPACKAGE' in p.stdout

    shutil.rmtree(subpackage_path)
    manifest.unlink()


def test_sbom_manifest_from_idf_component(hello_world_build: Path) -> None:
    """Test that sbom section/dict present in idf_component.yml is used if presented"""

    manifest = hello_world_build / 'main' / 'idf_component.yml'
    desc = 'FROM IDF_COMPONENT_YML SBOM NAMESPACE'
    content = f"""
              sbom:
                description: {desc}
              """
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert f'PackageSummary: <text>{desc}</text>' in p.stdout

    manifest.unlink()


def test_cve_exclude_list() -> None:
    """Test that CVE-2020-27209 is reported for the manifest file, then add
    it to cve-exclude-list and test it's not reported."""
    tmpdir = TemporaryDirectory()
    manifest = Path(tmpdir.name) / 'sbom.yml'

    content = """
              cpe: cpe:2.3:a:micro-ecc_project:micro-ecc:1.0:*:*:*:*:*:*:*
              """

    manifest.write_text(dedent(content))
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--format', 'csv', manifest],
        capture_output=True,
        text=True,
    )

    assert re.search(r'YES.+CVE-2020-27209', p.stdout) is not None

    content = """
              cpe: cpe:2.3:a:micro-ecc_project:micro-ecc:1.0:*:*:*:*:*:*:*
              cve-exclude-list:
                - cve: CVE-2020-27209
                  reason: This is not vulnerable
              """

    manifest.write_text(dedent(content))
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--format', 'csv', manifest],
        check=True,
        capture_output=True,
        text=True,
    )

    assert re.search(r'EXCLUDED.+CVE-2020-27209', p.stdout) is not None

    manifest.unlink()


def test_global_cve_exclude_list_in_sbom(hello_world_build: Path) -> None:
    """Test that CPE-scoped entries from the global excluded_cves.yaml are
    merged into the generated SBOM's per-package cve-exclude-list comment."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    # Pin a custom CPE on the main package so the test does not depend on
    # the IDF version's esp-idf CPE.
    manifest.write_text(
        dedent("""
              cpe: cpe:2.3:a:VENDOR1:PRODUCT1:1.0:*:*:*:*:*:*:*
              """)
    )

    with TemporaryDirectory() as tmpdir:
        excluded_path = Path(tmpdir) / 'excluded_cves.yaml'
        excluded_path.write_text(
            dedent("""
                  CVE-9999-99999:
                    cpes:
                      - cpe: cpe:2.3:a:VENDOR1:PRODUCT1:1.0:*:*:*:*:*:*:*
                    reason: integration test reason
                  """)
        )

        env = {**os.environ, 'SBOM_EXCLUDED_CVES_FILE': str(excluded_path)}
        p = run(
            [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

    assert 'CVE-9999-99999' in p.stdout
    assert 'integration test reason' in p.stdout

    manifest.unlink()


def test_validate_sbom(hello_world_build: Path) -> None:
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '--files', 'rem', '-o', output_fn, proj_desc_path], check=True)
    run(['pyspdxtools', '-i', output_fn], check=True)


def test_multiple_cpes(hello_world_build: Path) -> None:
    """Test that multiple CPE values can be specified in manifest file."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    content = """
              cpe:
                - cpe:2.3:a:VENDOR1:PRODUCT1:1.0:*:*:*:*:*:*:*
                - cpe:2.3:a:VENDOR2:PRODUCT2:1.0:*:*:*:*:*:*:*
              """

    manifest.write_text(dedent(content))
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'PRODUCT1' in p.stdout
    assert 'PRODUCT2' in p.stdout

    manifest.unlink()


def test_copyright_notices_unification(hello_world_build: Path) -> None:
    """Test copyright notices unification in license command."""

    manifest = hello_world_build / 'main' / 'sbom.yml'
    content = """
              copyright:
                - 2001-2003 John Doe
                - 2005 John Doe
                - 2007-2010 John Doe
                - 2002-2003 John Doe
                - 2008-2015 John Doe
                - 2011 John Doe
              """
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'license', '-u', proj_desc_path],
        check=True,
        capture_output=True,
        text=True,
    )

    assert '2001-2003, 2005, 2007-2015 John Doe' in p.stdout

    manifest.unlink()


def test_sbom_spdx_id(hello_world_build: Path) -> None:
    """Create subpackage directory with '+' character in its name.
    It should be replaced, because '+' is not allowed in SPDXID
    identifier. Validate the generated sbom.spd to make sure
    the SPDX identifier is sanitized.
    main
    └── sub+package
        └── sbom.yml
    """
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx'

    subpackage_path = hello_world_build / 'main' / 'sub+package'
    subpackage_path.mkdir(parents=True)
    (subpackage_path / 'sbom.yml').write_text('name: spdxid test')

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '-o', output_fn, proj_desc_path], check=True)
    run(['pyspdxtools', '-i', output_fn], check=True)

    shutil.rmtree(subpackage_path)


def test_virtual_package(hello_world_build: Path) -> None:
    """Verify that a virtual package can be included in the manifest file."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    virtpackage = hello_world_build / 'main' / 'virtpackage.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    content = """
              virtpackages:
                - virtpackage.yml
              """

    manifest.write_text(dedent(content))

    content = """
              name: TEST_VIRTUAL_PACKAGE
              """

    virtpackage.write_text(dedent(content))

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'TEST_VIRTUAL_PACKAGE' in p.stdout

    manifest.unlink()
    virtpackage.unlink()
    return


def test_manifest_expression(hello_world_build: Path) -> None:
    """Add a virtual package with several different "if" expressions and check whether it is included."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    virtpackage = hello_world_build / 'main' / 'virtpackage.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    content = """
              virtpackages:
                - virtpackage.yml
              """

    manifest.write_text(dedent(content))

    # Should be included
    content = """
              name: EXPR_VIRTUAL_PACKAGE
              if: 'IDF_TARGET = "esp32" && !!!!IDF_TARGET_ESP32 && LOG_DEFAULT_LEVEL > 1'
              """
    virtpackage.write_text(dedent(content))

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'EXPR_VIRTUAL_PACKAGE' in p.stdout

    # Should be included
    content = """
              name: EXPR_VIRTUAL_PACKAGE
              if: 'IDF_TARGET_ESP32S3 || (IDF_TARGET = "esp32" && IDF_TARGET_ARCH_XTENSA = True)'
              """
    virtpackage.write_text(dedent(content))

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'EXPR_VIRTUAL_PACKAGE' in p.stdout

    # Should NOT be included
    content = """
              name: EXPR_VIRTUAL_PACKAGE
              if: 'IDF_TARGET_ESP32S3 || !IDF_TARGET_ARCH_XTENSA'
              """
    virtpackage.write_text(dedent(content))

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path], check=True, capture_output=True, text=True
    )

    assert 'EXPR_VIRTUAL_PACKAGE' not in p.stdout

    # Should be included because the --disable-conditions is used
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--disable-conditions', proj_desc_path],
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'EXPR_VIRTUAL_PACKAGE' in p.stdout

    manifest.unlink()
    virtpackage.unlink()
    return


def test_subpackages_exclusion(hello_world_build: Path) -> None:
    """Create a subpackage in the main component and add an sbom.yml file
    for it along with the FILEFILEFILE file. Verify that the FILEFILEFILE file from subpackage
    is not included in the sbom if the subpackage is excluded based on the "if" condition.
    main
    └── subpackage
        ├── sbom.yml
        └── FILEFILEFILE
    """
    subpackage_path = hello_world_build / 'main' / 'subpackage'
    subpackage_path.mkdir(parents=True)

    content = """
              name: SUBPACKAGE
              if: 'NONEXISTING'
              """

    (subpackage_path / 'sbom.yml').write_text(dedent(content))
    (subpackage_path / 'FILEFILEFILE').touch()

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--files=auto', proj_desc_path],
        check=True,
        capture_output=True,
        text=True,
    )

    assert 'FILEFILEFILE' not in p.stdout

    shutil.rmtree(subpackage_path)


def test_local_db() -> None:
    """Scan an older version of FreeRTOS using the local NVD mirror and verify that the expected CVEs are reported."""
    tmpdir = TemporaryDirectory()
    manifest = Path(tmpdir.name) / 'sbom.yml'

    content = """
              cpe: cpe:2.3:o:amazon:freertos:10.0.0:*:*:*:*:*:*:*
              """

    manifest.write_text(dedent(content))
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--local-db', '--format', 'csv', manifest],
        capture_output=True,
        text=True,
    )

    assert re.search(r'YES.+CVE-2021-31571', p.stdout) is not None
    assert re.search(r'YES.+CVE-2021-31572', p.stdout) is not None
    assert re.search(r'YES.+CVE-2021-31572', p.stdout) is not None

    manifest.unlink()


def test_validate_report_json(hello_world_build: Path) -> None:
    """Generate SPDX SBOM, scan it for vulnerabilities, generate report in JSON format
    and validate it with JSON schema."""
    tmpdir = TemporaryDirectory()
    tmpdir_path = Path(tmpdir.name)
    sbom_path = tmpdir_path / 'sbom.spdx'
    report_path = tmpdir_path / 'report.json'
    schema_path = Path(__file__).resolve().parent.parent / 'report_schema.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '--output', sbom_path, proj_desc_path], check=True)

    # Avoid using check=True, because if a vulnerability is found, esp-idf-sbom will return 1.
    # A return value of 128 indicates a fatal error.
    p = run(
        [
            sys.executable,
            '-m',
            'esp_idf_sbom',
            'check',
            '--local-db',
            '--format',
            'json',
            '--output',
            report_path,
            sbom_path,
        ],
    )
    assert p.returncode in [0, 1]

    with open(report_path) as report_file, open(schema_path) as schema_file:
        json_data = json.load(report_file)
        schema_data = json.load(schema_file)

        validate(instance=json_data, schema=schema_data)


def test_none_severity_handling() -> None:
    """Test that CVEs with 'NONE' severity are handled correctly without KeyError."""
    import io
    from argparse import Namespace

    from esp_idf_sbom.libsbom import log
    from esp_idf_sbom.libsbom import report

    # Create test records with different severity levels including NONE
    test_records = [
        {
            'vulnerable': 'YES',
            'pkg_name': 'test_package_1',
            'pkg_version': '1.0.0',
            'cve_id': 'CVE-2023-00001',
            'cvss_base_score': '0.0',
            'cvss_base_severity': 'NONE',
            'cvss_version': '3.1',
            'cvss_vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
            'cpe': 'cpe:2.3:a:test:test_package_1:1.0.0:*:*:*:*:*:*:*',
            'keyword': '',
            'cve_link': 'https://nvd.nist.gov/vuln/detail/CVE-2023-00001',
            'cve_desc': 'Test CVE with NONE severity',
            'exclude_reason': '',
            'status': '',
        },
        {
            'vulnerable': 'YES',
            'pkg_name': 'test_package_2',
            'pkg_version': '2.0.0',
            'cve_id': 'CVE-2023-00002',
            'cvss_base_score': '7.5',
            'cvss_base_severity': 'HIGH',
            'cvss_version': '3.1',
            'cvss_vector_string': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
            'cpe': 'cpe:2.3:a:test:test_package_2:2.0.0:*:*:*:*:*:*:*',
            'keyword': '',
            'cve_link': 'https://nvd.nist.gov/vuln/detail/CVE-2023-00002',
            'cve_desc': 'Test CVE with HIGH severity',
            'exclude_reason': '',
            'status': '',
        },
        {
            'vulnerable': 'NO',
            'pkg_name': 'test_package_3',
            'pkg_version': '3.0.0',
            'cve_id': '',
            'cvss_base_score': '',
            'cvss_base_severity': '',
            'cvss_version': '',
            'cvss_vector_string': '',
            'cpe': 'cpe:2.3:a:test:test_package_3:3.0.0:*:*:*:*:*:*:*',
            'keyword': '',
            'cve_link': '',
            'cve_desc': '',
            'exclude_reason': '',
            'status': '',
        },
    ]

    # Capture the JSON output
    stdout = io.StringIO()
    log.set_console(stdout)

    # Create test args for JSON output
    args = Namespace(format='json', local_db=False)

    try:
        report.show(test_records, args, 'test_project', '1.0.0')
        output = stdout.getvalue()
    except KeyError as e:
        pytest.fail(f'KeyError raised when handling NONE severity: {e}')

    # Parse and validate the JSON output
    result = json.loads(output)

    # Verify 'none' severity data is present and correct
    assert 'none' in result['cves_summary'], "'none' key missing from cves_summary"
    assert result['cves_summary']['none']['count'] == 1, (
        f'Expected 1 NONE CVE, got {result["cves_summary"]["none"]["count"]}'
    )
    assert 'CVE-2023-00001' in result['cves_summary']['none']['cves'], (
        "CVE-2023-00001 not found in 'none' severity CVEs"
    )
    assert 'test_package_1' in result['cves_summary']['none']['packages'], (
        "test_package_1 not found in 'none' severity packages"
    )

    # Verify HIGH severity CVE is also correctly processed
    assert result['cves_summary']['high']['count'] == 1, (
        f'Expected 1 HIGH CVE, got {result["cves_summary"]["high"]["count"]}'
    )
    assert 'CVE-2023-00002' in result['cves_summary']['high']['cves'], (
        "CVE-2023-00002 not found in 'high' severity CVEs"
    )


def test_aliased_requirements(hello_world_build: Path) -> None:
    """Test that aliased requirement names (e.g. idf::spi_flash) in
    build_component_info are resolved correctly and don't cause KeyError.
    See https://github.com/espressif/esp-idf-sbom/issues/17"""
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    with open(proj_desc_path) as f:
        proj_desc = json.load(f)

    # Replace plain requirement names with their aliased form
    main_info = proj_desc['build_component_info']['main']
    main_info['priv_reqs'] = [
        proj_desc['build_component_info'][r]['alias'] if r in proj_desc['build_component_info'] else r
        for r in main_info['priv_reqs']
    ]

    modified_proj_desc_path = hello_world_build / 'build' / 'project_description_aliased.json'
    with open(modified_proj_desc_path, 'w') as f:
        json.dump(proj_desc, f)

    run([sys.executable, '-m', 'esp_idf_sbom', 'create', modified_proj_desc_path], check=True)

    modified_proj_desc_path.unlink()


def test_symlinked_component(hello_world_build: Path, tmp_path: Path) -> None:
    """Regression test for https://github.com/espressif/esp-idf-sbom/issues/19.

    A component whose directory is a symlink (or a Windows directory junction)
    into a separate git repo used to crash `esp-idf-sbom create`: `git
    rev-parse --show-toplevel` returns the resolved upstream path while
    project_description.json records the symlink, and `utils.prelpath`
    couldn't bridge that asymmetry.

    Copy hello_world's `main` component into a separate git repo, swap the
    original `main` directory for a symlink into it, and verify sbom create
    succeeds and emits the upstream remote with the `#main` path fragment.
    """
    upstream = tmp_path / 'upstream'
    shutil.copytree(hello_world_build / 'main', upstream / 'main')
    run(['git', 'init', '-q'], cwd=upstream, check=True)
    run(['git', 'add', '.'], cwd=upstream, check=True)
    run(
        ['git', '-c', 'user.email=test@example.com', '-c', 'user.name=test', 'commit', '-q', '-m', 'init'],
        cwd=upstream,
        check=True,
    )
    run(['git', 'remote', 'add', 'origin', 'https://example.com/fake/main.git'], cwd=upstream, check=True)

    main = hello_world_build / 'main'
    backup = hello_world_build / 'main_backup'
    main.rename(backup)
    try:
        main.symlink_to(upstream / 'main')
        proj_desc_path = hello_world_build / 'build' / 'project_description.json'
        p = run(
            [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True,
            capture_output=True,
            text=True,
        )
        assert re.search(
            r'ExternalRef: OTHER repository https://example\.com/fake/main\.git@[0-9a-f]+#main',
            p.stdout,
        )
    finally:
        if main.is_symlink():
            main.unlink()
        if backup.exists():
            backup.rename(main)


def test_purl_end_to_end(hello_world_build: Path) -> None:
    """End-to-end coverage of the PURL feature in a single SBOM run:

    * explicit purl in main/sbom.yml with the {} version placeholder
      substituted from the manifest's version
    * a subpackage with only a url: gets no auto-derived PURL (would
      otherwise falsely inherit the parent component's coordinates)
    * a subpackage with an explicit purl: still emits it -- suppression
      is on the guess only, not on the explicit opt-in
    * the toolchain auto-derives a github PURL from tools.json info_url
    * the toolchain emits the tarball SHA256 from tools.json as
      PackageChecksum, pinning the exact toolchain binary used for the
      build even without --files add
    """
    main_manifest = hello_world_build / 'main' / 'sbom.yml'
    auto_purl_dir = hello_world_build / 'main' / 'subpackage_auto_purl'
    with_purl_dir = hello_world_build / 'main' / 'subpackage_with_purl'

    main_manifest.write_text(
        dedent(
            """
            name: 'main-test'
            version: '9.9.9'
            purl: 'pkg:generic/main-test@{}'
            """
        )
    )
    auto_purl_dir.mkdir(parents=True)
    (auto_purl_dir / 'sbom.yml').write_text(
        dedent(
            """
            name: 'SUB-AUTO-PURL'
            version: '1.0'
            url: 'https://github.com/example/sub-auto-purl'
            """
        )
    )
    with_purl_dir.mkdir(parents=True)
    (with_purl_dir / 'sbom.yml').write_text(
        dedent(
            """
            name: 'SUB-WITH-PURL'
            version: '2.2'
            purl: 'pkg:generic/sub-with-purl@{}'
            """
        )
    )
    try:
        proj_desc_path = hello_world_build / 'build' / 'project_description.json'
        p = run(
            [sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True,
            capture_output=True,
            text=True,
        )

        # Explicit purl on main with {} substituted from version.
        assert 'ExternalRef: PACKAGE-MANAGER purl pkg:generic/main-test@9.9.9' in p.stdout

        # Subpackage with only a url: auto-derives a PURL from it. The
        # repository-fallback's #fragment check is what stops subpackages
        # inside a parent repo from emitting misleading parent PURLs, so
        # no subpackage-specific suppression is needed.
        assert 'SUB-AUTO-PURL' in p.stdout
        assert 'ExternalRef: PACKAGE-MANAGER purl pkg:github/example/sub-auto-purl@1.0' in p.stdout

        # Subpackage with explicit purl: emitted with {} substituted.
        assert 'ExternalRef: PACKAGE-MANAGER purl pkg:generic/sub-with-purl@2.2' in p.stdout

        # Toolchain auto-derives a github PURL from tools.json info_url.
        assert re.search(
            r'ExternalRef: PACKAGE-MANAGER purl pkg:github/espressif/crosstool-NG@\S+',
            p.stdout,
        )

        # In-tree wrapper components (components/* inside esp-idf, the
        # project directory itself) must not auto-derive a PURL that
        # points at the superproject -- identical pkg:github/espressif/
        # esp-idf@<ver> lines on dozens of packages would just be noise
        # over the per-package OTHER repository ExternalRef.
        assert 'PACKAGE-MANAGER purl pkg:github/espressif/esp-idf@' not in p.stdout

        # Toolchain emits the tarball SHA256 from tools.json. Match only
        # within the toolchain package block to avoid matching checksums
        # other packages might carry under --files add.
        toolchain_block = re.search(
            r'PackageName: toolchain-\S+.*?(?=\n#|\Z)',
            p.stdout,
            re.DOTALL,
        )
        assert toolchain_block is not None
        assert re.search(r'PackageChecksum: SHA256: [0-9a-f]{64}', toolchain_block.group(0))
    finally:
        main_manifest.unlink()
        shutil.rmtree(auto_purl_dir)
        shutil.rmtree(with_purl_dir)


def test_derive_purl() -> None:
    """derive_purl handles the URL shapes seen across esp-idf and
    idf-extra-components manifests: plain github URLs at the repository
    root with optional trailing slash or .git suffix, and gitlab.com URLs.

    Coverage of regex edge cases that an end-to-end test cannot
    sensibly exercise without one SBOM build per URL shape."""
    from esp_idf_sbom.libsbom.utils import derive_purl

    assert derive_purl('https://github.com/madler/zlib', '1.3.2') == 'pkg:github/madler/zlib@1.3.2'
    assert derive_purl('https://github.com/argtable/argtable3/', '3.2.2') == 'pkg:github/argtable/argtable3@3.2.2'
    assert derive_purl('https://github.com/espressif/mbedtls.git', '4.1.0') == 'pkg:github/espressif/mbedtls@4.1.0'
    assert derive_purl('https://gitlab.com/owner/repo', '2.0') == 'pkg:gitlab/owner/repo@2.0'

    # Subdirectory URLs identify a package within a parent repo, not the
    # whole repo. A derived PURL would point at the parent at a version
    # that may not exist there (e.g. the IDF Component Registry's
    # "<ver>~<rev>" revision form is not a github tag). Skip and let the
    # maintainer set an explicit purl: in the manifest.
    assert derive_purl('https://github.com/espressif/idf-extra-components/tree/master/esp_cli', '1.0') == ''

    # Non-github/gitlab URLs and missing inputs return empty so the caller
    # can skip PURL emission rather than producing something misleading.
    assert derive_purl('https://www.lua.org/', '5.4') == ''
    assert derive_purl('https://github.com/foo/bar', '') == ''
    assert derive_purl('', '1.0') == ''
