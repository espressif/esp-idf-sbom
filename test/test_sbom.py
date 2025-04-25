# SPDX-FileCopyrightText: 2023-2025 Espressif Systems (Shanghai) CO LTD
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
def hello_world_build(ctx: dict={'tmpdir': None}) -> Path:
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
    assert p.returncode in [0,1]


def test_sbom_project_manifest(hello_world_build: Path) -> None:
    manifest = hello_world_build / 'sbom.yml'
    content = '''
              name: MY-PROJECT-NAME
              version: 999.999.999
              description: testing hello_world application
              url: https://test.hello.world.org/hello_world-0.1.0.tar.gz
              cpe: cpe:2.3:a:hello_world:hello_world:{}:*:*:*:*:*:*:*
              supplier: 'Person: John Doe'
              '''
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'PackageVersion: 999.999.999' in p.stdout
    assert 'PackageSummary: <text>testing hello_world application</text>' in p.stdout
    assert 'PackageDownloadLocation: https://test.hello.world.org/hello_world-0.1.0.tar.gz' in p.stdout
    assert 'ExternalRef: SECURITY cpe23Type cpe:2.3:a:hello_world:hello_world:999.999.999:*:*:*:*:*:*:*' in p.stdout
    assert 'PackageSupplier: Person: John Doe' in p.stdout
    assert 'PackageName: MY-PROJECT-NAME' in p.stdout

    manifest.unlink()


def test_sbom_subpackages(hello_world_build: Path) -> None:
    """ Create two subpackages in main component and add sbom.yml
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

    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'TEST_SUBPACKAGE' in p.stdout
    assert 'TEST_SUBSUBPACKAGE' in p.stdout

    shutil.rmtree(subpackage_path)


def test_referenced_manifests(hello_world_build: Path) -> None:
    """ This is similar test as test_sbom_subpackages, but this time
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

    content = f'''
              manifests:
                - path: subpackage.yml
                  dest: subpackage
                - path: subsubpackage.yml
                  dest: subpackage/subsubpackage
              '''
    manifest.write_text(dedent(content))
    subpackage_manifest.write_text('description: TEST_SUBPACKAGE')
    subsubpackage_manifest.write_text('description: TEST_SUBSUBPACKAGE')

    subpackage_path = hello_world_build / 'main' / 'subpackage'
    (subpackage_path / 'subsubpackage').mkdir(parents=True)

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create',  proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'TEST_SUBPACKAGE' in p.stdout
    assert 'TEST_SUBSUBPACKAGE' in p.stdout

    shutil.rmtree(subpackage_path)
    manifest.unlink()
    subpackage_manifest.unlink()
    subsubpackage_manifest.unlink()


def test_embedded_manifests(hello_world_build: Path) -> None:
    """ This is similar test as test_referenced_manifests, but this time
    embedded manifests are used to create subpackages. Meaning the
    sbom.yml manifest is created for the main component only and it contains
    embedded manifests for subpackage and subsubpackage.
    main
    ├── sbom.yml
    └── subpackage
        └── subsubpackage
    """

    manifest = hello_world_build / 'main' / 'sbom.yml'

    content = f'''
              manifests:
                - manifest:
                    name: TEST_SUBPACKAGE
                  dest: subpackage
                - manifest:
                    name: TEST_SUBSUBPACKAGE
                  dest: subpackage/subsubpackage
              '''
    manifest.write_text(dedent(content))

    subpackage_path = hello_world_build / 'main' / 'subpackage'
    (subpackage_path / 'subsubpackage').mkdir(parents=True)

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create',  proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'TEST_SUBPACKAGE' in p.stdout
    assert 'TEST_SUBSUBPACKAGE' in p.stdout

    shutil.rmtree(subpackage_path)
    manifest.unlink()


def test_sbom_manifest_from_idf_component(hello_world_build: Path) -> None:
    """Test that sbom section/dict present in idf_component.yml is used if presented"""

    manifest = hello_world_build / 'main' / 'idf_component.yml'
    desc = 'FROM IDF_COMPONENT_YML SBOM NAMESPACE'
    content = f'''
              sbom:
                description: {desc}
              '''
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert f'PackageSummary: <text>{desc}</text>' in p.stdout

    manifest.unlink()


def test_cve_exclude_list() -> None:
    """Test that CVE-2020-27209 is reported for the manifest file, then add
    it to cve-exclude-list and test it's not reported."""
    tmpdir = TemporaryDirectory()
    manifest = Path(tmpdir.name) / 'sbom.yml'

    content = f'''
              cpe: cpe:2.3:a:micro-ecc_project:micro-ecc:1.0:*:*:*:*:*:*:*
              '''

    manifest.write_text(dedent(content))
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--format', 'csv', manifest],
            capture_output=True, text=True)

    assert re.search(r'YES.+CVE-2020-27209', p.stdout) is not None

    content = f'''
              cpe: cpe:2.3:a:micro-ecc_project:micro-ecc:1.0:*:*:*:*:*:*:*
              cve-exclude-list:
                - cve: CVE-2020-27209
                  reason: This is not vulnerable
              '''

    manifest.write_text(dedent(content))
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--format', 'csv', manifest],
            check=True, capture_output=True, text=True)

    assert re.search(r'EXCLUDED.+CVE-2020-27209', p.stdout) is not None

    manifest.unlink()


def test_validate_sbom(hello_world_build: Path) -> None:
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '--files', 'rem',
         '-o', output_fn, proj_desc_path],
        check=True)
    run(['pyspdxtools', '-i', output_fn], check=True)


def test_multiple_cpes(hello_world_build: Path) -> None:
    """Test that multiple CPE values can be specified in manifest file."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    content = f'''
              cpe:
                - cpe:2.3:a:VENDOR1:PRODUCT1:1.0:*:*:*:*:*:*:*
                - cpe:2.3:a:VENDOR2:PRODUCT2:1.0:*:*:*:*:*:*:*
              '''

    manifest.write_text(dedent(content))
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'PRODUCT1' in p.stdout
    assert 'PRODUCT2' in p.stdout

    manifest.unlink()


def test_copyright_notices_unification(hello_world_build: Path) -> None:
    """Test copyright notices unification in license command."""

    manifest = hello_world_build / 'main' / 'sbom.yml'
    content = f'''
              copyright:
                - 2001-2003 John Doe
                - 2005 John Doe
                - 2007-2010 John Doe
                - 2002-2003 John Doe
                - 2008-2015 John Doe
                - 2011 John Doe
              '''
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'license', '-u', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert f'2001-2003, 2005, 2007-2015 John Doe' in p.stdout

    manifest.unlink()


def test_sbom_spdx_id(hello_world_build: Path) -> None:
    """ Create subpackage directory with '+' character in its name.
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

    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '-o',
         output_fn, proj_desc_path], check=True)
    run(['pyspdxtools', '-i', output_fn], check=True)

    shutil.rmtree(subpackage_path)


def test_virtual_package(hello_world_build: Path) -> None:
    """Verify that a virtual package can be included in the manifest file."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    virtpackage = hello_world_build / 'main' / 'virtpackage.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    content = f'''
              virtpackages:
                - virtpackage.yml
              '''

    manifest.write_text(dedent(content))

    content = f'''
              name: TEST_VIRTUAL_PACKAGE
              '''

    virtpackage.write_text(dedent(content))

    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'TEST_VIRTUAL_PACKAGE' in p.stdout

    manifest.unlink()
    virtpackage.unlink()
    return


def test_manifest_expression(hello_world_build: Path) -> None:
    """Add a virtual package with several different "if" expressions and check whether it is included."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    virtpackage = hello_world_build / 'main' / 'virtpackage.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    content = f'''
              virtpackages:
                - virtpackage.yml
              '''

    manifest.write_text(dedent(content))

    # Should be included
    content = f'''
              name: EXPR_VIRTUAL_PACKAGE
              if: 'IDF_TARGET = "esp32" && !!!!IDF_TARGET_ESP32 && LOG_DEFAULT_LEVEL > 1'
              '''
    virtpackage.write_text(dedent(content))

    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'EXPR_VIRTUAL_PACKAGE' in p.stdout

    # Should be included
    content = f'''
              name: EXPR_VIRTUAL_PACKAGE
              if: 'IDF_TARGET_ESP32S3 || (IDF_TARGET = "esp32" && IDF_TARGET_ARCH_XTENSA = True)'
              '''
    virtpackage.write_text(dedent(content))

    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'EXPR_VIRTUAL_PACKAGE' in p.stdout

    # Should NOT be included
    content = f'''
              name: EXPR_VIRTUAL_PACKAGE
              if: 'IDF_TARGET_ESP32S3 || !IDF_TARGET_ARCH_XTENSA'
              '''
    virtpackage.write_text(dedent(content))

    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'EXPR_VIRTUAL_PACKAGE' not in p.stdout

    # Should be included because the --disable-conditions is used
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', '--disable-conditions', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'EXPR_VIRTUAL_PACKAGE' in p.stdout

    manifest.unlink()
    virtpackage.unlink()
    return


def test_subpackages_exclusion(hello_world_build: Path) -> None:
    """ Create a subpackage in the main component and add an sbom.yml file
    for it along with the FILEFILEFILE file. Verify that the FILEFILEFILE file from subpackage
    is not included in the sbom if the subpackage is excluded based on the "if" condition.
    main
    └── subpackage
        ├── sbom.yml
        └── FILEFILEFILE
    """
    subpackage_path = hello_world_build / 'main' / 'subpackage'
    subpackage_path.mkdir(parents=True)

    content = f'''
              name: SUBPACKAGE
              if: 'NONEXISTING'
              '''

    (subpackage_path / 'sbom.yml').write_text(dedent(content))
    (subpackage_path / 'FILEFILEFILE').touch()

    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    p = run([sys.executable, '-m', 'esp_idf_sbom', 'create', '--files=auto', proj_desc_path],
            check=True, capture_output=True, text=True)

    assert 'FILEFILEFILE' not in p.stdout

    shutil.rmtree(subpackage_path)


def test_local_db() -> None:
    """Scan an older version of FreeRTOS using the local NVD mirror and verify that the expected CVEs are reported."""
    tmpdir = TemporaryDirectory()
    manifest = Path(tmpdir.name) / 'sbom.yml'

    content = f'''
              cpe: cpe:2.3:o:amazon:freertos:10.0.0:*:*:*:*:*:*:*
              '''

    manifest.write_text(dedent(content))
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'check', '--local-db', '--format', 'csv', manifest],
            capture_output=True, text=True)

    assert re.search(r'YES.+CVE-2021-31571', p.stdout) is not None
    assert re.search(r'YES.+CVE-2021-31572', p.stdout) is not None
    assert re.search(r'YES.+CVE-2021-31572', p.stdout) is not None

    manifest.unlink()


def test_validate_report_json(hello_world_build: Path) -> None:
    """Generate SPDX SBOM, scan it for vulnerabilities, generate report in JSON format and validate it with JSON schema."""
    tmpdir = TemporaryDirectory()
    tmpdir_path = Path(tmpdir.name)
    sbom_path = tmpdir_path / 'sbom.spdx'
    report_path = tmpdir_path / 'report.json'
    schema_path = Path(__file__).resolve().parent.parent / 'report_schema.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '--output', sbom_path, proj_desc_path], check=True)

    run([sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db',
         '--format', 'json', '--output', report_path, sbom_path], check=True)

    with open(report_path, 'r') as report_file, open(schema_path, 'r') as schema_file:
        json_data = json.load(report_file)
        schema_data = json.load(schema_file)

        validate(instance=json_data, schema=schema_data)
