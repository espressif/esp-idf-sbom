# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

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
    run([sys.executable, '-m', 'esp_idf_sbom', '-v', 'check', output_fn], check=True)


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


def test_cve_exclude_list(hello_world_build: Path) -> None:
    """Test that CVE-2020-27209 is reported for the main component, then add
    it to cve-exclude-list and test it's not reported."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx'

    content = f'''
              cpe: cpe:2.3:a:micro-ecc_project:micro-ecc:1.0:*:*:*:*:*:*:*
              '''

    manifest.write_text(dedent(content))
    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '-o', output_fn, proj_desc_path],
        check=True)
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'check', '--format', 'csv', output_fn],
            capture_output=True, text=True)

    assert re.search(r'YES.+CVE-2020-27209', p.stdout) is not None

    content = f'''
              cpe: cpe:2.3:a:micro-ecc_project:micro-ecc:1.0:*:*:*:*:*:*:*
              cve-exclude-list:
                - cve: CVE-2020-27209
                  reason: This is not vulnerable
              '''

    manifest.write_text(dedent(content))
    run([sys.executable, '-m', 'esp_idf_sbom', 'create', '-o', output_fn, proj_desc_path],
        check=True)
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'check', '--format', 'csv', output_fn],
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
