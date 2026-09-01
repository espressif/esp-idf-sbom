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
    # Build for esp32 explicitly: set-target clears the build dir and regenerates
    # sdkconfig, so the target does not depend on whatever the source tree carries
    # (e.g. a manual set-target). Tests like test_manifest_expression assert on it.
    run([sys.executable, IDF_PY_PATH, 'set-target', 'esp32'], cwd=tmpdir.name, check=True)
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


def test_rem_subpackages_keeps_submodules(hello_world_build: Path) -> None:
    """--rem-subpackages must drop only subpackages, not submodules. They are
    independent: submodules come from git, subpackages from sbom.yml."""
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--rem-subpackages', proj_desc_path],
        check=True,
        capture_output=True,
        text=True,
    )
    # submodules are still reported as their own packages ...
    assert 'SPDXRef-SUBMODULE-' in p.stdout
    # ... while subpackages are removed.
    assert 'SPDXRef-SUBPACKAGE-' not in p.stdout


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


def test_idf_component_sbom_version_placeholder() -> None:
    """The component version at the idf_component.yml root is injected into
    the sbom section by fix(), since the sbom section itself usually carries
    no version key. This makes the {} placeholder in cpe/purl values expand
    from the root version and the version available for reports. Covers both
    the manifest commands path (mft.get_manifests) and the SBOM create path
    (mft.fix with the root version)."""
    from esp_idf_sbom.libsbom import mft

    tmpdir = TemporaryDirectory()
    manifest = Path(tmpdir.name) / 'idf_component.yml'
    content = """
              version: "2.4.1"
              sbom:
                cpe: cpe:2.3:a:espressif:led_strip:{}:*:*:*:*:*:*:*
                purl: pkg:generic/espressif/led_strip@{}
                supplier: 'Organization: Espressif Systems (Shanghai) CO LTD'
                cve-exclude-list:
                  - cve: CVE-2023-1234
                    reason: Description why this package is not vulnerable
              """
    manifest.write_text(dedent(content))

    # get_manifests extracts the sbom section, converts cpe into a list and
    # expands the {} placeholder from the root version; validate must accept
    # the result.
    manifests = mft.get_manifests([str(manifest)])
    assert len(manifests) == 1
    m = manifests[0]
    mft.validate(m, m['_src'], m['_dst'], die=False)
    assert m['version'] == '2.4.1'
    assert m['cpe'] == ['cpe:2.3:a:espressif:led_strip:2.4.1:*:*:*:*:*:*:*']
    assert m['purl'] == 'pkg:generic/espressif/led_strip@2.4.1'

    # SBOM create path: fix() applied to the extracted sbom section with the
    # root version.
    yml = mft.load(str(manifest))
    sub = yml.get('sbom', dict())
    mft.fix(sub, yml.get('version', ''))
    assert sub['version'] == '2.4.1'
    assert sub['cpe'] == ['cpe:2.3:a:espressif:led_strip:2.4.1:*:*:*:*:*:*:*']

    # A version key inside the sbom section takes precedence over the root one.
    sub = {'version': '9.9.9', 'cpe': 'cpe:2.3:a:espressif:led_strip:{}:*:*:*:*:*:*:*'}
    mft.fix(sub, '2.4.1')
    assert sub['version'] == '9.9.9'
    assert sub['cpe'] == ['cpe:2.3:a:espressif:led_strip:9.9.9:*:*:*:*:*:*:*']

    # An empty manifest is kept empty, so idf_component.yml without the sbom
    # section is still skipped by get_manifests.
    manifest.write_text('version: "2.4.1"\n')
    assert mft.get_manifests([str(manifest)]) == []

    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'manifest', 'validate', str(manifest)],
        capture_output=True,
        text=True,
    )
    assert p.returncode == 0, p.stderr

    manifest.unlink()


def test_find_orphan_manifests(tmp_path: Path) -> None:
    """find_orphan_manifests returns all sbom_<name>.yml files (each becomes a
    virtual package) and does not treat a plain sbom.yml as an orphan."""
    from esp_idf_sbom.libsbom.sbom import SBOMObject

    obj = SBOMObject({}, {})

    # none present
    assert obj.find_orphan_manifests(str(tmp_path)) == []

    # one orphan -> returned
    foo = tmp_path / 'sbom_foo.yml'
    foo.write_text('name: FOO\n')
    assert obj.find_orphan_manifests(str(tmp_path)) == [str(foo)]

    # a plain sbom.yml is handled by the normal path, not as an orphan
    (tmp_path / 'sbom.yml').write_text('name: BAR\n')
    assert obj.find_orphan_manifests(str(tmp_path)) == [str(foo)]

    # more than one orphan -> all returned, sorted
    bar = tmp_path / 'sbom_bar.yml'
    bar.write_text('name: BAR\n')
    assert obj.find_orphan_manifests(str(tmp_path)) == sorted([str(foo), str(bar)])


def test_get_manifest_adopts_orphans_as_virtpackages(tmp_path: Path) -> None:
    """A managed component (.component_hash present) whose idf_component.yml lost
    its "sbom" section on upload still ships the referenced sbom_<name>.yml
    file(s). get_manifest registers each as a virtual package and leaves the
    component's own identity untouched (no squashing)."""
    from esp_idf_sbom.libsbom.sbom import SBOMObject

    comp = tmp_path / 'espressif__orphanlib'
    comp.mkdir()
    # published idf_component.yml: the sbom section was stripped on upload
    (comp / 'idf_component.yml').write_text('version: "1.2.3"\ndescription: managed component\n')
    # marker written by the component manager when a managed component is installed
    (comp / '.component_hash').write_text('deadbeef')
    # two orphaned, previously-referenced manifests still shipped in the package
    (comp / 'sbom_orphanlib.yml').write_text('name: orphanlib\ncpe: cpe:2.3:a:orphanlib:orphanlib:1.0:*:*:*:*:*:*:*\n')
    (comp / 'sbom_otherlib.yml').write_text('name: otherlib\ncpe: cpe:2.3:a:otherlib:otherlib:2.0:*:*:*:*:*:*:*\n')

    manifest = SBOMObject({}, {}).get_manifest(str(comp))

    # each orphan is registered as a virtual package, not squashed onto the component
    assert manifest['virtpackages'] == ['sbom_orphanlib.yml', 'sbom_otherlib.yml']
    # the component keeps its own identity and gains no CPE of its own
    assert manifest['version'] == '1.2.3'
    assert manifest['description'] == 'managed component'
    assert manifest['cpe'] == []
    # the shared EMPTY_MANIFEST list must not have been mutated in place
    assert SBOMObject.EMPTY_MANIFEST['virtpackages'] == []


def test_get_manifest_ignores_orphan_without_component_hash(tmp_path: Path) -> None:
    """Without a .component_hash (a source checkout, not a managed component), an
    orphaned sbom_<name>.yml is NOT adopted; wiring stays the component's job."""
    from esp_idf_sbom.libsbom.sbom import SBOMObject

    comp = tmp_path / 'orphanlib'
    comp.mkdir()
    (comp / 'idf_component.yml').write_text('version: "1.2.3"\ndescription: source component\n')
    (comp / 'sbom_orphanlib.yml').write_text('name: orphanlib\ncpe: cpe:2.3:a:orphanlib:orphanlib:1.0:*:*:*:*:*:*:*\n')
    # note: no .component_hash

    manifest = SBOMObject({}, {}).get_manifest(str(comp))

    assert manifest['virtpackages'] == []
    assert manifest['cpe'] == []
    assert manifest['description'] == 'source component'


def test_update_manifest_embeded_path_first_wins() -> None:
    """_embeded_path must stay tied to the source that first supplied the
    "manifests" list. A later source that also carries a "manifests" key must
    not overwrite it, otherwise the recorded origin would disagree with the
    kept list and embedded manifests would report the wrong source."""
    from esp_idf_sbom.libsbom.sbom import SBOMObject

    obj = SBOMObject({}, {})
    dst = SBOMObject.EMPTY_MANIFEST.copy()

    # first source with a "manifests" list sets both the list and its origin
    obj.update_manifest(dst, {'manifests': [{'path': 'a.yml', 'dest': 'a'}]}, '/first/sbom.yml')
    assert dst['manifests'] == [{'path': 'a.yml', 'dest': 'a'}]
    assert dst['_embeded_path'] == '/first/sbom.yml'

    # a later source also carrying "manifests" leaves both untouched (first-wins)
    obj.update_manifest(dst, {'manifests': [{'path': 'b.yml', 'dest': 'b'}]}, '/second/sbom.yml')
    assert dst['manifests'] == [{'path': 'a.yml', 'dest': 'a'}]
    assert dst['_embeded_path'] == '/first/sbom.yml'


def test_pwalk_prunes_excluded_subtree(tmp_path: Path) -> None:
    """pwalk must skip an excluded directory AND everything under it, so a
    subpackage's nested files are not also collected for the parent package."""
    from esp_idf_sbom.libsbom import utils

    (tmp_path / 'top.txt').write_text('')
    (tmp_path / 'sub' / 'deeper').mkdir(parents=True)
    (tmp_path / 'sub' / 'direct.txt').write_text('')
    (tmp_path / 'sub' / 'deeper' / 'nested.txt').write_text('')

    collected = {
        os.path.relpath(os.path.join(root, f), str(tmp_path))
        for root, _dirs, files in utils.pwalk(str(tmp_path), [str(tmp_path / 'sub')])
        for f in files
    }

    # only the parent's own file; both the subpackage's direct and nested files
    # are pruned (before the fix, sub/deeper/nested.txt leaked in)
    assert collected == {'top.txt'}


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


def test_validate_sbom_json(hello_world_build: Path) -> None:
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run(
        [
            sys.executable,
            '-m',
            'esp_idf_sbom',
            'create',
            '--format',
            'spdx-json',
            '--files',
            'rem',
            '-o',
            output_fn,
            proj_desc_path,
        ],
        check=True,
    )
    run(['pyspdxtools', '-i', output_fn], check=True)


def test_check_sbom_json(hello_world_build: Path) -> None:
    """check must accept an SPDX JSON SBOM (sbom.load auto-detects the format)."""
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', 'spdx-json', '-o', output_fn, proj_desc_path],
        check=True,
    )
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db', output_fn])
    assert p.returncode in [0, 1]


def test_validate_sbom_cyclonedx(hello_world_build: Path) -> None:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.cdx.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', 'cyclonedx-json', '-o', output_fn, proj_desc_path],
        check=True,
    )
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(output_fn.read_text())
    assert errors is None, f'CycloneDX validation failed: {errors}'


def test_check_sbom_cyclonedx(hello_world_build: Path) -> None:
    """check must accept a CycloneDX SBOM (sbom.load auto-detects the format)."""
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.cdx.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', 'cyclonedx-json', '-o', output_fn, proj_desc_path],
        check=True,
    )
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db', output_fn])
    assert p.returncode in [0, 1]


def _sbom_with_file():
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import File
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    f = File(path='./main/foo.c', sha1='a' * 40, sha256='b' * 64, license_concluded='MIT', copyrights={'Copyright X'})
    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-lib']
    )
    lib = Package(
        ref='COMPONENT-lib', name='lib', package_name='lib', kind=PackageKind.COMPONENT, version='2.0', files=[f]
    )
    return SBOM(name='app', root='PROJECT-app', packages=[proj, lib])


def test_cyclonedx_renders_files() -> None:
    """--files add: files must be emitted as nested CycloneDX components and validate."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    from esp_idf_sbom.libsbom import cyclonedx

    text = cyclonedx.render(_sbom_with_file(), version='1.6')
    assert '"type": "file"' in text
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None


def test_validate_sbom_spdx_jsonld(hello_world_build: Path) -> None:
    """create --format spdx-json-ld must validate against the official SPDX 3.0.1 JSON schema."""
    import urllib.request

    import jsonschema

    try:
        with urllib.request.urlopen('https://spdx.org/schema/3.0.1/spdx-json-schema.json', timeout=30) as resp:
            schema = json.loads(resp.read())
    except Exception as e:
        pytest.skip(f'cannot fetch the SPDX 3.0.1 schema: {e}')

    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx3.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', 'spdx-json-ld', '-o', output_fn, proj_desc_path],
        check=True,
    )
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(json.loads(output_fn.read_text())))
    assert not errors, f'SPDX 3.0 validation failed: {errors[:3]}'


def test_check_sbom_spdx_jsonld(hello_world_build: Path) -> None:
    """check must accept an SPDX 3.0 JSON-LD SBOM (sbom.load auto-detects the format)."""
    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx3.json'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', 'spdx-json-ld', '-o', output_fn, proj_desc_path],
        check=True,
    )
    p = run([sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db', output_fn])
    assert p.returncode in [0, 1]


def test_spdx_jsonld_renders_files() -> None:
    """--files add: files must be emitted as software_File elements and validate."""
    import urllib.request

    import jsonschema

    from esp_idf_sbom.libsbom import spdx

    text = spdx.render(_sbom_with_file(), format='json-ld', version='3.0.1')
    assert '"software_File"' in text
    try:
        with urllib.request.urlopen('https://spdx.org/schema/3.0.1/spdx-json-schema.json', timeout=30) as resp:
            schema = json.loads(resp.read())
    except Exception as e:
        pytest.skip(f'cannot fetch the SPDX 3.0.1 schema: {e}')
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(json.loads(text)))
    assert not errors, f'SPDX 3.0 file validation failed: {errors[:2]}'


def test_spdx_jsonld_parses_bare_refs() -> None:
    """SPDX 3.0 element ids carry the document namespace. Parsing must drop our own
    so the refs match what the other backends produce, and so re-rendering does not
    nest the old namespace inside the new one."""
    from esp_idf_sbom.libsbom import spdx

    model = _sbom_with_file()
    model.packages[1].cve_exclude_list = [{'cve': 'CVE-2020-1', 'reason': 'not used'}]

    back = spdx.parse(spdx.render(model, format='json-ld', version='3.0.1'), format='json-ld')

    by_ref = {pkg.ref: pkg for pkg in back.packages}
    assert back.root == 'PROJECT-app'
    assert set(by_ref) == {'PROJECT-app', 'COMPONENT-lib'}
    assert by_ref['PROJECT-app'].depends_on == ['COMPONENT-lib']
    # The graph is still keyed on full ids, so this breaks if the two ever drift.
    assert by_ref['COMPONENT-lib'].cve_exclude_list == [{'cve': 'CVE-2020-1', 'reason': 'not used'}]

    graph = json.loads(spdx.render(back, format='json-ld', version='3.0.1'))['@graph']
    assert all(e.get('spdxId', '').count('#') <= 1 for e in graph)


def test_producer_attribution() -> None:
    """Every format must attribute the document to the tool that produced it:
    name and version, the organization supplying the tool, and the tool's purl
    wherever the format has a slot for one."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx
    from esp_idf_sbom.libsbom.sbom import TOOL_NAME
    from esp_idf_sbom.libsbom.sbom import TOOL_PURL
    from esp_idf_sbom.libsbom.sbom import TOOL_SUPPLIER
    from esp_idf_sbom.libsbom.sbom import TOOL_VERSION

    model = _sbom_with_file()
    tool_id = f'{TOOL_NAME}-{TOOL_VERSION}'
    org = TOOL_SUPPLIER.split(': ', 1)[1]

    tagvalue = spdx.render(model, format='tagvalue', version='2.2')
    assert f'Creator: Tool: {tool_id}' in tagvalue
    assert f'Creator: {TOOL_SUPPLIER}' in tagvalue

    document = json.loads(spdx.render(model, format='json', version='2.2'))
    assert document['creationInfo']['creators'] == [f'Tool: {tool_id}', TOOL_SUPPLIER]

    graph = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))['@graph']
    tool = next(e for e in graph if e['type'] == 'Tool')
    assert tool['name'] == tool_id
    assert tool['externalIdentifier'][0]['identifier'] == TOOL_PURL
    creation_info = next(e for e in graph if e['type'] == 'CreationInfo')
    assert creation_info['createdUsing'] == [tool['spdxId']]
    creator = next(e for e in graph if e.get('spdxId') in creation_info['createdBy'])
    assert creator['type'] == 'Organization' and creator['name'] == org

    bom = json.loads(cyclonedx.render(model, version='1.6'))
    component = bom['metadata']['tools']['components'][0]
    assert component['name'] == TOOL_NAME
    assert component['version'] == TOOL_VERSION
    assert component['supplier']['name'] == org
    assert component['purl'] == TOOL_PURL


def test_vex_build() -> None:
    """vex.build turns each cve-exclude-list entry into one not-affected statement
    about its own package, carrying both product identities."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_file()
    lib = model.packages[1]
    lib.purl = 'pkg:github/example/lib@2.0'
    lib.cpes = ['cpe:2.3:a:example:lib:2.0:*:*:*:*:*:*:*']
    lib.cve_exclude_list = [
        {'cve': 'CVE-2020-1', 'reason': 'not used'},
        {'cve': 'CVE-2020-2', 'reason': 'not reachable'},
    ]

    doc = vex.build(model, sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555')

    assert doc.sbom_id == 'urn:uuid:11111111-2222-3333-4444-555555555555'
    assert doc.sbom_name == 'app'
    assert [s.vulnerability for s in doc.statements] == ['CVE-2020-1', 'CVE-2020-2']

    statement = doc.statements[0]
    assert statement.status is vex.VexStatus.NOT_AFFECTED
    assert statement.justification is None
    assert statement.impact_statement == 'not used'

    product = statement.products[0]
    assert product.ref == 'COMPONENT-lib'
    assert product.purl == 'pkg:github/example/lib@2.0'
    assert product.cpes == ['cpe:2.3:a:example:lib:2.0:*:*:*:*:*:*:*']
    assert product.name == 'lib'
    assert product.version == '2.0'
    # A copy, so editing the statement cannot reach back into the SBOM model.
    assert product.cpes is not lib.cpes


def test_vex_build_without_exclusions() -> None:
    """An SBOM with nothing excluded yields no statements at all."""
    from esp_idf_sbom.libsbom import vex

    assert vex.build(_sbom_with_file()).statements == []


def test_vex_vocabulary_is_cisa() -> None:
    """The model vocabulary has to stay CISA's. OpenVEX and the SPDX 3.0.1 security
    profile use it verbatim, so only the CycloneDX backend maps out of it; changing
    these values would push that mapping into every backend."""
    from esp_idf_sbom.libsbom import vex

    assert {s.value for s in vex.VexStatus} == {
        'not_affected',
        'affected',
        'fixed',
        'under_investigation',
    }
    assert {j.value for j in vex.VexJustification} == {
        'component_not_present',
        'vulnerable_code_not_present',
        'vulnerable_code_not_in_execute_path',
        'vulnerable_code_cannot_be_controlled_by_adversary',
        'inline_mitigations_already_exist',
    }


def _sbom_with_exclusions():
    model = _sbom_with_file()
    model.packages[1].cve_exclude_list = [
        {'cve': 'CVE-2020-1', 'reason': 'not used'},
        {'cve': 'CVE-2020-2', 'reason': 'not reachable'},
    ]
    return model


def test_embedded_vex_matches_model() -> None:
    """Embedded VEX is rendered from the same model a standalone document will be,
    so the two cannot drift: what vex.build produces is exactly what lands in each
    format that has a VEX vocabulary."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_exclusions()
    statements = vex.build(model).statements

    bom = json.loads(cyclonedx.render(model, version='1.6'))
    assert [(v['id'], v['analysis']['state'], v['analysis']['detail']) for v in bom['vulnerabilities']] == [
        (s.vulnerability, 'not_affected', s.impact_statement) for s in statements
    ]
    assert [v['affects'][0]['ref'] for v in bom['vulnerabilities']] == [s.products[0].ref for s in statements]

    graph = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))['@graph']
    vulns = [e for e in graph if e['type'] == 'security_Vulnerability']
    assessments = [e for e in graph if e['type'] == 'security_VexNotAffectedVulnAssessmentRelationship']
    assert [v['externalIdentifier'][0]['identifier'] for v in vulns] == [s.vulnerability for s in statements]
    assert [a['security_impactStatement'] for a in assessments] == [s.impact_statement for s in statements]

    document = next(e for e in graph if e['type'] == 'SpdxDocument')
    assert 'security' in document['profileConformance']
    assert all(e['spdxId'] in document['element'] for e in vulns + assessments)


def test_embedded_vex_absent_without_exclusions() -> None:
    """With nothing excluded no VEX is emitted at all, and SPDX 3.0.1 drops the
    security profile along with it."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx

    model = _sbom_with_file()

    assert 'vulnerabilities' not in json.loads(cyclonedx.render(model, version='1.6'))

    graph = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))['@graph']
    assert not [e for e in graph if e['type'].startswith('security_')]
    document = next(e for e in graph if e['type'] == 'SpdxDocument')
    assert 'security' not in document['profileConformance']


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
    args = {'format': 'json', 'local_db': False}

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

        # In-tree packages derive the esp-idf superproject PURL, each pinned to
        # the checkout's commit and distinguished by its own path as the PURL
        # subpath. What must never happen is the same PURL repeated across
        # packages, which is what dropping the subpath would produce. There are
        # none at all when esp-idf's remote is an internal/ssh URL that
        # guess_purl ignores, so this checks for duplicates rather than a count.
        idf_purls = re.findall(r'pkg:github/espressif/esp-idf@\S+', p.stdout)
        assert len(idf_purls) == len(set(idf_purls))

        # Toolchain emits the tarball SHA256 from tools.json as the only
        # PackageChecksum in the SBOM (files get FileChecksum, packages get
        # PackageVerificationCode), so a plain match is unambiguous.
        assert re.search(r'PackageChecksum: SHA256: [0-9a-f]{64}', p.stdout)
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


def test_get_files_deduplicates_symlinks() -> None:
    """A symlink and its target both surface in the directory walk, and prelpath
    resolves the symlink to the target, so without deduplication they collapse to
    the same relative path and the same file SPDXID (the toolchain's
    xtensa-esp-elf-cc -> -gcc is the real case). get_files keeps one relpath per
    file so per-file SPDXIDs stay unique."""
    from esp_idf_sbom.libsbom import sbom

    tmpdir = TemporaryDirectory()
    base = Path(tmpdir.name)
    (base / 'real.txt').write_text('content')
    (base / 'link.txt').symlink_to(base / 'real.txt')

    obj = sbom.SBOMObject({'file_tags': False}, {})
    files = obj.get_files(str(base))
    paths = [f.file.path for f in files]

    assert len(paths) == len(set(paths)), f'duplicate file paths: {paths}'
    assert paths == ['./real.txt']


def test_expand_cpe_aliases() -> None:
    """utils.expand_cpe_aliases adds sibling CPEs for vendor-renamed products.

    NVD files CVEs for the same software under more than one vendor name (e.g.
    Mbed TLS under both 'arm' and 'trustedfirmware'), so a CPE whose base is in
    utils.CPE_ALIASES must be scanned under every vendor in its group, with the
    version and remaining fields carried over.
    """
    from esp_idf_sbom.libsbom.utils import expand_cpe_aliases

    # An aliased vendor:product gains its sibling, preserving version/fields.
    assert expand_cpe_aliases(['cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*']) == [
        'cpe:2.3:a:arm:mbed_tls:3.6.5:*:*:*:*:*:*:*',
        'cpe:2.3:a:trustedfirmware:mbed_tls:3.6.5:*:*:*:*:*:*:*',
    ]

    # tf-psa-crypto is aliased the same way.
    assert expand_cpe_aliases(['cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*']) == [
        'cpe:2.3:a:arm:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*',
        'cpe:2.3:a:trustedfirmware:tf-psa-crypto:1.1.0:*:*:*:*:*:*:*',
    ]

    # A manifest already listing both vendors stays unchanged (no duplicate).
    both = [
        'cpe:2.3:a:arm:mbed_tls:4.1.0:*:*:*:*:*:*:*',
        'cpe:2.3:a:trustedfirmware:mbed_tls:4.1.0:*:*:*:*:*:*:*',
    ]
    assert expand_cpe_aliases(both) == both

    # A CPE with no alias is returned unchanged.
    assert expand_cpe_aliases(['cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*']) == [
        'cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*',
    ]


def test_create_vulnerable_record_maybe() -> None:
    """The `maybe` flag drives the MAYBE classification.

    Keyword-search and NA-version hits cannot be confirmed to apply to the
    scanned version, so callers pass maybe=True to report them as MAYBE rather
    than YES. The NVD status no longer affects the classification; exclusion
    still takes precedence.
    """
    from esp_idf_sbom.libsbom import report

    cpe = 'cpe:2.3:a:lwip_project:lwip:-:*:*:*:*:*:*:*'
    vuln = {
        'cve': {
            'id': 'CVE-2020-22283',
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang': 'en', 'value': 'buffer overflow'}],
            'metrics': {},
        }
    }

    # Default: asserted as YES.
    assert report.create_vulnerable_record(vuln, {}, cpe, '', 'lwip', '2.2.0')['vulnerable'] == 'YES'

    # maybe=True downgrades to MAYBE.
    assert report.create_vulnerable_record(vuln, {}, cpe, '', 'lwip', '2.2.0', maybe=True)['vulnerable'] == 'MAYBE'

    # The NVD status alone no longer forces MAYBE; only the maybe flag does.
    awaiting = {'cve': dict(vuln['cve'], vulnStatus='Awaiting Analysis')}
    assert report.create_vulnerable_record(awaiting, {}, cpe, '', 'lwip', '2.2.0')['vulnerable'] == 'YES'

    # Exclusion still wins over maybe.
    rec = report.create_vulnerable_record(vuln, {'CVE-2020-22283': 'fixed'}, cpe, '', 'lwip', '2.2.0', maybe=True)
    assert rec['vulnerable'] == 'EXCLUDED'


def test_evaluate_cpematch_ignores_na_target_for_versioned_criteria(monkeypatch: pytest.MonkeyPatch) -> None:
    """An NA (-) source must not match a versioned/ranged criteria via the :- name.

    NVD enumerates the NA CPE name among the concrete names of a version range,
    so without this guard an NA-version query would match a range CVE that does
    not apply (e.g. lwip <= 1.4.1 against lwip 2.2.0). A genuine NA criteria must
    still match an NA query.
    """
    from esp_idf_sbom.libsbom import nvd

    na_cpe = 'cpe:2.3:a:lwip_project:lwip:-:*:*:*:*:*:*:*'

    # Version-ranged criteria whose matchString includes the spurious :- name.
    monkeypatch.setattr(
        nvd,
        'get_match_criteria',
        lambda cid: [na_cpe, 'cpe:2.3:a:lwip_project:lwip:1.4.1:*:*:*:*:*:*:*'],
    )
    ranged = {
        'vulnerable': True,
        'criteria': 'cpe:2.3:a:lwip_project:lwip:*:*:*:*:*:*:*:*',
        'matchCriteriaId': 'RANGED',
        'versionEndIncluding': '1.4.1',
    }
    assert nvd.evaluate_cpematch(na_cpe, ranged) is False

    # A genuine NA criteria still matches the NA query.
    monkeypatch.setattr(nvd, 'get_match_criteria', lambda cid: [na_cpe])
    na = {
        'vulnerable': True,
        'criteria': 'cpe:2.3:a:lwip_project:lwip:-:*:*:*:*:*:*:*',
        'matchCriteriaId': 'NA',
    }
    assert nvd.evaluate_cpematch(na_cpe, na) is True


def test_merge_local_excluded_cves(tmp_path: Path) -> None:
    """nvd.merge_local_excluded_cves merges a repo-local excluded_cves.yaml into
    the in-memory exclusion set, extending the global list for the scan.

    This is the mechanism that lets a release branch suppress a framework (or
    component) CVE it has already fixed but cannot distinguish from the affected
    release by version. The merged set feeds both manifest check and SBOM
    generation, so testing it here covers both paths.
    """
    from esp_idf_sbom.libsbom import nvd

    # Set a known global exclusion set (one unrelated global-drop entry). The
    # path argument loads it and stores it as the in-memory cache, so the test
    # needs no internal cache poking and is isolated from any earlier load.
    global_file = tmp_path / 'global_excluded_cves.yaml'
    global_file.write_text('CVE-1111-0001: Unrelated to Espressif\n')
    nvd.get_excluded_cves(path=str(global_file))

    # Repo-local list: a scoped exclusion for the esp-idf framework CPE.
    root = tmp_path / 'idf'
    root.mkdir()
    (root / nvd.LOCAL_EXCLUDED_CVES_FILE).write_text(
        dedent(
            """\
            CVE-2026-45160:
              cpes:
                - cpe: cpe:2.3:a:espressif:esp-idf:6.0.1:*:*:*:*:*:*:*
              reason: Fixed on release/v6.0
            """
        )
    )

    # Before the merge only the global entry is known.
    assert 'CVE-2026-45160' not in nvd.get_excluded_cves()
    assert nvd.get_excluded_cves_for_cpe('cpe:2.3:a:espressif:esp-idf:6.0.1:*:*:*:*:*:*:*') == {}

    nvd.merge_local_excluded_cves(str(root))

    # The local scoped entry is honored for the matching CPE/version, but not for
    # a different version, and the original global entry is untouched.
    assert nvd.get_excluded_cves_for_cpe('cpe:2.3:a:espressif:esp-idf:6.0.1:*:*:*:*:*:*:*') == {
        'CVE-2026-45160': 'Fixed on release/v6.0'
    }
    assert nvd.get_excluded_cves_for_cpe('cpe:2.3:a:espressif:esp-idf:6.0.2:*:*:*:*:*:*:*') == {}
    assert nvd.get_globally_excluded_cves() == {'CVE-1111-0001': 'Unrelated to Espressif'}


def test_merge_local_excluded_cves_robustness(tmp_path: Path) -> None:
    """A missing local file is a no-op; on a duplicate CVE id the local entry
    overrides the global one (it is more specific to the scanned revision)."""
    from esp_idf_sbom.libsbom import nvd

    global_file = tmp_path / 'global_excluded_cves.yaml'
    global_file.write_text('CVE-2026-45160: Globally dropped\n')
    nvd.get_excluded_cves(path=str(global_file))

    # Missing local file leaves the global set unchanged.
    empty = tmp_path / 'empty'
    empty.mkdir()
    nvd.merge_local_excluded_cves(str(empty))
    assert nvd.get_excluded_cves()['CVE-2026-45160'] == 'Globally dropped'

    # Local entry for the same CVE id wins over the global one.
    root = tmp_path / 'idf'
    root.mkdir()
    (root / nvd.LOCAL_EXCLUDED_CVES_FILE).write_text(
        dedent(
            """\
            CVE-2026-45160:
              cpes:
                - cpe: cpe:2.3:a:espressif:esp-idf:6.0.1:*:*:*:*:*:*:*
              reason: Fixed on release/v6.0
            """
        )
    )
    nvd.merge_local_excluded_cves(str(root))
    entry = nvd.get_excluded_cves()['CVE-2026-45160']
    assert isinstance(entry, dict) and entry['reason'] == 'Fixed on release/v6.0'


def _document_manifest() -> str:
    return dedent(
        """\
        document:
          supplier:
            name: 'Organization: Acme Corp'
            url: 'https://acme.example'
            contact: 'psirt@acme.example'
          manufacturer:
            name: 'Organization: Acme Corp'
            url: 'https://acme.example'
            contact: 'psirt@acme.example'
        """
    )


@pytest.mark.parametrize(
    'manifest,valid',
    [
        ({'document': {'supplier': {'name': 'Organization: A', 'contact': 'a@b.io'}}}, True),
        ({'document': {'supplier': {'name': 'Person: A', 'url': 'https://a.example'}}}, True),
        ({'document': {}}, True),
        # A name alone identifies the entity but gives no way to reach it.
        ({'document': {'supplier': {'name': 'Organization: A'}}}, False),
        # The "Person: "/"Organization: " prefix is required, as for suppliers.
        ({'document': {'supplier': {'name': 'A', 'contact': 'a@b.io'}}}, False),
        ({'document': {'supplier': {'name': 'Organization: A', 'contact': 'nope'}}}, False),
        ({'document': {'supplier': {'name': 'Organization: A', 'url': 'ssh://a.example'}}}, False),
        # Unknown entities are rejected even though the outer schema ignores extra keys.
        ({'document': {'author': {'name': 'Organization: A', 'contact': 'a@b.io'}}}, False),
        ({'document': 'Organization: A'}, False),
    ],
)
def test_manifest_document_schema(manifest: dict, valid: bool) -> None:
    """The "document" key accepts an entity with a prefixed name plus a way to
    reach it, and rejects anything that could not satisfy a compliance check."""
    from esp_idf_sbom.libsbom import mft

    if valid:
        mft.validate(manifest, 'sbom.yml', '.', die=False)
    else:
        with pytest.raises(RuntimeError):
            mft.validate(manifest, 'sbom.yml', '.', die=False)


def test_document_metadata_cyclonedx(hello_world_build: Path) -> None:
    """document metadata from the project manifest lands in CycloneDX
    metadata.supplier/manufacturer and survives a parse/render round trip."""
    from esp_idf_sbom.libsbom import cyclonedx

    (hello_world_build / 'sbom.yml').write_text(_document_manifest())
    try:
        tmpdir = TemporaryDirectory()
        output_fn = Path(tmpdir.name) / 'sbom.cdx.json'
        proj_desc_path = hello_world_build / 'build' / 'project_description.json'
        run(
            [
                sys.executable,
                '-m',
                'esp_idf_sbom',
                'create',
                '--format',
                'cyclonedx-json',
                '-o',
                output_fn,
                proj_desc_path,
            ],
            check=True,
        )
    finally:
        (hello_world_build / 'sbom.yml').unlink()

    text = output_fn.read_text()
    metadata = json.loads(text)['metadata']
    for key in ('supplier', 'manufacturer'):
        assert metadata[key]['name'] == 'Acme Corp'
        assert metadata[key]['url'] == ['https://acme.example']
        assert metadata[key]['contact'] == [{'email': 'psirt@acme.example'}]

    model = cyclonedx.parse(text)
    assert model.supplier.name == 'Acme Corp'
    assert model.supplier.contact_email == 'psirt@acme.example'
    assert model.manufacturer.url == 'https://acme.example'
    # Re-rendering must not lose or alter the entities.
    assert cyclonedx.parse(cyclonedx.render(model)).supplier == model.supplier


def test_document_metadata_spdx(hello_world_build: Path) -> None:
    """The manufacturer is recorded as an SPDX document creator: a Creator line
    in 2.2, and an Agent with an email/urlScheme identifier in 3.0.1. SPDX has
    no document-level slot for the supplier, so only the manufacturer maps."""
    (hello_world_build / 'sbom.yml').write_text(_document_manifest())
    try:
        tmpdir = TemporaryDirectory()
        proj_desc_path = hello_world_build / 'build' / 'project_description.json'
        outputs = {}
        for fmt, name in (('spdx-tag-value', 'sbom.spdx'), ('spdx-json-ld', 'sbom.spdx3.json')):
            outputs[fmt] = Path(tmpdir.name) / name
            run(
                [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', fmt, '-o', outputs[fmt], proj_desc_path],
                check=True,
            )
    finally:
        (hello_world_build / 'sbom.yml').unlink()

    assert 'Creator: Organization: Acme Corp (psirt@acme.example)' in outputs['spdx-tag-value'].read_text()

    graph = json.loads(outputs['spdx-json-ld'].read_text())['@graph']
    creation_info = next(e for e in graph if e.get('type') == 'CreationInfo')
    agent = next(e for e in graph if e.get('name') == 'Acme Corp')
    assert agent['spdxId'] in creation_info['createdBy']
    identifiers = {i['externalIdentifierType']: i['identifier'] for i in agent['externalIdentifier']}
    assert identifiers == {'email': 'psirt@acme.example', 'urlScheme': 'https://acme.example'}


def test_document_metadata_ignored_outside_project(hello_world_build: Path) -> None:
    """The key is read from the project manifest only.

    It is not an EMPTY_MANIFEST key, so update_manifest never carries it and
    only SBOMProject.get_manifest reads it. A component that sets it therefore
    does not get it on its own manifest, and cannot supply the document
    metadata for the SBOM.
    """
    manifest = hello_world_build / 'main' / 'sbom.yml'
    manifest.write_text(_document_manifest())
    try:
        tmpdir = TemporaryDirectory()
        output_fn = Path(tmpdir.name) / 'sbom.cdx.json'
        proj_desc_path = hello_world_build / 'build' / 'project_description.json'
        run(
            [
                sys.executable,
                '-m',
                'esp_idf_sbom',
                'create',
                '--format',
                'cyclonedx-json',
                '-o',
                output_fn,
                proj_desc_path,
            ],
            check=True,
        )
    finally:
        manifest.unlink()

    metadata = json.loads(output_fn.read_text())['metadata']
    assert 'supplier' not in metadata and 'manufacturer' not in metadata


def test_idf_framework_manifest_license() -> None:
    """The synthesized ESP-IDF framework manifest declares the license from the
    LICENSE file at the repository root, so the framework package is not the one
    component in a generated SBOM without license information."""
    from esp_idf_sbom.libsbom import mft

    manifest = mft.build_idf_framework_manifest(os.environ['IDF_PATH'])
    assert manifest['license'] == 'Apache-2.0'
    # It must survive manifest validation, which parses the license expression.
    mft.validate(manifest, 'built-in', os.environ['IDF_PATH'], die=False)


def _guess_purl(**manifest) -> str:
    """Run guess_purl against a synthetic manifest.

    The commit-based paths cannot be reached end-to-end from a checkout whose
    remote is not a github.com/gitlab.com URL, which is the case for any
    internal or ssh clone, so the manifest states are built directly.
    """
    from esp_idf_sbom.libsbom.sbom import SBOMObject
    from esp_idf_sbom.libsbom.sbom import SBOMPackage

    pkg = SBOMPackage.__new__(SBOMPackage)
    pkg.args = {'no_guess': manifest.pop('no_guess', False)}
    pkg.manifest = dict(SBOMObject.EMPTY_MANIFEST, **manifest)
    return pkg.guess_purl()


def test_guess_purl_prefers_commit() -> None:
    """A recorded commit wins over the package version, and the package's path
    inside the repository becomes the PURL subpath.

    The github/gitlab PURL types define the version as "a commit or tag". The
    package version is neither here: an in-tree component carries ESP-IDF's git
    describe output and a managed component the registry's "<ver>~<rev>"
    revision, and neither is a ref in the repository the PURL names.
    """
    # In-tree component: get_remote_location() records "<url>@<sha>#<path>".
    assert (
        _guess_purl(
            repository='https://github.com/espressif/esp-idf@a9de6a4f302d1e6e#components/heap',
            version='v6.2-dev-2219-ga9de6a4f302d',
        )
        == 'pkg:github/espressif/esp-idf@a9de6a4f302d1e6e#components/heap'
    )
    # Submodule at a working tree root: no path fragment, so no subpath.
    assert (
        _guess_purl(
            repository='https://github.com/kmackay/micro-ecc@24c60e243580c786',
            version='1.1',
            url='https://github.com/kmackay/micro-ecc',
        )
        == 'pkg:github/kmackay/micro-ecc@24c60e243580c786'
    )
    # Managed component: the registry's repository_info, over a "git://" URL
    # and a version that is a registry revision rather than a tag.
    assert (
        _guess_purl(
            repository='git://github.com/espressif/example_components.git',
            version='3.3.9~1',
            url='https://github.com/espressif/example_components/tree/master/cmp',
            repository_info={'commit_sha': '121f1c16ec4b0a0a', 'path': 'cmp'},
        )
        == 'pkg:github/espressif/example_components@121f1c16ec4b0a0a#cmp'
    )
    # The registry writes "." for a component published from the repo root.
    assert (
        _guess_purl(
            repository='git://github.com/lvgl/lvgl.git',
            version='9.5.0',
            repository_info={'commit_sha': '85aa60d18b1e5b0b', 'path': '.'},
        )
        == 'pkg:github/lvgl/lvgl@85aa60d18b1e5b0b'
    )


def test_guess_purl_falls_back_to_version() -> None:
    """With no commit recorded the package version is used. This is the
    toolchain, described by tools.json rather than by a checkout, whose version
    is a crosstool-NG release tag and so still names a real ref."""
    assert (
        _guess_purl(repository='https://github.com/espressif/crosstool-NG', version='esp-16.1.0_20260609')
        == 'pkg:github/espressif/crosstool-NG@esp-16.1.0_20260609'
    )
    # No repository and no commit: nothing to derive from.
    assert _guess_purl(version='0.3.0') == ''
    # A commit on a host with no PURL type yields nothing rather than a guess.
    assert _guess_purl(repository='https://example.com/foo/bar@abc123', version='1.0') == ''
    # --no-guess suppresses the commit path too.
    assert _guess_purl(repository='https://github.com/a/b@abc123', version='1.0', no_guess=True) == ''


def test_derive_purl_subpath() -> None:
    """derive_purl carries a subpath and accepts the "git" scheme the IDF
    Component Registry writes into a managed component's repository URL."""
    from esp_idf_sbom.libsbom.utils import derive_purl

    assert derive_purl('https://github.com/a/b', 'abc', 'sub/dir') == 'pkg:github/a/b@abc#sub/dir'
    assert derive_purl('git://github.com/a/b.git', 'abc') == 'pkg:github/a/b@abc'
    # "." and empty both mean the repository root.
    assert derive_purl('https://github.com/a/b', 'abc', '.') == 'pkg:github/a/b@abc'
    assert derive_purl('https://github.com/a/b', 'abc', '') == 'pkg:github/a/b@abc'
    assert derive_purl('https://github.com/a/b', 'abc', '/sub/') == 'pkg:github/a/b@abc#sub'
    # A subdirectory browse URL still does not derive; the subpath is the way
    # to express a package inside a repository.
    assert derive_purl('https://github.com/a/b/tree/master/sub', 'abc') == ''


def test_guess_purl_virtpackage_borrowed_dir() -> None:
    """A virtual package must not derive a PURL from a commit.

    It has no directory of its own and borrows the one holding its manifest,
    which belongs to the component it is declared in. Deriving from that commit
    would identify the virtual package as the code at that path and collide with
    the component's own PURL. Its own url still derives.
    """
    from esp_idf_sbom.libsbom.sbom import SBOMObject
    from esp_idf_sbom.libsbom.sbom import SBOMVirtpackage

    pkg = SBOMVirtpackage.__new__(SBOMVirtpackage)
    pkg.args = {'no_guess': False}
    pkg.manifest = dict(
        SBOMObject.EMPTY_MANIFEST,
        repository='https://github.com/espressif/esp-idf@a9de6a4f302d1e6e#components/esp_libc',
        version='1.8.10',
    )
    assert pkg.guess_purl() == ''

    pkg.manifest['url'] = 'https://github.com/picolibc/picolibc'
    assert pkg.guess_purl() == 'pkg:github/picolibc/picolibc@1.8.10'


def test_repository_info_not_hand_authorable(tmp_path) -> None:
    """repository_info is registry data, not a documented manifest key.

    It is deliberately absent from EMPTY_MANIFEST, and update_manifest copies
    only keys already present there, so it never takes part in the referenced
    manifest -> sbom.yml -> idf_component.yml merge. get_manifest assigns it
    straight from idf_component.yml, where the registry writes it, leaving a
    hand-written entry in any other manifest with no effect. Merging it would
    let such an entry shadow the commit the registry recorded.
    """
    from esp_idf_sbom.libsbom.sbom import SBOMObject

    # Neither non-package key may be an EMPTY_MANIFEST key; that is what keeps
    # update_manifest from carrying them, so readers must use get().
    assert 'repository_info' not in SBOMObject.EMPTY_MANIFEST
    assert 'document' not in SBOMObject.EMPTY_MANIFEST

    (tmp_path / 'sbom.yml').write_text("repository_info:\n  commit_sha: 'handwritten'\n  path: 'evil'\n")
    (tmp_path / 'idf_component.yml').write_text(
        f"version: '1.0'\nrepository_info:\n  commit_sha: '{'a' * 40}'\n  path: 'led_strip'\n"
    )
    # A referenced manifest is merged before either file, so it would win too.
    SBOMObject.REFERENCED_MANIFESTS[str(tmp_path)] = {
        '_embeded_path': str(tmp_path / 'ref.yml'),
        'repository_info': {'commit_sha': 'referenced', 'path': 'evil'},
    }
    try:
        manifest = SBOMObject({'no_guess': False}, {}).get_manifest(str(tmp_path))
    finally:
        del SBOMObject.REFERENCED_MANIFESTS[str(tmp_path)]

    assert manifest['repository_info'] == {'commit_sha': 'a' * 40, 'path': 'led_strip'}

    # With no idf_component.yml the key is absent, not the sbom.yml value.
    (tmp_path / 'idf_component.yml').unlink()
    assert 'repository_info' not in SBOMObject({'no_guess': False}, {}).get_manifest(str(tmp_path))
