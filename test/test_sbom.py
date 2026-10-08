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
    embedded manifests for subpackage and subsubpackage. A cpe string with the
    {} placeholder works as in a manifest file.
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
                    version: 1.2.3
                    cpe: cpe:2.3:a:example:test_subpackage:{}:*:*:*:*:*:*:*
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
    assert 'cpe:2.3:a:example:test_subpackage:1.2.3:*:*:*:*:*:*:*' in p.stdout

    shutil.rmtree(subpackage_path)
    manifest.unlink()


def test_get_manifests_fixes_embedded_manifest(tmp_path: Path) -> None:
    """The manifest commands fix an embedded manifest like a manifest file, so a
    cpe string with the {} placeholder works there too."""
    from esp_idf_sbom.libsbom import mft

    (tmp_path / 'sub').mkdir()
    (tmp_path / 'sbom.yml').write_text(
        dedent("""
              manifests:
                - manifest:
                    name: sub
                    version: 1.2.3
                    cpe: cpe:2.3:a:example:sub:{}:*:*:*:*:*:*:*
                  dest: sub
              """)
    )

    sub = next(m for m in mft.get_manifests([str(tmp_path)]) if m.get('name') == 'sub')
    assert sub['cpe'] == ['cpe:2.3:a:example:sub:1.2.3:*:*:*:*:*:*:*']
    mft.validate(sub, sub['_src'], sub['_dst'], die=False)


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


def test_is_espressif_path_needs_a_directory_boundary(tmp_path: Path) -> None:
    """A path is in ESP-IDF only if it is IDF_PATH or below it. A sibling directory
    whose name starts with the same text, like esp-idf-app, is not, so its
    packages do not get Espressif as their supplier."""
    from esp_idf_sbom.libsbom.sbom import SBOMObject

    idf = tmp_path / 'esp-idf'
    sibling = tmp_path / 'esp-idf-app' / 'main'
    obj = SBOMObject({'no_guess': False}, {'idf_path': idf.as_posix()})

    assert obj.is_espressif_path(idf.as_posix())
    assert obj.is_espressif_path((idf / 'components' / 'log').as_posix())
    assert not obj.is_espressif_path(sibling.as_posix())
    assert obj.guess_supplier(sibling.as_posix()) == ''


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


def test_manifest_cve_exclude_list_justification() -> None:
    """A manifest entry accepts the CISA justifications and rejects other values."""
    from esp_idf_sbom.libsbom import mft

    def validate(**fields: object) -> None:
        manifest: dict = {'cve-exclude-list': [{'cve': 'CVE-2020-1000', 'reason': 'not used', **fields}]}
        mft.validate(manifest, 'sbom.yml', '.', die=False)

    validate(justification='vulnerable_code_not_present')
    with pytest.raises(RuntimeError, match='Justification "code_not_present"'):
        validate(justification='code_not_present')


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


def test_global_cve_exclude_fields_in_sbom(hello_world_build: Path) -> None:
    """A field that the manifest entry does not set comes from the matching entry
    in excluded_cves.yaml. A field that the manifest entry sets wins."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    manifest.write_text(
        dedent("""
              cpe: cpe:2.3:a:VENDOR1:PRODUCT1:1.0:*:*:*:*:*:*:*
              cve-exclude-list:
                - cve: CVE-9999-99999
                  reason: manifest reason
              """)
    )

    try:
        with TemporaryDirectory() as tmpdir:
            excluded_path = Path(tmpdir) / 'excluded_cves.yaml'
            excluded_path.write_text(
                dedent("""
                      CVE-9999-99999:
                        cpes:
                          - cpe: cpe:2.3:a:VENDOR1:PRODUCT1:1.0:*:*:*:*:*:*:*
                        reason: global reason
                        justification: vulnerable_code_not_in_execute_path
                      """)
            )

            env = {**os.environ, 'SBOM_EXCLUDED_CVES_FILE': str(excluded_path)}
            p = run(
                [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', 'cyclonedx-json', proj_desc_path],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
    finally:
        manifest.unlink()

    vulnerability = next(v for v in json.loads(p.stdout)['vulnerabilities'] if v['id'] == 'CVE-9999-99999')
    assert vulnerability['analysis'] == {
        'state': 'not_affected',
        'justification': 'code_not_reachable',
        'response': ['will_not_fix'],
        'detail': 'manifest reason',
    }


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
    """check must accept an SPDX JSON SBOM (formats.load_sbom auto-detects the format)."""
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
    """check must accept a CycloneDX SBOM (formats.load_sbom auto-detects the format)."""
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


def _assessments(*entries: dict) -> list:
    """The assessments for cve-exclude-list entries."""
    from esp_idf_sbom.libsbom.sbom import assessment_from_exclusion

    return [assessment_from_exclusion(entry) for entry in entries]


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
    """check must accept an SPDX 3.0 JSON-LD SBOM (formats.load_sbom auto-detects the format)."""
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
    model.packages[1].assessments = _assessments({'cve': 'CVE-2020-1', 'reason': 'not used'})

    back = spdx.parse(spdx.render(model, format='json-ld', version='3.0.1'), format='json-ld')

    by_ref = {pkg.ref: pkg for pkg in back.packages}
    assert back.root == 'PROJECT-app'
    assert set(by_ref) == {'PROJECT-app', 'COMPONENT-lib'}
    assert by_ref['PROJECT-app'].depends_on == ['COMPONENT-lib']
    # The graph is still keyed on full ids, so this breaks if the two ever drift.
    assert [a.vulnerability for a in by_ref['COMPONENT-lib'].assessments] == ['CVE-2020-1']

    graph = json.loads(spdx.render(back, format='json-ld', version='3.0.1'))['@graph']
    assert all(e.get('spdxId', '').count('#') <= 1 for e in graph)


def _sbom_with_licenses():
    """A component that declares a custom license and a copyright, and has a
    license and copyright notices found in its files."""
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import LicenseRef
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-lib']
    )
    lib = Package(
        ref='COMPONENT-lib',
        name='lib',
        package_name='lib',
        kind=PackageKind.COMPONENT,
        licenses_declared={'LicenseRef-Acme'},
        licenses_concluded={'MIT'},
        copyrights_declared={'2026 Acme Corp'},
        copyrights_concluded={'2010 Somebody Else'},
    )
    return SBOM(
        name='app',
        root='PROJECT-app',
        packages=[proj, lib],
        license_refs=[LicenseRef(id='LicenseRef-Acme', name='Acme License', text='Acme terms.')],
    )


def _component(text: str, name: str):
    """One component of a rendered CycloneDX document, by name."""
    return [c for c in json.loads(text)['components'] if c['name'] == name][0]


def test_spdx_defines_custom_license() -> None:
    """A LicenseRef- used in the document must be defined, or the document is
    not valid."""
    from esp_idf_sbom.libsbom import spdx

    text = spdx.render(_sbom_with_licenses(), version='2.2')
    assert 'PackageLicenseDeclared: LicenseRef-Acme' in text
    assert 'LicenseID: LicenseRef-Acme' in text
    assert 'ExtractedText: <text>Acme terms.</text>' in text

    tmpdir = TemporaryDirectory()
    output_fn = Path(tmpdir.name) / 'sbom.spdx'
    output_fn.write_text(text)
    run(['pyspdxtools', '-i', output_fn], check=True)


def test_spdx_copyright_and_attribution() -> None:
    """The declared copyright is the package copyright, the notices found in
    the files are attribution."""
    from esp_idf_sbom.libsbom import spdx

    text = spdx.render(_sbom_with_licenses(), version='2.2')
    assert 'PackageCopyrightText: <text>2026 Acme Corp</text>' in text
    assert 'PackageAttributionText: <text>2010 Somebody Else</text>' in text


def test_cyclonedx_declared_and_evidence() -> None:
    """What the author declared stays in the component, what the file scan
    found goes to evidence. The declared custom license carries its name and
    text as a license object, the scan result stays an expression."""
    from esp_idf_sbom.libsbom import cyclonedx

    comp = _component(cyclonedx.render(_sbom_with_licenses(), version='1.6'), 'lib')
    assert comp['licenses'] == [
        {
            'license': {
                'name': 'Acme License',
                'text': {'contentType': 'text/plain', 'content': 'Acme terms.'},
                'acknowledgement': 'declared',
            }
        }
    ]
    assert comp['copyright'] == '2026 Acme Corp'
    assert comp['evidence']['licenses'] == [{'expression': 'MIT', 'acknowledgement': 'concluded'}]
    assert comp['evidence']['copyright'] == [{'text': '2010 Somebody Else'}]


def test_cyclonedx_without_declared_values() -> None:
    """With nothing declared the scanned license and copyright are all there
    is, so they stay in the component and no evidence is reported."""
    from esp_idf_sbom.libsbom import cyclonedx

    sbom = _sbom_with_licenses()
    sbom.packages[1].licenses_declared = set()
    sbom.packages[1].copyrights_declared = set()

    comp = _component(cyclonedx.render(sbom, version='1.6'), 'lib')
    assert comp['licenses'] == [{'expression': 'MIT', 'acknowledgement': 'concluded'}]
    assert comp['copyright'] == '2010 Somebody Else'
    assert 'evidence' not in comp


def _lib_licenses(declared: str, refs=None):
    """The "licenses" of a component that declares the given expression."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-lib']
    )
    lib = Package(
        ref='COMPONENT-lib', name='lib', package_name='lib', kind=PackageKind.COMPONENT, licenses_declared={declared}
    )
    sbom = SBOM(name='app', root='PROJECT-app', packages=[proj, lib], license_refs=refs or [])
    return _component(cyclonedx.render(sbom, version='1.6'), 'lib')['licenses']


def test_cyclonedx_custom_license_carries_url() -> None:
    """A custom license with a url reports it in the license object."""
    from esp_idf_sbom.libsbom.sbom import LicenseRef

    ref = LicenseRef(id='LicenseRef-Acme', name='Acme License', text='Acme terms.', urls=['https://acme.example/l'])
    assert _lib_licenses('LicenseRef-Acme', [ref]) == [
        {
            'license': {
                'name': 'Acme License',
                'text': {'contentType': 'text/plain', 'content': 'Acme terms.'},
                'url': 'https://acme.example/l',
                'acknowledgement': 'declared',
            }
        }
    ]


def test_cyclonedx_custom_license_in_and() -> None:
    """A "AND" of an SPDX license and a custom one becomes one license object
    each. The SPDX license uses "id", the custom one its name and text."""
    from esp_idf_sbom.libsbom.sbom import LicenseRef

    ref = LicenseRef(id='LicenseRef-Acme', name='Acme License', text='Acme terms.')
    assert _lib_licenses('MIT AND LicenseRef-Acme', [ref]) == [
        {
            'license': {
                'name': 'Acme License',
                'text': {'contentType': 'text/plain', 'content': 'Acme terms.'},
                'acknowledgement': 'declared',
            }
        },
        {'license': {'id': 'MIT', 'acknowledgement': 'declared'}},
    ]


def test_cyclonedx_custom_license_in_or_stays_expression() -> None:
    """An "OR" has no license object list, so the whole expression stays, and
    the custom license keeps its identifier only."""
    from esp_idf_sbom.libsbom.sbom import LicenseRef

    ref = LicenseRef(id='LicenseRef-Acme', name='Acme License', text='Acme terms.')
    assert _lib_licenses('MIT OR LicenseRef-Acme', [ref]) == [
        {'expression': 'LicenseRef-Acme OR MIT', 'acknowledgement': 'declared'}
    ]


def test_cyclonedx_spdx_license_stays_expression() -> None:
    """A component with only SPDX licenses is unchanged, it stays an
    expression."""
    assert _lib_licenses('Apache-2.0') == [{'expression': 'Apache-2.0', 'acknowledgement': 'declared'}]


def test_cyclonedx_custom_license_only_in_evidence() -> None:
    """A custom license declared standard but found by the scan reports its name
    and text in evidence, not just in the declared field."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import LicenseRef
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-lib']
    )
    lib = Package(
        ref='COMPONENT-lib',
        name='lib',
        package_name='lib',
        kind=PackageKind.COMPONENT,
        licenses_declared={'MIT'},
        licenses_concluded={'LicenseRef-Acme'},
    )
    sbom = SBOM(
        name='app',
        root='PROJECT-app',
        packages=[proj, lib],
        license_refs=[LicenseRef(id='LicenseRef-Acme', name='Acme License', text='Acme terms.')],
    )
    comp = _component(cyclonedx.render(sbom, version='1.6'), 'lib')
    assert comp['licenses'] == [{'expression': 'MIT', 'acknowledgement': 'declared'}]
    assert comp['evidence']['licenses'] == [
        {
            'license': {
                'name': 'Acme License',
                'text': {'contentType': 'text/plain', 'content': 'Acme terms.'},
                'acknowledgement': 'concluded',
            }
        }
    ]


def test_producer_attribution() -> None:
    """Every format must attribute the document to the tool that produced it:
    name and version, the organization supplying the tool, and the tool's purl
    wherever the format has a slot for one. Espressif made the tool, not the
    document, so it is not a creator of the document."""
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
    assert 'Creator: Organization:' not in tagvalue

    document = json.loads(spdx.render(model, format='json', version='2.2'))
    assert document['creationInfo']['creators'] == [f'Tool: {tool_id}']

    graph = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))['@graph']
    tool = next(e for e in graph if e['type'] == 'Tool')
    assert tool['name'] == tool_id
    assert tool['externalIdentifier'][0]['identifier'] == TOOL_PURL
    creation_info = next(e for e in graph if e['type'] == 'CreationInfo')
    assert creation_info['createdUsing'] == [tool['spdxId']]
    # createdBy is required. Without a manufacturer it names the tool.
    creator = next(e for e in graph if e.get('spdxId') in creation_info['createdBy'])
    assert creator['type'] == 'SoftwareAgent' and creator['name'] == tool_id

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
    lib.assessments = _assessments(
        {'cve': 'CVE-2020-1', 'reason': 'not used'},
        {'cve': 'CVE-2020-2', 'reason': 'not reachable'},
    )

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


def test_vex_build_merges_equal_statements() -> None:
    """Packages with the same assessment of a CVE get one statement. Another content
    or other times give another statement."""
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    def package(name: str, *assessments) -> Package:
        return Package(
            ref=f'COMPONENT-{name}',
            name=name,
            package_name=name,
            kind=PackageKind.COMPONENT,
            assessments=list(assessments),
        )

    def not_affected(**values):
        values = {'impact_statement': 'Not used.', **values}
        return vex.VexAssessment(vulnerability='CVE-2026-0001', status=vex.VexStatus.NOT_AFFECTED, **values)

    fixed = vex.VexAssessment(vulnerability='CVE-2026-0002', status=vex.VexStatus.FIXED)
    model = SBOM(
        name='app',
        root='',
        packages=[
            package('a', not_affected()),
            package('b', not_affected(), fixed),
            package('c', not_affected(impact_statement='Other.')),
            package('d', not_affected(first_issued='2020-01-01T00:00:00Z')),
        ],
    )
    assert [(s.vulnerability, [p.ref for p in s.products]) for s in vex.build(model).statements] == [
        ('CVE-2026-0001', ['COMPONENT-a', 'COMPONENT-b']),
        ('CVE-2026-0002', ['COMPONENT-b']),
        ('CVE-2026-0001', ['COMPONENT-c']),
        ('CVE-2026-0001', ['COMPONENT-d']),
    ]


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


def test_vex_response_is_cyclonedx() -> None:
    """CISA has no response, so the model uses the five CycloneDX values."""
    from esp_idf_sbom.libsbom import vex

    assert {r.value for r in vex.VexResponse} == {
        'can_not_fix',
        'will_not_fix',
        'update',
        'rollback',
        'workaround_available',
    }


def test_vex_build_justification_and_response() -> None:
    """vex.build copies the justification of an entry. An unknown value can come
    only from an excluded_cves.yaml outside this repository, and it is skipped.
    The response is always will_not_fix."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_file()
    model.packages[1].assessments = _assessments(
        {'cve': 'CVE-2020-1', 'reason': 'not used', 'justification': 'vulnerable_code_not_present'},
        {'cve': 'CVE-2020-2', 'reason': 'not used', 'justification': 'unknown'},
        {'cve': 'CVE-2020-3', 'reason': 'not used'},
    )

    first, second, third = vex.build(model).statements
    assert first.justification is vex.VexJustification.VULNERABLE_CODE_NOT_PRESENT
    assert second.justification is None
    assert third.justification is None
    for statement in (first, second, third):
        assert statement.response == [vex.VexResponse.WILL_NOT_FIX]


def test_vex_build_nvd_url() -> None:
    """Each statement links to the NVD page of its CVE, because CISA requires the
    description of the vulnerability or a link to it. Other ids have no NVD page."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_file()
    model.packages[1].assessments = _assessments(
        {'cve': 'CVE-2025-66442', 'reason': 'not used'},
        {'cve': 'GHSA-2qrg-x229-3v8q', 'reason': 'not used'},
    )

    cve, ghsa = vex.build(model).statements
    assert cve.nvd_url == 'https://nvd.nist.gov/vuln/detail/CVE-2025-66442'
    assert ghsa.nvd_url == ''


def _sbom_with_exclusions():
    model = _sbom_with_file()
    model.packages[1].assessments = _assessments(
        {'cve': 'CVE-2020-1', 'reason': 'not used'},
        {'cve': 'CVE-2020-2', 'reason': 'not reachable'},
    )
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


def test_render_honours_supplied_document_id() -> None:
    """render() must use the doc_id it is given, and create a new one when there is
    none. All four formats must do this."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx

    model = _sbom_with_file()

    doc_id = cyclonedx.new_document_id(model)
    assert doc_id.startswith('urn:uuid:')
    assert json.loads(cyclonedx.render(model, version='1.6', doc_id=doc_id))['serialNumber'] == doc_id
    assert json.loads(cyclonedx.render(model, version='1.6'))['serialNumber'] != doc_id

    doc_id = spdx.new_document_id(model)
    assert doc_id.startswith('https://spdx.org/spdxdocs/app-')

    tagvalue = spdx.render(model, format='tagvalue', version='2.2', doc_id=doc_id)
    assert f'DocumentNamespace: {doc_id}\n' in tagvalue
    assert f'DocumentNamespace: {doc_id}\n' not in spdx.render(model, format='tagvalue', version='2.2')

    document = json.loads(spdx.render(model, format='json', version='2.2', doc_id=doc_id))
    assert document['documentNamespace'] == doc_id

    graph = json.loads(spdx.render(model, format='json-ld', version='3.0.1', doc_id=doc_id))['@graph']
    spdx_document = next(e for e in graph if e['type'] == 'SpdxDocument')
    assert spdx_document['spdxId'] == f'{doc_id}#SPDXRef-DOCUMENT'


def _vex_with_identities():
    """A VEX model whose product carries both identities, so the ref-based and the
    identity-based backends each have something to render."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_exclusions()
    model.packages[1].purl = 'pkg:github/example/lib@2.0'
    model.packages[1].cpes = ['cpe:2.3:a:example:lib:2.0:*:*:*:*:*:*:*']
    return vex.build(model, sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555')


def test_render_vex_cyclonedx() -> None:
    """A standalone CycloneDX VEX is a BOM carrying only assessments, linked to
    the SBOM it assesses by BOM-Link, and it must validate as a 1.6 document."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    from esp_idf_sbom.libsbom import cyclonedx

    text = cyclonedx.render_vex(_vex_with_identities(), version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None

    bom = json.loads(text)
    link = 'urn:cdx:11111111-2222-3333-4444-555555555555/1'
    assert 'components' not in bom
    assert 'dependencies' not in bom
    # Its own identity, distinct from the SBOM it points at.
    assert bom['serialNumber'].startswith('urn:uuid:')
    assert bom['serialNumber'] != 'urn:uuid:11111111-2222-3333-4444-555555555555'
    assert bom['externalReferences'] == [{'type': 'bom', 'url': link, 'comment': 'SBOM this VEX applies to: app'}]
    assert [v['id'] for v in bom['vulnerabilities']] == ['CVE-2020-1', 'CVE-2020-2']
    assert all(v['affects'][0]['ref'] == f'{link}#COMPONENT-lib' for v in bom['vulnerabilities'])


def test_render_vex_cyclonedx_needs_sbom_identity() -> None:
    """Without the SBOM's serialNumber there is no BOM-Link to build, so failing
    is better than emitting a document whose refs resolve to nothing."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex

    with pytest.raises(ValueError, match='serialNumber'):
        cyclonedx.render_vex(vex.build(_sbom_with_exclusions()))


def test_render_vex_openvex() -> None:
    """OpenVEX takes the CISA vocabulary verbatim and names products by identity,
    so it carries no reference to the SBOM document at all."""
    from esp_idf_sbom.libsbom import openvex

    document = json.loads(openvex.render_vex(_vex_with_identities()))

    assert document['@context'] == 'https://openvex.dev/ns/v0.2.0'
    assert document['@id'].startswith('urn:uuid:')
    assert document['author'] == 'Unknown Author'
    assert 'esp-idf-sbom' in document['tooling']
    assert 'urn:cdx' not in json.dumps(document)

    statement = document['statements'][0]
    assert statement == {
        'vulnerability': {'name': 'CVE-2020-1'},
        'products': [
            {
                '@id': 'pkg:github/example/lib@2.0',
                'identifiers': {
                    'purl': 'pkg:github/example/lib@2.0',
                    'cpe23': 'cpe:2.3:a:example:lib:2.0:*:*:*:*:*:*:*',
                },
            }
        ],
        'status': 'not_affected',
        'impact_statement': 'not used',
    }


def test_vex_author_is_the_manufacturer() -> None:
    """The author of a VEX document is the manufacturer from the project manifest,
    not Espressif, which only made the tool. OpenVEX requires an author, so without
    a manufacturer it writes the go-vex default."""
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import Organization

    vexdoc = _vex_with_identities()
    assert json.loads(openvex.render_vex(vexdoc))['author'] == 'Unknown Author'
    assert 'manufacturer' not in json.loads(cyclonedx.render_vex(vexdoc, version='1.6'))['metadata']

    model = _sbom_with_exclusions()
    model.manufacturer = Organization(name='Organization: Acme Corp', url='https://acme.example')
    vexdoc = vex.build(model, sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555')
    assert vexdoc.manufacturer == model.manufacturer

    model.packages[1].purl = 'pkg:github/example/lib@2.0'
    assert json.loads(openvex.render_vex(vex.build(model)))['author'] == 'Acme Corp'
    text = cyclonedx.render_vex(vexdoc, version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    assert json.loads(text)['metadata']['manufacturer'] == {'name': 'Acme Corp', 'url': ['https://acme.example']}


def test_render_vex_openvex_skips_unidentifiable_products() -> None:
    """A package with neither a PURL nor a CPE cannot be named in a way any
    consumer could match, so it is dropped with a warning rather than written."""
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex

    document = json.loads(openvex.render_vex(vex.build(_sbom_with_exclusions())))
    assert document['statements'] == []


def test_vex_justification_and_response_rendered() -> None:
    """The justification goes to every format that has a field for it, the
    response only to CycloneDX. The documents must still validate."""
    import urllib.request

    import jsonschema
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import spdx
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_exclusions()
    model.packages[1].purl = 'pkg:github/example/lib@2.0'
    model.packages[1].assessments[0].justification = vex.VexJustification.VULNERABLE_CODE_NOT_PRESENT

    text = cyclonedx.render(model, version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    first, second = json.loads(text)['vulnerabilities']
    assert first['analysis'] == {
        'state': 'not_affected',
        'justification': 'code_not_present',
        'response': ['will_not_fix'],
        'detail': 'not used',
    }
    assert second['analysis'] == {'state': 'not_affected', 'response': ['will_not_fix'], 'detail': 'not reachable'}

    vexdoc = vex.build(model, sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555')
    text = cyclonedx.render_vex(vexdoc, version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    assert json.loads(text)['vulnerabilities'][0]['analysis']['response'] == ['will_not_fix']

    statement = json.loads(openvex.render_vex(vexdoc))['statements'][0]
    assert statement['justification'] == 'vulnerable_code_not_present'

    document = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))
    first, second = [e for e in document['@graph'] if e['type'] == 'security_VexNotAffectedVulnAssessmentRelationship']
    assert first['security_justificationType'] == 'vulnerableCodeNotPresent'
    assert 'security_justificationType' not in second

    try:
        with urllib.request.urlopen('https://spdx.org/schema/3.0.1/spdx-json-schema.json', timeout=30) as resp:
            schema = json.loads(resp.read())
    except Exception as e:
        pytest.skip(f'cannot fetch the SPDX 3.0.1 schema: {e}')
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(document))
    assert not errors, f'SPDX 3.0 file validation failed: {errors[:2]}'


def test_vex_nvd_url_rendered() -> None:
    """The NVD link goes to the CycloneDX source.url, the OpenVEX vulnerability @id
    and an SPDX 3.0.1 securityAdvisory reference. The documents must still validate."""
    import urllib.request

    import jsonschema
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import spdx
    from esp_idf_sbom.libsbom import vex

    url = 'https://nvd.nist.gov/vuln/detail/CVE-2025-66442'
    model = _sbom_with_file()
    model.packages[1].purl = 'pkg:github/example/lib@2.0'
    model.packages[1].assessments = _assessments({'cve': 'CVE-2025-66442', 'reason': 'not used'})

    text = cyclonedx.render(model, version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    assert json.loads(text)['vulnerabilities'][0]['source'] == {'name': 'NVD', 'url': url}

    vexdoc = vex.build(model, sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555')
    text = cyclonedx.render_vex(vexdoc, version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    assert json.loads(text)['vulnerabilities'][0]['source'] == {'name': 'NVD', 'url': url}

    statement = json.loads(openvex.render_vex(vexdoc))['statements'][0]
    assert statement['vulnerability'] == {'name': 'CVE-2025-66442', '@id': url}

    document = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))
    vulnerability = next(e for e in document['@graph'] if e['type'] == 'security_Vulnerability')
    assert vulnerability['externalRef'] == [
        {'type': 'ExternalRef', 'externalRefType': 'securityAdvisory', 'locator': [url]}
    ]

    try:
        with urllib.request.urlopen('https://spdx.org/schema/3.0.1/spdx-json-schema.json', timeout=30) as resp:
            schema = json.loads(resp.read())
    except Exception as e:
        pytest.skip(f'cannot fetch the SPDX 3.0.1 schema: {e}')
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(document))
    assert not errors, f'SPDX 3.0 file validation failed: {errors[:2]}'


def test_create_vex_none(hello_world_build: Path) -> None:
    """--vex-format none drops the vulnerability information from every format, and only
    that: the SPDX 2.2 comment keeps its cve-keywords block, which is used to
    search CVE descriptions and is not an assessment."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    content = """
              cve-keywords:
                - helloworld
              cve-exclude-list:
                - cve: CVE-2020-1234
                  reason: not used in this configuration
              """
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    def create(fmt: str, *extra: str) -> str:
        cmd = [sys.executable, '-m', 'esp_idf_sbom', 'create', '--format', fmt, *extra, str(proj_desc_path)]
        return run(cmd, check=True, capture_output=True, text=True).stdout

    try:
        # CycloneDX: the whole vulnerabilities array goes.
        assert 'CVE-2020-1234' in create('cyclonedx-json')
        assert 'vulnerabilities' not in json.loads(create('cyclonedx-json', '--vex-format', 'none'))

        # SPDX 3.0.1: the security elements, and the security profile with them.
        assert 'CVE-2020-1234' in create('spdx-json-ld')
        graph = json.loads(create('spdx-json-ld', '--vex-format', 'none'))['@graph']
        assert not [e for e in graph if e['type'].startswith('security_')]
        document = next(e for e in graph if e['type'] == 'SpdxDocument')
        assert 'security' not in document['profileConformance']

        # SPDX 2.2 has no VEX vocabulary, so what goes is the cve-exclude-list
        # block of the package comment.
        for fmt in ('spdx-tag-value', 'spdx-json'):
            assert 'CVE-2020-1234' in create(fmt)
            text = create(fmt, '--vex-format', 'none')
            assert 'CVE-2020-1234' not in text
            assert 'cve-exclude-list' not in text
            assert 'cve-keywords' in text and 'helloworld' in text
    finally:
        manifest.unlink()


def test_parse_vex_round_trip() -> None:
    """render_vex then parse_vex must give back the same statements. The CycloneDX
    document also carries the id of the SBOM it belongs to, OpenVEX does not."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex

    original = _vex_with_identities()

    back = cyclonedx.parse_vex(cyclonedx.render_vex(original))
    assert back.sbom_id == original.sbom_id
    assert back.sbom_version == 1
    assert [(s.vulnerability, s.status, s.impact_statement) for s in back.statements] == [
        (s.vulnerability, s.status, s.impact_statement) for s in original.statements
    ]
    # CycloneDX names components by ref, so that is what comes back.
    assert [s.products[0].ref for s in back.statements] == ['COMPONENT-lib', 'COMPONENT-lib']

    back = openvex.parse_vex(openvex.render_vex(original))
    assert back.sbom_id == ''
    assert back.author == 'Unknown Author'
    assert [(s.vulnerability, s.status, s.impact_statement) for s in back.statements] == [
        (s.vulnerability, s.status, s.impact_statement) for s in original.statements
    ]
    # OpenVEX names products by identity, so there is no ref.
    product = back.statements[0].products[0]
    assert product.ref == ''
    assert product.purl == 'pkg:github/example/lib@2.0'
    assert product.cpes == ['cpe:2.3:a:example:lib:2.0:*:*:*:*:*:*:*']

    assert vex.VexStatus.NOT_AFFECTED is back.statements[0].status


def _assessments_of_all_statuses() -> list:
    """One assessment for each status, with every field that the status can have."""
    from esp_idf_sbom.libsbom import vex

    return [
        vex.VexAssessment(
            vulnerability='CVE-2020-1',
            status=vex.VexStatus.NOT_AFFECTED,
            justification=vex.VexJustification.COMPONENT_NOT_PRESENT,
            response=[vex.VexResponse.WILL_NOT_FIX],
            impact_statement='not used',
            first_issued='2026-01-01T10:00:00Z',
            last_updated='2026-01-01T10:00:00Z',
        ),
        vex.VexAssessment(
            vulnerability='CVE-2020-2',
            status=vex.VexStatus.FIXED,
            impact_statement='patched',
            first_issued='2026-01-01T10:00:00Z',
            last_updated='2026-02-01T10:00:00Z',
        ),
        vex.VexAssessment(
            vulnerability='CVE-2020-3',
            status=vex.VexStatus.AFFECTED,
            response=[vex.VexResponse.UPDATE],
            impact_statement='The TLS server is enabled.',
            action_statement='Update to version 2.1.',
            first_issued='2026-02-01T10:00:00Z',
            last_updated='2026-02-01T10:00:00Z',
        ),
        vex.VexAssessment(
            vulnerability='CVE-2020-4',
            status=vex.VexStatus.UNDER_INVESTIGATION,
            first_issued='2026-03-01T10:00:00Z',
            last_updated='2026-03-01T10:00:00Z',
        ),
    ]


def test_cyclonedx_vex_reads_back_all_fields() -> None:
    """Every field of a statement comes back from a CycloneDX VEX and from a
    CycloneDX SBOM. The action is the recommendation, and the CISA justification
    is kept in a property, because CycloneDX has no value for
    component_not_present."""
    import dataclasses

    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_file()
    model.packages[1].assessments = _assessments_of_all_statuses()

    text = cyclonedx.render_vex(vex.build(model, sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555'))
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    first, _, third, _ = json.loads(text)['vulnerabilities']
    assert first['analysis']['justification'] == 'code_not_present'
    assert first['properties'] == [{'name': 'esp-idf-sbom:justification', 'value': 'component_not_present'}]
    assert third['recommendation'] == 'Update to version 2.1.'

    def assessments(statements: list) -> list:
        """The statements without their products, as a package keeps them."""
        names = [f.name for f in dataclasses.fields(vex.VexAssessment)]
        return [vex.VexAssessment(**{name: getattr(s, name) for name in names}) for s in statements]

    assert assessments(cyclonedx.parse_vex(text).statements) == model.packages[1].assessments

    text = cyclonedx.render(model, version='1.6')
    assert JsonStrictValidator(SchemaVersion.V1_6).validate_str(text) is None
    by_ref = {pkg.ref: pkg for pkg in cyclonedx.parse(text).packages}
    assert by_ref['COMPONENT-lib'].assessments == model.packages[1].assessments


def test_vex_document_reads_back_id_version_and_times() -> None:
    """The document id, version and times come back from both formats, so that
    an update can keep the id. A statement without a time of its own gets the
    time of the document, and its last update is its first issue. CycloneDX has
    no first-issued time for the document, and its metadata.timestamp is the last
    update."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex

    document = _vex_with_identities()
    document.doc_id = 'urn:uuid:22222222-3333-4444-5555-666666666666'
    document.doc_version = 3
    document.first_issued = '2026-01-01T10:00:00Z'
    document.last_updated = '2026-03-01T10:00:00Z'
    first, second = document.statements
    first.first_issued = '2026-02-01T10:00:00Z'
    first.last_updated = '2026-03-01T10:00:00Z'

    def times(vexdoc: vex.Vex) -> list:
        return [(s.first_issued, s.last_updated) for s in vexdoc.statements]

    back = cyclonedx.parse_vex(cyclonedx.render_vex(document))
    assert (back.doc_id, back.doc_version) == (document.doc_id, 3)
    assert (back.first_issued, back.last_updated) == ('', '2026-03-01T10:00:00Z')
    assert times(back) == [
        ('2026-02-01T10:00:00Z', '2026-03-01T10:00:00Z'),
        ('2026-03-01T10:00:00Z', '2026-03-01T10:00:00Z'),
    ]

    back = openvex.parse_vex(openvex.render_vex(document))
    assert (back.doc_id, back.doc_version) == (document.doc_id, 3)
    assert (back.first_issued, back.last_updated) == ('2026-01-01T10:00:00Z', '2026-03-01T10:00:00Z')
    assert times(back) == [
        ('2026-02-01T10:00:00Z', '2026-03-01T10:00:00Z'),
        ('2026-01-01T10:00:00Z', '2026-01-01T10:00:00Z'),
    ]


def test_vex_build_writes_a_new_document() -> None:
    """A VEX built from an SBOM is a new document: a new id each time, version 1,
    and no statement times, so the output of create does not change."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex

    first = json.loads(cyclonedx.render_vex(_vex_with_identities()))
    second = json.loads(cyclonedx.render_vex(_vex_with_identities()))
    assert first['serialNumber'] != second['serialNumber']
    assert first['version'] == 1
    assert all('firstIssued' not in v['analysis'] for v in first['vulnerabilities'])

    first = json.loads(openvex.render_vex(_vex_with_identities()))
    second = json.loads(openvex.render_vex(_vex_with_identities()))
    assert first['@id'] != second['@id']
    assert first['version'] == 1
    assert 'last_updated' not in first
    assert all('timestamp' not in s for s in first['statements'])


def test_cyclonedx_vex_justification_from_other_tools() -> None:
    """Without the property, code_not_present means vulnerable_code_not_present.
    The CycloneDX justifications without a CISA match give none. The property is
    used only when it agrees with the CycloneDX justification."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex

    def justification(analysis: dict, properties: list = []):
        vulnerability = {
            'id': 'CVE-2020-1',
            'analysis': {'state': 'not_affected', **analysis},
            'affects': [{'ref': 'COMPONENT-lib'}],
            'properties': properties,
        }
        document = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'vulnerabilities': [vulnerability]}
        return cyclonedx.parse_vex(json.dumps(document)).statements[0].justification

    def prop(value: str) -> list:
        return [{'name': 'esp-idf-sbom:justification', 'value': value}]

    assert justification({'justification': 'code_not_present'}) is vex.VexJustification.VULNERABLE_CODE_NOT_PRESENT
    assert justification({'justification': 'requires_configuration'}) is None
    assert justification({}) is None
    # Someone changed the CycloneDX justification and left the property.
    changed = justification({'justification': 'code_not_reachable'}, prop('component_not_present'))
    assert changed is vex.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    # The property alone is not a justification.
    assert justification({}, prop('component_not_present')) is None
    unknown = justification({'justification': 'code_not_present'}, prop('unknown'))
    assert unknown is vex.VexJustification.VULNERABLE_CODE_NOT_PRESENT


def test_spdx_jsonld_reads_back_all_statuses() -> None:
    """SPDX 3.0.1 has one relationship class for each status, with the CISA
    justifications. Everything but the response comes back as it was, because
    SPDX has no response. The document must still validate."""
    import urllib.request
    from dataclasses import replace

    import jsonschema

    from esp_idf_sbom.libsbom import spdx

    model = _sbom_with_file()
    model.packages[1].assessments = _assessments_of_all_statuses()

    text = spdx.render(model, format='json-ld', version='3.0.1')
    graph = json.loads(text)['@graph']
    relationships = [e for e in graph if e['type'].startswith('security_Vex')]
    assert [(e['type'], e['relationshipType']) for e in relationships] == [
        ('security_VexNotAffectedVulnAssessmentRelationship', 'doesNotAffect'),
        ('security_VexFixedVulnAssessmentRelationship', 'fixedIn'),
        ('security_VexAffectedVulnAssessmentRelationship', 'affects'),
        ('security_VexUnderInvestigationVulnAssessmentRelationship', 'underInvestigationFor'),
    ]
    affected = relationships[2]
    assert affected['security_actionStatement'] == 'Update to version 2.1.'
    assert affected['security_statusNotes'] == 'The TLS server is enabled.'
    assert relationships[1]['security_modifiedTime'] == '2026-02-01T10:00:00Z'

    back = spdx.parse(text, format='json-ld')
    by_ref = {pkg.ref: pkg for pkg in back.packages}
    assert by_ref['COMPONENT-lib'].assessments == [replace(a, response=[]) for a in model.packages[1].assessments]

    try:
        with urllib.request.urlopen('https://spdx.org/schema/3.0.1/spdx-json-schema.json', timeout=30) as resp:
            schema = json.loads(resp.read())
    except Exception as e:
        pytest.skip(f'cannot fetch the SPDX 3.0.1 schema: {e}')
    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(json.loads(text)))
    assert not errors, f'SPDX 3.0 file validation failed: {errors[:2]}'


def test_vex_parse_time() -> None:
    """parse_time() reads the times that VEX and SBOM files write. Python before 3.11
    reads a fraction of a second only with 3 or 6 digits, and go-vex writes up to 9."""
    from esp_idf_sbom.libsbom import vex

    def read(value: str) -> str:
        time = vex.parse_time(value)
        return time.isoformat() if time else ''

    assert read('2026-10-08T10:49:12Z') == '2026-10-08T10:49:12+00:00'
    assert read('2026-10-08T10:49:12.123456789Z') == '2026-10-08T10:49:12.123456+00:00'
    assert read('2026-10-08T10:49:12.5Z') == '2026-10-08T10:49:12.500000+00:00'
    assert read('2026-10-08T12:49:12.123+02:00') == '2026-10-08T12:49:12.123000+02:00'
    # A time without a time zone is in UTC.
    assert read('2026-10-08T10:49:12') == '2026-10-08T10:49:12+00:00'
    assert read('yesterday') == read('') == ''


def test_spdx_jsonld_writes_times_in_utc() -> None:
    """SPDX 3.0.1 requires UTC times with whole seconds and a Z. A time read from
    another file may have another form, and a time that cannot be read is
    skipped."""
    from esp_idf_sbom.libsbom import spdx
    from esp_idf_sbom.libsbom.sbom import VexAssessment
    from esp_idf_sbom.libsbom.vexvalues import VexStatus

    model = _sbom_with_file()
    model.packages[1].assessments = [
        VexAssessment(
            vulnerability='CVE-2020-1',
            status=VexStatus.UNDER_INVESTIGATION,
            first_issued='2026-01-01T10:00:00.123+02:00',
            last_updated='yesterday',
        )
    ]

    graph = json.loads(spdx.render(model, format='json-ld', version='3.0.1'))['@graph']
    relationship = next(e for e in graph if e['type'].startswith('security_Vex'))
    assert relationship['security_publishedTime'] == '2026-01-01T08:00:00Z'
    assert 'security_modifiedTime' not in relationship


def test_parse_vex_detects_format(tmp_path: Path) -> None:
    """formats.load_vex detects the format from the top-level keys, like load_sbom does.
    The model keeps the format and the text of the file."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import formats
    from esp_idf_sbom.libsbom import openvex

    original = _vex_with_identities()

    cdx_file = tmp_path / 'a.vex.cdx.json'
    cdx_file.write_text(cyclonedx.render_vex(original))
    vexdoc = formats.load_vex(str(cdx_file))
    assert vexdoc.sbom_id == original.sbom_id
    assert (vexdoc.format_name, vexdoc.text) == ('cyclonedx-json', cdx_file.read_text())

    ovx_file = tmp_path / 'a.openvex.json'
    ovx_file.write_text(openvex.render_vex(original))
    vexdoc = formats.load_vex(str(ovx_file))
    assert len(vexdoc.statements) == 2
    assert (vexdoc.format_name, vexdoc.text) == ('openvex', ovx_file.read_text())

    other = tmp_path / 'other.json'
    other.write_text(json.dumps({'spdxVersion': 'SPDX-2.2'}))
    with pytest.raises(ValueError, match='unrecognized VEX format'):
        formats.load_vex(str(other))


def test_parse_vex_reads_document_reference() -> None:
    """The SBOM a VEX belongs to is named in its document level externalReferences,
    so it survives even when the document has no statements to carry a BOM-Link."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex

    empty = vex.Vex(statements=[], sbom_id='urn:uuid:11111111-2222-3333-4444-555555555555', sbom_name='app')
    back = cyclonedx.parse_vex(cyclonedx.render_vex(empty))
    assert back.statements == []
    assert back.sbom_id == empty.sbom_id

    # Without the document reference, the links in affects[] still say it.
    document = json.loads(cyclonedx.render_vex(_vex_with_identities()))
    del document['externalReferences']
    assert cyclonedx.parse_vex(json.dumps(document)).sbom_id == _vex_with_identities().sbom_id


def test_parse_vex_rejects_two_sboms() -> None:
    """A statement pointing somewhere other than the document reference would be
    applied to the wrong SBOM, because the model keeps only the component ref."""
    from esp_idf_sbom.libsbom import cyclonedx

    document = json.loads(cyclonedx.render_vex(_vex_with_identities()))
    other = 'urn:cdx:99999999-8888-7777-6666-555555555555/1'
    document['vulnerabilities'][1]['affects'][0]['ref'] = f'{other}#COMPONENT-lib'
    with pytest.raises(ValueError, match='more than one SBOM'):
        cyclonedx.parse_vex(json.dumps(document))


def test_vex_apply() -> None:
    """apply() puts the statements into the assessments, which is where the rest
    of the tool already reads them from. OpenVEX has no response, so none comes
    back."""
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex

    document = openvex.parse_vex(openvex.render_vex(_vex_with_identities()))

    model = _sbom_with_file()
    model.packages[1].purl = 'pkg:github/example/lib@2.0'
    assert model.packages[1].assessments == []

    vex.apply(model, document)
    # The statements have no times of their own, so they get the document time.
    issued = document.first_issued
    assert model.packages[1].assessments == [
        vex.VexAssessment(
            vulnerability='CVE-2020-1',
            status=vex.VexStatus.NOT_AFFECTED,
            impact_statement='not used',
            first_issued=issued,
            last_updated=issued,
        ),
        vex.VexAssessment(
            vulnerability='CVE-2020-2',
            status=vex.VexStatus.NOT_AFFECTED,
            impact_statement='not reachable',
            first_issued=issued,
            last_updated=issued,
        ),
    ]
    assert model.packages[0].assessments == []


def _sbom_for_lookup():
    """Packages for find_packages(): a package with a PURL, two copies of cJSON
    with the same CPE and name, and Mbed TLS under the arm vendor name."""
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    def package(ref: str, name: str, cpe: str, purl: str = '') -> Package:
        return Package(ref=ref, name=name, package_name=name, kind=PackageKind.COMPONENT, purl=purl, cpes=[cpe])

    cjson = 'cpe:2.3:a:cjson_project:cjson:1.7.19:*:*:*:*:*:*:*'
    packages = [
        package('COMPONENT-lib', 'lib', 'cpe:2.3:a:example:lib:2.0:*:*:*:*:*:*:*', 'pkg:github/example/lib@2.0'),
        package('SUBMODULE-json-cJSON', 'cJSON', cjson),
        package('COMPONENT-espressif-cjson', 'cJSON', cjson),
        package('SUBMODULE-mbedtls-mbedtls', 'mbedtls', 'cpe:2.3:a:arm:mbed_tls:3.6.2:*:*:*:*:*:*:*'),
    ]
    return SBOM(name='app', root='COMPONENT-lib', packages=packages)


def test_find_packages() -> None:
    """A product is found by its ref, PURL, CPE or name, in this order. A CPE is
    compared without case, its version only when it has one, and also through its
    aliases. A CPE or a name can find more than one package."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_for_lookup()

    def refs(**fields) -> list:
        return [pkg.ref for pkg in vex.find_packages(model, vex.VexProduct(**fields))]

    def cpe(vendor: str, product: str, version: str) -> str:
        return f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'

    cjson = ['SUBMODULE-json-cJSON', 'COMPONENT-espressif-cjson']
    assert refs(ref='COMPONENT-lib') == ['COMPONENT-lib']
    assert refs(purl='pkg:github/example/lib@2.0') == ['COMPONENT-lib']
    assert refs(cpes=[cpe('cjson_project', 'cjson', '1.7.19')]) == cjson
    assert refs(cpes=[cpe('CJSON_PROJECT', 'cJSON', '1.7.19')]) == cjson
    assert refs(cpes=[cpe('cjson_project', 'cjson', '*')]) == cjson
    assert refs(cpes=[cpe('cjson_project', 'cjson', '-')]) == cjson
    assert refs(cpes=[cpe('cjson_project', 'cjson', '1.7.18')]) == []
    # NVD names Mbed TLS also under trustedfirmware, see utils.CPE_ALIASES.
    assert refs(cpes=[cpe('trustedfirmware', 'mbed_tls', '3.6.2')]) == ['SUBMODULE-mbedtls-mbedtls']
    assert refs(name='cJSON') == cjson
    assert refs(name='unknown') == []
    # The ref is tried first, so the CPE does not add the other copy.
    assert refs(ref='SUBMODULE-json-cJSON', cpes=[cpe('cjson_project', 'cjson', '1.7.19')]) == cjson[:1]
    # A PURL that is not in the SBOM falls back to the CPE.
    assert refs(purl='pkg:github/other/lib@1.0', cpes=[cpe('example', 'lib', '2.0')]) == ['COMPONENT-lib']


def test_vex_apply_reaches_every_package_with_the_cpe() -> None:
    """A statement found by CPE goes to every package with that CPE. Before, only
    the last package with the CPE got it."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_for_lookup()
    statement = vex.VexStatement(
        vulnerability='CVE-2020-1',
        status=vex.VexStatus.NOT_AFFECTED,
        products=[vex.VexProduct(cpes=['cpe:2.3:a:cjson_project:cjson:1.7.19:*:*:*:*:*:*:*'])],
        impact_statement='not used',
    )
    vex.apply(model, vex.Vex(statements=[statement]))
    with_statement = [pkg.ref for pkg in model.packages if pkg.assessments]
    assert with_statement == ['SUBMODULE-json-cJSON', 'COMPONENT-espressif-cjson']


def test_vexyaml_parses_statements() -> None:
    """Each CVE of a package becomes a statement for that package. The form of the
    package id says which id of the package it is, and find_packages() then finds
    the package. Unknown keys are ignored, so that a newer version can add keys."""
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom import vexyaml

    cjson_cpe = 'cpe:2.3:a:cjson_project:cjson:1.7.19:*:*:*:*:*:*:*'
    text = dedent(
        f"""\
        future: ignored
        packages:
          - package: {cjson_cpe}
            future: ignored
            vulnerabilities:
              - cve: CVE-2026-1
                status: not_affected
                justification: vulnerable_code_not_in_execute_path
                detail: Not used.
                future: ignored
              - cve: CVE-2026-6
                status: fixed
          - package: pkg:github/example/lib@2.0
            vulnerabilities:
              - cve: CVE-2026-2
                status: affected
                detail: The server is enabled.
                action: Update to 2.1.
          - package: urn:cdx:11111111-2222-3333-4444-555555555555/1#COMPONENT-lib
            vulnerabilities:
              - cve: CVE-2026-3
                status: fixed
          - package: SPDXRef-COMPONENT-lib
            vulnerabilities:
              - cve: CVE-2026-4
                status: under_investigation
          - package: cJSON
            vulnerabilities:
              - cve: CVE-2026-5
                status: under_investigation
        """
    )
    document = vexyaml.parse_vex(text)

    statements = document.statements
    assert [s.vulnerability for s in statements] == [f'CVE-2026-{n}' for n in (1, 6, 2, 3, 4, 5)]
    assert statements[0].status is vex.VexStatus.NOT_AFFECTED
    assert statements[0].justification is vex.VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
    assert statements[0].impact_statement == 'Not used.'
    affected = statements[2]
    assert affected.status is vex.VexStatus.AFFECTED
    assert (affected.impact_statement, affected.action_statement) == ('The server is enabled.', 'Update to 2.1.')
    assert [s.products for s in statements] == [
        [vex.VexProduct(cpes=[cjson_cpe])],
        [vex.VexProduct(cpes=[cjson_cpe])],
        [vex.VexProduct(purl='pkg:github/example/lib@2.0')],
        [vex.VexProduct(ref='COMPONENT-lib')],
        [vex.VexProduct(ref='COMPONENT-lib')],
        [vex.VexProduct(ref='cJSON', name='cJSON')],
    ]
    # The BOM-Link names the SBOM it was copied from.
    assert (document.sbom_id, document.sbom_version) == ('urn:uuid:11111111-2222-3333-4444-555555555555', 1)

    model = _sbom_for_lookup()
    cjson = ['SUBMODULE-json-cJSON', 'COMPONENT-espressif-cjson']
    lib = ['COMPONENT-lib']
    found = [[pkg.ref for pkg in vex.find_packages(model, s.products[0])] for s in statements]
    assert found == [cjson, cjson, lib, lib, lib, cjson]


def test_vexyaml_spdx_element_id() -> None:
    """An SPDX 3.0.1 element id gives the ref, and its namespace names the SBOM.
    Package ids that name two different SBOMs are an error."""
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom import vexyaml

    namespace = 'https://spdx.org/spdxdocs/app-11111111-2222-3333-4444-555555555555'
    entry = {'package': f'{namespace}#COMPONENT-lib', 'vulnerabilities': [{'cve': 'CVE-2026-1', 'status': 'fixed'}]}
    document = vexyaml.parse_vex(json.dumps({'packages': [entry]}))
    assert document.sbom_id == namespace
    assert document.statements[0].products == [vex.VexProduct(ref='COMPONENT-lib')]

    link = {**entry, 'package': 'urn:cdx:11111111-2222-3333-4444-555555555555/1#COMPONENT-lib'}
    with pytest.raises(ValueError, match='more than one SBOM'):
        vexyaml.parse_vex(json.dumps({'packages': [entry, link]}))


def test_vexyaml_rejects_invalid_entries() -> None:
    """A missing or unknown value is an error. So is a field that the status does
    not allow, or a field that it needs, as CISA describes them."""
    from esp_idf_sbom.libsbom import vexyaml

    def parse(package: str = 'lib', **fields):
        cve_entry = {'cve': 'CVE-2026-1', 'status': 'fixed', **fields}
        cve_entry = {key: value for key, value in cve_entry.items() if value is not None}
        return vexyaml.parse_vex(json.dumps({'packages': [{'package': package, 'vulnerabilities': [cve_entry]}]}))

    assert len(parse().statements) == 1

    def error(**fields) -> str:
        with pytest.raises(ValueError) as info:
            parse(**fields)
        return str(info.value)

    assert error(status=None).startswith("packages[0] (lib): vulnerabilities[0] (CVE-2026-1): Missing key: 'status'")
    assert 'Status "bad" must be one of' in error(status='bad')
    assert 'Justification "bad" must be one of' in error(status='not_affected', justification='bad')
    assert 'only for the not_affected status' in error(justification='component_not_present')
    assert 'needs a justification or a detail' in error(status='not_affected')
    assert 'needs an action' in error(status='affected')
    assert 'Response "bad" must be one of' in error(response=['bad'])
    assert 'The response must be a list' in error(response='update')
    assert 'not a CPE 2.3 string' in error(package='cpe:/a:example:lib:2.0')
    assert 'must not be empty' in error(package='')
    with pytest.raises(ValueError, match="packages\\[0\\]: Missing key: 'vulnerabilities'"):
        vexyaml.parse_vex(json.dumps({'packages': [{'package': 'lib'}]}))
    with pytest.raises(ValueError, match='needs a "packages" list'):
        vexyaml.parse_vex('vulnerabilities: []')
    with pytest.raises(ValueError, match='not valid YAML'):
        vexyaml.parse_vex('packages: [')


def test_vexyaml_response() -> None:
    """The response is a list of CycloneDX values. Without it, not_affected gets
    will_not_fix, like a cve-exclude-list entry, and the other statuses get none."""
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom import vexyaml

    def response(**fields):
        cve_entry = {'cve': 'CVE-2026-1', **fields}
        document = vexyaml.parse_vex(json.dumps({'packages': [{'package': 'lib', 'vulnerabilities': [cve_entry]}]}))
        return document.statements[0].response

    not_affected = {'status': 'not_affected', 'detail': 'Not used.'}
    assert response(**not_affected) == [vex.VexResponse.WILL_NOT_FIX]
    assert response(**not_affected, response=[]) == []
    assert response(status='affected', action='Update.', response=['update', 'workaround_available']) == [
        vex.VexResponse.UPDATE,
        vex.VexResponse.WORKAROUND_AVAILABLE,
    ]
    assert response(status='fixed') == []


def test_vex_apply_keeps_all_statuses() -> None:
    """apply() keeps the statements of all four statuses with all their fields.
    What a status means is up to the consumer, for example the check report."""
    from esp_idf_sbom.libsbom import vex

    assessments = [
        vex.VexAssessment(vulnerability='CVE-2020-7', status=vex.VexStatus.AFFECTED, action_statement='update'),
        vex.VexAssessment(vulnerability='CVE-2020-8', status=vex.VexStatus.UNDER_INVESTIGATION),
        vex.VexAssessment(vulnerability='CVE-2020-9', status=vex.VexStatus.FIXED),
        vex.VexAssessment(
            vulnerability='CVE-2020-10',
            status=vex.VexStatus.NOT_AFFECTED,
            justification=vex.VexJustification.COMPONENT_NOT_PRESENT,
            response=[vex.VexResponse.WILL_NOT_FIX],
            impact_statement='not used',
        ),
    ]
    statements = [
        vex.VexStatement(**vars(assessment), products=[vex.VexProduct(ref='COMPONENT-lib')])
        for assessment in assessments
    ]

    model = _sbom_with_file()
    vex.apply(model, vex.Vex(statements=statements))
    assert model.packages[1].assessments == assessments


def test_vex_apply_refuses_another_sbom() -> None:
    """A VEX document that names its SBOM is used only with that SBOM."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_exclusions()
    model.doc_id = 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79'
    vex.apply(model, vex.Vex(sbom_id=model.doc_id))
    vex.apply(model, vex.Vex())
    with pytest.raises(ValueError, match='belongs to another SBOM'):
        vex.apply(model, vex.Vex(sbom_id='urn:uuid:00000000-0000-0000-0000-000000000000'))


def test_cyclonedx_vex_needs_a_serial_number() -> None:
    """A BOM-Link needs the serialNumber of a CycloneDX SBOM, not an SPDX namespace."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex

    with pytest.raises(ValueError, match='needs the serialNumber of its SBOM'):
        cyclonedx.render_vex(vex.Vex())
    with pytest.raises(ValueError, match='needs the serialNumber of a CycloneDX SBOM'):
        cyclonedx.render_vex(vex.Vex(sbom_id='https://spdx.org/spdxdocs/app-1234'))


def test_vex_apply_replaces_existing_entry() -> None:
    """The VEX file is the newer document, so its statement replaces the same CVE
    in the SBOM, at the same position. A statement that matches no package is
    ignored, not an error."""
    from esp_idf_sbom.libsbom import vex

    model = _sbom_with_exclusions()
    document = vex.Vex(
        statements=[
            vex.VexStatement(
                vulnerability='CVE-2020-1',
                status=vex.VexStatus.NOT_AFFECTED,
                products=[vex.VexProduct(ref='COMPONENT-lib')],
                impact_statement='re-checked, still not used',
            ),
            vex.VexStatement(
                vulnerability='CVE-2020-7',
                status=vex.VexStatus.NOT_AFFECTED,
                products=[vex.VexProduct(purl='pkg:github/other/thing@1.0')],
                impact_statement='not in this SBOM',
            ),
        ]
    )

    vex.apply(model, document)
    assert model.packages[1].assessments == [
        vex.VexAssessment(
            vulnerability='CVE-2020-1',
            status=vex.VexStatus.NOT_AFFECTED,
            impact_statement='re-checked, still not used',
        ),
        *_assessments({'cve': 'CVE-2020-2', 'reason': 'not reachable'}),
    ]


def test_parse_sbom_reads_document_id() -> None:
    """Every format must read back the id of the document it was parsed from.
    check needs it to tell whether a CycloneDX VEX belongs to this SBOM."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx

    model = _sbom_with_file()

    doc_id = cyclonedx.new_document_id(model)
    assert cyclonedx.parse(cyclonedx.render(model, doc_id=doc_id)).doc_id == doc_id

    doc_id = spdx.new_document_id(model)
    for fmt in ('tagvalue', 'json', 'json-ld'):
        parsed = spdx.parse(spdx.render(model, format=fmt, version=_SPDX_VERSION[fmt], doc_id=doc_id), format=fmt)
        assert parsed.doc_id == doc_id, fmt


_SPDX_VERSION = {'tagvalue': '2.2', 'json': '2.2', 'json-ld': '3.0.1'}


def _freertos_sbom_and_vex(tmp_path, sbom_format='cyclonedx-json', vex_format='cyclonedx-json'):
    """An SBOM with a CPE the local NVD mirror reports CVEs for, plus a VEX that
    marks one of them not affected. Returns the two file paths."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    cpe = 'cpe:2.3:o:amazon:freertos:10.0.0:*:*:*:*:*:*:*'
    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-freertos']
    )
    comp = Package(
        ref='COMPONENT-freertos',
        name='freertos',
        package_name='freertos',
        kind=PackageKind.COMPONENT,
        version='10.0.0',
        purl='pkg:generic/freertos@10.0.0',
        cpes=[cpe],
        assessments=_assessments({'cve': 'CVE-2021-31571', 'reason': 'evaluated in the VEX file'}),
    )
    model = SBOM(name='app', root='PROJECT-app', packages=[proj, comp])

    backend = cyclonedx if sbom_format == 'cyclonedx-json' else None
    doc_id = cyclonedx.new_document_id(model)
    vexdoc = vex.build(model, sbom_id=doc_id)

    # The SBOM itself is clean, as create --vex-output writes it.
    for pkg in model.packages:
        pkg.assessments = []

    sbom_file = tmp_path / 'app.cdx.json'
    assert backend is not None
    sbom_file.write_text(cyclonedx.render(model, version='1.6', doc_id=doc_id))

    vex_file = tmp_path / 'app.vex.json'
    if vex_format == 'cyclonedx-json':
        vex_file.write_text(cyclonedx.render_vex(vexdoc, version='1.6'))
    else:
        vex_file.write_text(openvex.render_vex(vexdoc))
    return sbom_file, vex_file


def _check_freertos(sbom_file, *extra):
    cmd = [
        sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db', '--format', 'csv',
        *extra, str(sbom_file),
    ]  # fmt: skip
    return run(cmd, capture_output=True, text=True)


def test_check_global_exclusion_for_any_cpe_of_package(tmp_path: Path) -> None:
    """A global entry that matches one CPE of a package also excludes a CVE that
    NVD reports under another CPE of the package. NVD lists CVE-2025-27810 for
    Mbed TLS 3.6.2 only under the trustedfirmware vendor name, and check adds that
    CPE to arm:mbed_tls (utils.CPE_ALIASES)."""
    import csv
    import io

    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-mbedtls']
    )
    comp = Package(
        ref='COMPONENT-mbedtls',
        name='mbedtls',
        package_name='mbedtls',
        kind=PackageKind.COMPONENT,
        version='3.6.2',
        cpes=['cpe:2.3:a:arm:mbed_tls:3.6.2:*:*:*:*:*:*:*'],
    )
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(cyclonedx.render(SBOM(name='app', root='PROJECT-app', packages=[proj, comp]), version='1.6'))

    excluded = tmp_path / 'excluded_cves.yaml'
    excluded.write_text(
        dedent(
            """\
            CVE-2025-27810:
              cpes:
                - cpe: cpe:2.3:a:arm:mbed_tls:*:*:*:*:*:*:*:*
                  versionStartIncluding: '3.6.0'
              reason: test reason
            """
        )
    )

    env = {**os.environ, 'SBOM_EXCLUDED_CVES_FILE': str(excluded)}
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db', '--format', 'csv', str(sbom_file)],
        capture_output=True,
        text=True,
        env=env,
    )
    rows = [row for row in csv.DictReader(io.StringIO(p.stdout)) if row['cve_id'] == 'CVE-2025-27810']
    assert [(row['vulnerable'], row['cpe'].split(':')[3]) for row in rows] == [('EXCLUDED', 'trustedfirmware')]


def test_check_vex_affected_wins_over_global_exclusion(tmp_path: Path) -> None:
    """The VEX of the product is newer than excluded_cves.yaml. When it says that a
    CVE affects the package, check reports the CVE, even if a global entry
    excludes it."""
    import csv
    import io

    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    cpe = 'cpe:2.3:a:arm:mbed_tls:3.6.2:*:*:*:*:*:*:*'
    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-mbedtls']
    )
    comp = Package(
        ref='COMPONENT-mbedtls',
        name='mbedtls',
        package_name='mbedtls',
        kind=PackageKind.COMPONENT,
        version='3.6.2',
        cpes=[cpe],
    )
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(cyclonedx.render(SBOM(name='app', root='PROJECT-app', packages=[proj, comp]), version='1.6'))

    excluded = tmp_path / 'excluded_cves.yaml'
    excluded.write_text(
        dedent(
            """\
            CVE-2025-27810:
              cpes:
                - cpe: cpe:2.3:a:arm:mbed_tls:*:*:*:*:*:*:*:*
                  versionStartIncluding: '3.6.0'
              reason: test reason
            """
        )
    )

    statement = vex.VexStatement(
        vulnerability='CVE-2025-27810',
        status=vex.VexStatus.AFFECTED,
        products=[vex.VexProduct(ref='COMPONENT-mbedtls', cpes=[cpe])],
        action_statement='Update to Mbed TLS 3.6.3.',
    )
    vex_file = tmp_path / 'app.openvex.json'
    vex_file.write_text(openvex.render_vex(vex.Vex(statements=[statement])))

    env = {**os.environ, 'SBOM_EXCLUDED_CVES_FILE': str(excluded)}
    cmd = [
        sys.executable, '-m', 'esp_idf_sbom', 'check', '--local-db', '--format', 'csv',
        '--vex', str(vex_file), str(sbom_file),
    ]  # fmt: skip
    p = run(cmd, capture_output=True, text=True, env=env)
    rows = [row for row in csv.DictReader(io.StringIO(p.stdout)) if row['cve_id'] == 'CVE-2025-27810']
    assert [(row['vulnerable'], row['vex_status'], row['vex_action']) for row in rows] == [
        ('YES', 'affected', 'Update to Mbed TLS 3.6.3.')
    ]

    cmd.remove('--format')
    cmd.remove('csv')
    p = run(cmd, capture_output=True, text=True, env={**env, 'COLUMNS': '200'})
    assert 'Update to Mbed TLS 3.6.3.' in p.stdout


def test_check_vex_reports_cve_not_found_by_scan(tmp_path: Path) -> None:
    """NVD may have no CPE data for a CVE yet, so check reports the CVE of every
    statement also when the scan does not find it, without NVD data."""
    import csv
    import io

    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex

    sbom_file, _ = _freertos_sbom_and_vex(tmp_path)
    product = vex.VexProduct(ref='COMPONENT-freertos', purl='pkg:generic/freertos@10.0.0')
    # Mbed TLS CVEs, so the scan of FreeRTOS does not find them.
    statements = [
        vex.VexStatement(
            vulnerability='CVE-2025-27810',
            status=vex.VexStatus.AFFECTED,
            action_statement='Update.',
            products=[product],
        ),
        vex.VexStatement(
            vulnerability='CVE-2025-52496',
            status=vex.VexStatus.NOT_AFFECTED,
            justification=vex.VexJustification.COMPONENT_NOT_PRESENT,
            products=[product],
        ),
        vex.VexStatement(vulnerability='CVE-2025-54764', status=vex.VexStatus.UNDER_INVESTIGATION, products=[product]),
    ]
    vex_file = tmp_path / 'app.openvex.json'
    vex_file.write_text(openvex.render_vex(vex.Vex(statements=statements)))

    p = _check_freertos(sbom_file, '--vex', str(vex_file))
    rows = {row['cve_id']: row for row in csv.DictReader(io.StringIO(p.stdout))}
    assert [(rows[s.vulnerability]['vulnerable'], rows[s.vulnerability]['vex_status']) for s in statements] == [
        ('YES', 'affected'),
        ('EXCLUDED', 'not_affected'),
        ('MAYBE', 'under_investigation'),
    ]
    row = rows['CVE-2025-27810']
    assert (row['status'], row['cvss_base_score'], row['cve_desc'], row['cpe']) == ('', '', '', '')


def test_check_vex_excludes_reported_cve() -> None:
    """The VEX file is the only place the exclusions live once the SBOM is clean,
    so check --vex has to turn a reported CVE into an excluded one."""
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        sbom_file, vex_file = _freertos_sbom_and_vex(tmp_path)

        without = _check_freertos(sbom_file)
        assert re.search(r'YES.+CVE-2021-31571', without.stdout) is not None

        with_vex = _check_freertos(sbom_file, '--vex', str(vex_file))
        assert re.search(r'EXCLUDED.+CVE-2021-31571', with_vex.stdout) is not None
        assert re.search(r'YES.+CVE-2021-31571', with_vex.stdout) is None
        # A CVE the VEX says nothing about is still reported.
        assert re.search(r'YES.+CVE-2021-31572', with_vex.stdout) is not None


def test_check_vex_openvex_matches_by_identity() -> None:
    """An OpenVEX document carries no link to a document, so it is matched to the
    package by PURL and CPE."""
    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        sbom_file, vex_file = _freertos_sbom_and_vex(tmp_path, vex_format='openvex')
        assert 'urn:cdx' not in vex_file.read_text()

        result = _check_freertos(sbom_file, '--vex', str(vex_file))
        assert re.search(r'EXCLUDED.+CVE-2021-31571', result.stdout) is not None


def test_check_vex_rejects_foreign_cyclonedx_vex(tmp_path: Path) -> None:
    """A CycloneDX VEX links to one SBOM by BOM-Link. Using it with another SBOM
    would silence CVEs for components it was never written about."""
    from esp_idf_sbom.libsbom import cyclonedx

    sbom_file, vex_file = _freertos_sbom_and_vex(tmp_path)

    # Same content, but rendered again, so it gets a new serialNumber.
    other = tmp_path / 'other.cdx.json'
    other.write_text(cyclonedx.render(cyclonedx.parse(sbom_file.read_text()), version='1.6'))

    result = _check_freertos(other, '--vex', str(vex_file))
    assert result.returncode != 0
    assert 'belongs to another SBOM' in result.stderr


def test_check_vex_rejects_cyclonedx_vex_with_spdx_sbom(tmp_path: Path) -> None:
    """A CycloneDX VEX links to the serialNumber of a CycloneDX SBOM, so an SPDX
    SBOM is another SBOM."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx

    sbom_file, vex_file = _freertos_sbom_and_vex(tmp_path)
    spdx_file = tmp_path / 'app.spdx'
    spdx_file.write_text(spdx.render(cyclonedx.parse(sbom_file.read_text()), format='tagvalue', version='2.2'))

    result = _check_freertos(spdx_file, '--vex', str(vex_file))
    assert result.returncode != 0
    assert 'belongs to another SBOM' in result.stderr


def test_check_vex_rejects_cyclonedx_vex_without_serial(tmp_path: Path) -> None:
    """serialNumber is optional in CycloneDX, so a valid SBOM may carry none. The
    BOM-Link then has nothing to resolve against."""
    sbom_file, vex_file = _freertos_sbom_and_vex(tmp_path)

    bom = json.loads(sbom_file.read_text())
    del bom['serialNumber']
    no_serial = tmp_path / 'no-serial.cdx.json'
    no_serial.write_text(json.dumps(bom, indent=2))

    result = _check_freertos(no_serial, '--vex', str(vex_file))
    assert result.returncode != 0
    assert 'this SBOM has no id' in result.stderr


_OLD_TIME = '2020-01-01T00:00:00Z'


def _vex_update(*args: str):
    cmd = [sys.executable, '-m', 'esp_idf_sbom', 'vex', 'update', *args]
    return run(cmd, capture_output=True, text=True)


def _vex_assessment(cve: str, status: str, **values):
    from esp_idf_sbom.libsbom import vex

    return vex.VexAssessment(vulnerability=cve, status=vex.VexStatus(status), **values)


def _write_statements(tmp_path: Path, *statements: dict, name: str = 'statements.yaml') -> Path:
    """Write a statements file. Each statement names its package, and the
    statements for the same package are grouped under it."""
    packages: dict = {}
    for statement in statements:
        fields = dict(statement)
        packages.setdefault(fields.pop('package'), []).append(fields)
    path = tmp_path / name
    # JSON is also YAML.
    path.write_text(json.dumps({'packages': [{'package': p, 'vulnerabilities': v} for p, v in packages.items()]}))
    return path


def _vex_update_files(tmp_path: Path, vex_format: str = 'cyclonedx-json', statements=(), embedded=()):
    """A CycloneDX SBOM of an app with FreeRTOS 10.0.0 and a VEX file for it, both
    from 2020. statements are the assessments in the VEX file, embedded are the
    assessments in the SBOM. Returns the two file paths."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    proj = Package(
        ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT, depends_on=['COMPONENT-freertos']
    )
    comp = Package(
        ref='COMPONENT-freertos',
        name='freertos',
        package_name='freertos',
        kind=PackageKind.COMPONENT,
        version='10.0.0',
        purl='pkg:generic/freertos@10.0.0',
        cpes=['cpe:2.3:o:amazon:freertos:10.0.0:*:*:*:*:*:*:*'],
        assessments=list(statements),
    )
    model = SBOM(name='app', root='PROJECT-app', packages=[proj, comp])
    doc_id = cyclonedx.new_document_id(model)
    vexdoc = vex.build(model, sbom_id=doc_id)
    # The statements have no times, so they get the times of the document.
    vexdoc.first_issued = vexdoc.last_updated = _OLD_TIME

    comp.assessments = list(embedded)
    bom = json.loads(cyclonedx.render(model, version='1.6', doc_id=doc_id))
    bom['metadata']['timestamp'] = _OLD_TIME
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(json.dumps(bom, indent=2))

    vex_file = tmp_path / 'app.vex.json'
    backend = cyclonedx if vex_format == 'cyclonedx-json' else openvex
    vex_file.write_text(backend.render_vex(vexdoc))
    return sbom_file, vex_file


def test_vex_update_adds_statement(tmp_path: Path) -> None:
    """A statement about a new CVE becomes a new statement in the VEX document,
    issued now. The document keeps its id and gets the next version. The other
    statement keeps its times."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path, statements=[_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')]
    )
    statements = _write_statements(
        tmp_path,
        {
            'cve': 'CVE-2026-0002',
            'package': 'pkg:generic/freertos@10.0.0',
            'status': 'affected',
            'action': 'Update FreeRTOS.',
        },
    )
    output = tmp_path / 'new.vex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr

    old = json.loads(vex_file.read_text())
    new = json.loads(output.read_text())
    assert new['serialNumber'] == old['serialNumber']
    assert new['version'] == old['version'] + 1
    assert new['externalReferences'] == old['externalReferences']
    now = new['metadata']['timestamp']
    assert now != _OLD_TIME

    kept, added = new['vulnerabilities']
    assert kept == old['vulnerabilities'][0]
    assert added['id'] == 'CVE-2026-0002'
    assert added['analysis']['state'] == 'exploitable'
    assert added['recommendation'] == 'Update FreeRTOS.'
    assert added['analysis']['firstIssued'] == added['analysis']['lastUpdated'] == now


def test_vex_update_adds_an_openvex_statement(tmp_path: Path) -> None:
    """An OpenVEX document keeps the history of a CVE, and a newer statement
    overrides an older one. So a change is a new statement at the end, with the
    current time, and the older statements stay as they are. The document keeps its
    id and the time when it was first issued."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path,
        'openvex',
        statements=[
            _vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='First.'),
            _vex_assessment('CVE-2026-0002', 'not_affected', impact_statement='Second.'),
        ],
    )
    statements = _write_statements(
        tmp_path,
        {
            'cve': 'CVE-2026-0001',
            'package': 'cpe:2.3:o:amazon:freertos:10.0.0:*:*:*:*:*:*:*',
            'status': 'fixed',
            'detail': 'Patched.',
        },
    )
    output = tmp_path / 'new.openvex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr

    old = json.loads(vex_file.read_text())
    new = json.loads(output.read_text())
    assert new['@id'] == old['@id']
    assert new['version'] == 2
    assert new['timestamp'] == _OLD_TIME
    assert new['last_updated'] != _OLD_TIME

    *kept, added = new['statements']
    assert kept == old['statements']
    assert (added['vulnerability']['name'], added['status']) == ('CVE-2026-0001', 'fixed')
    assert added['timestamp'] == added['last_updated'] == new['last_updated']


def test_vex_update_without_change_keeps_the_version(tmp_path: Path) -> None:
    """When nothing changed, the output is the VEX file as it is. A statement that
    repeats a cve-exclude-list entry, as create writes it, is no change, also with
    the response that CycloneDX writes for it."""
    from esp_idf_sbom.libsbom import sbom

    for vex_format in ('cyclonedx-json', 'openvex'):
        sbom_file, vex_file = _vex_update_files(
            tmp_path,
            vex_format,
            statements=[sbom.assessment_from_exclusion({'cve': 'CVE-2026-0001', 'reason': 'Not used.'})],
        )
        statements = _write_statements(
            tmp_path,
            {'cve': 'CVE-2026-0001', 'package': 'COMPONENT-freertos', 'status': 'not_affected', 'detail': 'Not used.'},
        )
        output = tmp_path / 'new.vex.json'
        result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
        assert result.returncode == 0, result.stderr
        assert output.read_text() == vex_file.read_text()


def test_vex_update_response(tmp_path: Path) -> None:
    """CycloneDX writes the response of a statement. OpenVEX cannot keep it, so a
    second update with the same statements file changes nothing."""
    statements = _write_statements(
        tmp_path,
        {
            'cve': 'CVE-2026-0002',
            'package': 'COMPONENT-freertos',
            'status': 'affected',
            'action': 'Update FreeRTOS.',
            'response': ['update'],
        },
    )

    sbom_file, vex_file = _vex_update_files(tmp_path)
    output = tmp_path / 'new.vex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    (added,) = json.loads(output.read_text())['vulnerabilities']
    assert added['analysis']['response'] == ['update']

    sbom_file, vex_file = _vex_update_files(tmp_path, 'openvex')
    first = tmp_path / 'first.openvex.json'
    second = tmp_path / 'second.openvex.json'
    for current, updated in ((vex_file, first), (first, second)):
        result = _vex_update('--vex', str(current), '-o', str(updated), str(sbom_file), str(statements))
        assert result.returncode == 0, result.stderr
    assert json.loads(first.read_text())['version'] == 2
    assert json.loads(second.read_text())['version'] == 2


def test_vex_update_keeps_unknown_cyclonedx_fields(tmp_path: Path) -> None:
    """vex update changes only what the model knows. The other fields stay, in the
    document and in each entry, also in a changed one. An unchanged entry stays as
    it is, also with a state that the model cannot hold."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path,
        statements=[
            _vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.'),
            _vex_assessment('CVE-2026-0002', 'not_affected', impact_statement='Not used.'),
        ],
    )
    bom = json.loads(vex_file.read_text())
    bom['properties'] = [{'name': 'acme:product', 'value': 'Widget'}]
    unchanged, changed = bom['vulnerabilities']
    unchanged['analysis']['state'] = 'false_positive'
    for entry in (unchanged, changed):
        entry['ratings'] = [{'source': {'name': 'NVD'}, 'score': 9.3, 'severity': 'critical', 'method': 'CVSSv4'}]
        entry['properties'] = [{'name': 'acme:ticket', 'value': 'SEC-1 :warning:'}]
    vex_file.write_text(json.dumps(bom, indent=2))

    statements = _write_statements(
        tmp_path,
        {'cve': 'CVE-2026-0002', 'package': 'COMPONENT-freertos', 'status': 'affected', 'action': 'Update FreeRTOS.'},
        {'cve': 'CVE-2026-0003', 'package': 'COMPONENT-freertos', 'status': 'under_investigation'},
    )
    output = tmp_path / 'new.vex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr

    new = json.loads(output.read_text())
    assert new['version'] == 2
    assert new['properties'] == bom['properties']
    first, second, added = new['vulnerabilities']
    assert first == unchanged
    assert (second['ratings'], second['properties']) == (changed['ratings'], changed['properties'])
    assert (second['analysis']['state'], second['recommendation']) == ('exploitable', 'Update FreeRTOS.')
    assert second['analysis']['firstIssued'] == _OLD_TIME
    assert second['analysis']['lastUpdated'] == new['metadata']['timestamp']
    assert (added['id'], added['analysis']['state']) == ('CVE-2026-0003', 'in_triage')


def test_vex_update_keeps_unknown_openvex_fields(tmp_path: Path) -> None:
    """OpenVEX keeps the fields that the model does not know too: a change adds a
    new statement and does not touch the older ones. The new statement has only
    the fields that come from the model."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path,
        'openvex',
        statements=[
            _vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.'),
            _vex_assessment('CVE-2026-0002', 'not_affected', impact_statement='Not used.'),
        ],
    )
    document = json.loads(vex_file.read_text())
    document['role'] = 'Document Creator'
    unchanged, changed = document['statements']
    for entry in (unchanged, changed):
        entry['status_notes'] = 'Checked by the security team :warning:'
    vex_file.write_text(json.dumps(document, indent=2))

    statements = _write_statements(
        tmp_path,
        {'cve': 'CVE-2026-0002', 'package': 'COMPONENT-freertos', 'status': 'affected', 'action': 'Update FreeRTOS.'},
    )
    output = tmp_path / 'new.openvex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr

    new = json.loads(output.read_text())
    assert (new['version'], new['role']) == (2, 'Document Creator')
    *kept, added = new['statements']
    assert kept == [unchanged, changed]
    assert (added['status'], added['action_statement']) == ('affected', 'Update FreeRTOS.')
    assert 'status_notes' not in added and 'impact_statement' not in added


def test_vex_update_moves_a_changed_package_out_of_an_entry(tmp_path: Path) -> None:
    """A CycloneDX entry can name several packages. When the statement for one of
    them changes, that package moves into a copy of the entry, and the other
    packages keep the old statement. When all of them change the same way, the
    entry is written in place. OpenVEX adds a statement instead, see
    test_vex_update_adds_an_openvex_statement_for_changed_packages()."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    def component(name: str, version: str, cpe: str) -> Package:
        return Package(
            ref=f'COMPONENT-{name}',
            name=name,
            package_name=name,
            kind=PackageKind.COMPONENT,
            version=version,
            purl=f'pkg:generic/{name}@{version}',
            cpes=[cpe],
            assessments=[_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')],
        )

    packages = [
        Package(ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT),
        component('freertos', '10.0.0', 'cpe:2.3:o:amazon:freertos:10.0.0:*:*:*:*:*:*:*'),
        component('lwip', '2.2.0', 'cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*'),
    ]
    model = SBOM(name='app', root='PROJECT-app', packages=packages)
    doc_id = cyclonedx.new_document_id(model)
    vexdoc = vex.build(model, sbom_id=doc_id)
    vexdoc.first_issued = vexdoc.last_updated = _OLD_TIME
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(cyclonedx.render(model, version='1.6', doc_id=doc_id))
    document = json.loads(cyclonedx.render_vex(vexdoc))
    # build() wrote one entry for both packages, because they have the same statement.
    (entry,) = document['vulnerabilities']
    entry['notes'] = 'Kept.'
    vex_file = tmp_path / 'app.vex.json'
    vex_file.write_text(json.dumps(document, indent=2))
    output = tmp_path / 'new.vex.json'
    affected = {'cve': 'CVE-2026-0001', 'status': 'affected', 'action': 'Update.'}

    lwip_only = _write_statements(tmp_path, {**affected, 'package': 'COMPONENT-lwip'}, name='lwip.yaml')
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(lwip_only))
    assert result.returncode == 0, result.stderr
    old_entry, new_entry = json.loads(output.read_text())['vulnerabilities']
    assert old_entry['affects'] == entry['affects'][:1]
    assert new_entry['affects'] == entry['affects'][1:]
    assert old_entry['notes'] == new_entry['notes'] == 'Kept.'
    assert (old_entry['analysis']['state'], new_entry['analysis']['state']) == ('not_affected', 'exploitable')

    both = _write_statements(
        tmp_path,
        {**affected, 'package': 'COMPONENT-freertos'},
        {**affected, 'package': 'COMPONENT-lwip'},
        name='both.yaml',
    )
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(both))
    assert result.returncode == 0, result.stderr
    (changed,) = json.loads(output.read_text())['vulnerabilities']
    assert changed['affects'] == entry['affects']
    assert (changed['notes'], changed['analysis']['state']) == ('Kept.', 'exploitable')


def test_vex_update_writes_every_entry_of_a_package(tmp_path: Path) -> None:
    """A CycloneDX file can have two entries for one CVE of a package. Both get the
    new statement, so that they agree afterwards."""
    import copy

    old = [_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')]
    statements = _write_statements(
        tmp_path, {'cve': 'CVE-2026-0001', 'package': 'COMPONENT-freertos', 'status': 'fixed', 'detail': 'Patched.'}
    )
    output = tmp_path / 'new.vex.json'

    sbom_file, vex_file = _vex_update_files(tmp_path, statements=old)
    bom = json.loads(vex_file.read_text())
    second = copy.deepcopy(bom['vulnerabilities'][0])
    second['bom-ref'] += '-second'
    bom['vulnerabilities'].append(second)
    vex_file.write_text(json.dumps(bom, indent=2))
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    assert [v['analysis']['state'] for v in json.loads(output.read_text())['vulnerabilities']] == ['resolved'] * 2


def test_vex_update_keeps_bom_refs_unique(tmp_path: Path) -> None:
    """The entry for FreeRTOS and lwIP is named after FreeRTOS, its first package.
    When FreeRTOS moves into a copy, the copy cannot take that name, so it gets a
    number."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    def component(name: str) -> Package:
        return Package(
            ref=f'COMPONENT-{name}',
            name=name,
            package_name=name,
            kind=PackageKind.COMPONENT,
            version='1.0',
            assessments=[_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')],
        )

    project = Package(ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT)
    model = SBOM(name='app', root='PROJECT-app', packages=[project, component('freertos'), component('lwip')])
    doc_id = cyclonedx.new_document_id(model)
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(cyclonedx.render(model, version='1.6', doc_id=doc_id))
    vex_file = tmp_path / 'app.vex.json'
    vex_file.write_text(cyclonedx.render_vex(vex.build(model, sbom_id=doc_id)))
    statements = _write_statements(
        tmp_path, {'cve': 'CVE-2026-0001', 'package': 'COMPONENT-freertos', 'status': 'fixed'}
    )

    result = _vex_update('--vex', str(vex_file), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    entries = json.loads(result.stdout)['vulnerabilities']
    assert [(entry['bom-ref'], len(entry['affects'])) for entry in entries] == [
        ('vex-COMPONENT-freertos-CVE-2026-0001', 1),
        ('vex-COMPONENT-freertos-CVE-2026-0001-2', 1),
    ]


def test_vex_update_adds_an_openvex_statement_for_changed_packages(tmp_path: Path) -> None:
    """An OpenVEX statement can name several packages. When the statement for one of
    them changes, a new statement names only that package. The old statement stays
    as it is, also its fields that the model does not have."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import openvex
    from esp_idf_sbom.libsbom import vex
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    def component(name: str) -> Package:
        return Package(
            ref=f'COMPONENT-{name}',
            name=name,
            package_name=name,
            kind=PackageKind.COMPONENT,
            version='1.0',
            purl=f'pkg:generic/{name}@1.0',
            assessments=[_vex_assessment('CVE-2026-0001', 'affected', action_statement='Update.')],
        )

    project = Package(ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT)
    model = SBOM(name='app', root='PROJECT-app', packages=[project, component('freertos'), component('lwip')])
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(cyclonedx.render(model, version='1.6'))
    document = json.loads(openvex.render_vex(vex.build(model)))
    # One statement for both packages, which have a purl as their @id.
    (statement,) = document['statements']
    assert [product['@id'] for product in statement['products']] == ['pkg:generic/freertos@1.0', 'pkg:generic/lwip@1.0']
    statement['@id'] = 'urn:uuid:11111111-2222-3333-4444-555555555555'
    statement['version'] = 3
    statement['action_statement_timestamp'] = _OLD_TIME
    vex_file = tmp_path / 'app.openvex.json'
    vex_file.write_text(json.dumps(document, indent=2))
    output = tmp_path / 'new.openvex.json'
    cve = {'cve': 'CVE-2026-0001'}

    # lwIP gets another action.
    lwip = _write_statements(
        tmp_path,
        {**cve, 'package': 'COMPONENT-lwip', 'status': 'affected', 'action': 'Update lwIP.'},
        name='lwip.yaml',
    )
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(lwip))
    assert result.returncode == 0, result.stderr
    old, new = json.loads(output.read_text())['statements']
    assert old == statement
    assert new['products'] == statement['products'][1:]
    assert (new['status'], new['action_statement']) == ('affected', 'Update lwIP.')

    # Both packages change the same way, so one new statement names both.
    not_affected = {**cve, 'status': 'not_affected', 'justification': 'component_not_present'}
    both = _write_statements(
        tmp_path,
        {**not_affected, 'package': 'COMPONENT-freertos'},
        {**not_affected, 'package': 'COMPONENT-lwip'},
        name='both.yaml',
    )
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(both))
    assert result.returncode == 0, result.stderr
    old, new = json.loads(output.read_text())['statements']
    assert old == statement
    assert (new['products'], new['status']) == (statement['products'], 'not_affected')


def test_vex_update_uses_the_newest_openvex_statement(tmp_path: Path) -> None:
    """vex update compares with the newest OpenVEX statement about the CVE of a
    package, also when it is not the last one in the document. The newest is the
    one with the newest timestamp, as in go-vex."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path, 'openvex', statements=[_vex_assessment('CVE-2026-0001', 'affected', action_statement='Update.')]
    )
    document = json.loads(vex_file.read_text())
    (older,) = document['statements']
    older['timestamp'] = '2026-01-01T10:00:00Z'
    newer = {key: value for key, value in older.items() if key != 'action_statement'}
    newer.update(timestamp='2026-02-01T10:00:00Z', status='fixed')
    document['statements'] = [newer, older]
    vex_file.write_text(json.dumps(document, indent=2))
    output = tmp_path / 'new.openvex.json'
    cve = {'cve': 'CVE-2026-0001', 'package': 'COMPONENT-freertos'}

    fixed = _write_statements(tmp_path, {**cve, 'status': 'fixed'}, name='fixed.yaml')
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(fixed))
    assert result.returncode == 0, result.stderr
    assert output.read_text() == vex_file.read_text()

    # The older statement says this, but it is not in effect, so it is added again.
    affected = _write_statements(tmp_path, {**cve, 'status': 'affected', 'action': 'Update.'}, name='affected.yaml')
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(affected))
    assert result.returncode == 0, result.stderr
    *kept, added = json.loads(output.read_text())['statements']
    assert kept == [newer, older]
    assert (added['status'], added['action_statement']) == ('affected', 'Update.')

    # last_updated does not count, so the newer statement stays in effect.
    older['last_updated'] = '2026-03-01T10:00:00Z'
    vex_file.write_text(json.dumps(document, indent=2))
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(fixed))
    assert result.returncode == 0, result.stderr
    assert output.read_text() == vex_file.read_text()


def test_vex_update_ignores_sbom_statements(tmp_path: Path) -> None:
    """A statement in the statements file replaces the statement of the same CVE in
    the VEX file. The statements embedded in the SBOM are not written to the VEX
    document."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path,
        statements=[
            _vex_assessment('CVE-2026-0001', 'affected', action_statement='From the VEX file.'),
            _vex_assessment('CVE-2026-0002', 'affected', action_statement='From the VEX file.'),
        ],
        embedded=[
            _vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='From the SBOM.'),
            _vex_assessment('CVE-2026-0003', 'not_affected', impact_statement='From the SBOM.'),
        ],
    )
    statements = _write_statements(
        tmp_path,
        {
            'cve': 'CVE-2026-0002',
            'package': 'COMPONENT-freertos',
            'status': 'fixed',
            'detail': 'From the statements file.',
        },
    )
    output = tmp_path / 'new.vex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr

    old = {v['id']: v for v in json.loads(vex_file.read_text())['vulnerabilities']}
    vulnerabilities = {v['id']: v for v in json.loads(output.read_text())['vulnerabilities']}
    assert list(vulnerabilities) == ['CVE-2026-0001', 'CVE-2026-0002']
    assert vulnerabilities['CVE-2026-0001'] == old['CVE-2026-0001']
    assert vulnerabilities['CVE-2026-0002']['analysis']['detail'] == 'From the statements file.'
    changed = vulnerabilities['CVE-2026-0002']['analysis']
    assert changed['firstIssued'] == _OLD_TIME != changed['lastUpdated']


def test_vex_update_new_document(tmp_path: Path) -> None:
    """Without --vex, a new VEX document is made from the statements file only. The
    statements embedded in the SBOM are not in it."""
    sbom_file, _ = _vex_update_files(
        tmp_path, embedded=[_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')]
    )
    statements = _write_statements(
        tmp_path, {'cve': 'CVE-2026-0002', 'package': 'freertos', 'status': 'under_investigation'}
    )

    result = _vex_update(str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document['@context'].startswith('https://openvex.dev/')
    assert document['version'] == 1
    (decided,) = document['statements']
    assert decided['vulnerability']['name'] == 'CVE-2026-0002'
    # As in create, the statement has no time of its own, so it has the time of the document.
    assert 'timestamp' not in decided
    assert document['timestamp'] != _OLD_TIME

    result = _vex_update('--format', 'cyclonedx-json', str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    serial = json.loads(sbom_file.read_text())['serialNumber']
    link = json.loads(result.stdout)['externalReferences'][0]['url']
    assert link == 'urn:cdx:' + serial[len('urn:uuid:') :] + '/1'


def test_vex_update_statement_for_several_packages(tmp_path: Path) -> None:
    """A CPE can name two copies of one library. The statement applies to both, with
    a warning, and it is written once for both."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom.sbom import SBOM
    from esp_idf_sbom.libsbom.sbom import Package
    from esp_idf_sbom.libsbom.sbom import PackageKind

    cpe = 'cpe:2.3:a:cjson_project:cjson:1.7.19:*:*:*:*:*:*:*'
    packages = [
        Package(ref='PROJECT-app', name='app', package_name='app', kind=PackageKind.PROJECT),
        Package(
            ref='SUBMODULE-cjson',
            name='cjson',
            package_name='cjson',
            kind=PackageKind.SUBMODULE,
            version='1.7.19',
            cpes=[cpe],
        ),
        Package(
            ref='COMPONENT-espressif__cjson',
            name='espressif__cjson',
            package_name='cjson',
            kind=PackageKind.COMPONENT,
            version='1.7.19',
            cpes=[cpe],
        ),
    ]
    sbom_file = tmp_path / 'app.cdx.json'
    sbom_file.write_text(cyclonedx.render(SBOM(name='app', root='PROJECT-app', packages=packages), version='1.6'))
    statements = _write_statements(
        tmp_path, {'cve': 'CVE-2026-0001', 'package': cpe, 'status': 'affected', 'action': 'Update cJSON.'}
    )

    result = _vex_update(str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    # The packages have no purl, so OpenVEX names both by the same CPE, once and
    # without an @id.
    (statement,) = json.loads(result.stdout)['statements']
    assert statement['products'] == [{'identifiers': {'cpe23': cpe}}]
    assert 'names 2 packages, SUBMODULE-cjson, COMPONENT-espressif__cjson' in result.stderr


def test_vex_update_several_statements_files(tmp_path: Path) -> None:
    """Several statements files can be given, and a later file wins. When a later
    file sets a statement back to what the VEX file says, it is no change."""
    from esp_idf_sbom.libsbom import sbom

    sbom_file, vex_file = _vex_update_files(
        tmp_path, statements=[sbom.assessment_from_exclusion({'cve': 'CVE-2026-0001', 'reason': 'Not used.'})]
    )
    freertos = {'package': 'COMPONENT-freertos'}
    affected = {**freertos, 'cve': 'CVE-2026-0001', 'status': 'affected', 'action': 'Update FreeRTOS.'}
    first = _write_statements(
        tmp_path, affected, {**freertos, 'cve': 'CVE-2026-0002', 'status': 'under_investigation'}, name='first.yaml'
    )
    second = _write_statements(tmp_path, {**freertos, 'cve': 'CVE-2026-0002', 'status': 'fixed'}, name='second.yaml')
    output = tmp_path / 'new.vex.json'
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(first), str(second))
    assert result.returncode == 0, result.stderr
    states = {v['id']: v['analysis']['state'] for v in json.loads(output.read_text())['vulnerabilities']}
    assert states == {'CVE-2026-0001': 'exploitable', 'CVE-2026-0002': 'resolved'}

    change = _write_statements(tmp_path, affected, name='change.yaml')
    back = _write_statements(
        tmp_path,
        {**freertos, 'cve': 'CVE-2026-0001', 'status': 'not_affected', 'detail': 'Not used.'},
        name='back.yaml',
    )
    result = _vex_update('--vex', str(vex_file), '-o', str(output), str(sbom_file), str(change), str(back))
    assert result.returncode == 0, result.stderr
    assert output.read_text() == vex_file.read_text()


def test_vex_update_keeps_statements_for_other_packages(tmp_path: Path) -> None:
    """A VEX file can name packages that are not in the SBOM, for example when it
    covers a whole product line. Their statements stay as they are."""
    sbom_file, vex_file = _vex_update_files(
        tmp_path, 'openvex', statements=[_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')]
    )
    document = json.loads(vex_file.read_text())
    document['statements'][0]['products'] = [
        {'@id': 'pkg:generic/other@1', 'identifiers': {'purl': 'pkg:generic/other@1'}}
    ]
    vex_file.write_text(json.dumps(document))
    statements = _write_statements(tmp_path, {'cve': 'CVE-2026-0002', 'package': 'freertos', 'status': 'fixed'})

    result = _vex_update('--vex', str(vex_file), str(sbom_file), str(statements))
    assert result.returncode == 0, result.stderr
    kept, added = json.loads(result.stdout)['statements']
    assert kept == document['statements'][0]
    assert added['vulnerability']['name'] == 'CVE-2026-0002'


def test_vex_update_errors(tmp_path: Path) -> None:
    """vex update stops when it cannot write a correct VEX document."""
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx

    sbom_file, vex_file = _vex_update_files(
        tmp_path, 'openvex', statements=[_vex_assessment('CVE-2026-0001', 'not_affected', impact_statement='Not used.')]
    )
    statements = _write_statements(tmp_path, {'cve': 'CVE-2026-0002', 'package': 'freertos', 'status': 'fixed'})

    # A statement for a package that is not in the SBOM.
    unknown = _write_statements(
        tmp_path, {'cve': 'CVE-2026-0003', 'package': 'pkg:generic/other@1', 'status': 'fixed'}, name='unknown.yaml'
    )
    result = _vex_update('--vex', str(vex_file), str(sbom_file), str(unknown))
    assert result.returncode != 0
    assert 'CVE-2026-0003: pkg:generic/other@1' in result.stderr

    # A CycloneDX VEX file belongs to one SBOM.
    cdx = tmp_path / 'cdx'
    cdx.mkdir()
    cdx_sbom, cdx_vex = _vex_update_files(cdx)
    bom = json.loads(cdx_sbom.read_text())
    bom['serialNumber'] = 'urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79'
    other_sbom = cdx / 'other.cdx.json'
    other_sbom.write_text(json.dumps(bom))
    result = _vex_update('--vex', str(cdx_vex), str(other_sbom), str(statements))
    assert result.returncode != 0
    assert 'belongs to another SBOM' in result.stderr

    result = _vex_update('--vex', str(vex_file), '--format', 'openvex', str(sbom_file), str(statements))
    assert result.returncode != 0
    assert '--format cannot be used with --vex' in result.stderr

    spdx_file = tmp_path / 'app.spdx'
    spdx_file.write_text(spdx.render(cyclonedx.parse(sbom_file.read_text())))
    result = _vex_update('--format', 'cyclonedx-json', str(spdx_file), str(statements))
    assert result.returncode != 0
    assert 'needs the serialNumber of a CycloneDX SBOM' in result.stderr

    bom = json.loads(sbom_file.read_text())
    del bom['serialNumber']
    no_serial = tmp_path / 'no-serial.cdx.json'
    no_serial.write_text(json.dumps(bom))
    result = _vex_update('--format', 'cyclonedx-json', str(no_serial), str(statements))
    assert result.returncode != 0
    assert 'needs the serialNumber of its SBOM' in result.stderr

    # A statements file belongs to one SBOM, like a VEX file.
    other = _write_statements(
        tmp_path,
        {
            'cve': 'CVE-2026-0002',
            'package': 'urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#COMPONENT-freertos',
            'status': 'fixed',
        },
        name='other.yaml',
    )
    result = _vex_update(str(sbom_file), str(other))
    assert result.returncode != 0
    assert 'belongs to another SBOM' in result.stderr


def test_output_file_kept_on_failure(hello_world_build: Path, tmp_path: Path) -> None:
    """A failing command must not touch the output file. Creating it upfront left
    an empty file behind and destroyed the output of a previous run."""
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    output = tmp_path / 'app.spdx'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '-o', str(output), str(proj_desc_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    before = output.read_text()
    assert before.startswith('# Generated by esp-idf-sbom')

    # --vex-format none writes no separate file, so this run fails after the output file
    # would have been opened.
    failed = run(
        [
            sys.executable,
            '-m',
            'esp_idf_sbom',
            'create',
            '-o',
            str(output),
            '--vex-format',
            'none',
            '--vex-output',
            str(tmp_path / 'vex.json'),
            str(proj_desc_path),
        ],  # fmt: skip
        capture_output=True,
        text=True,
    )
    assert failed.returncode != 0
    assert output.read_text() == before


def test_output_file_creates_parent_directory(hello_world_build: Path, tmp_path: Path) -> None:
    """The output file may name a directory that does not exist yet."""
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    output = tmp_path / 'reports' / 'sub' / 'app.spdx'
    run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', '-o', str(output), str(proj_desc_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.read_text().startswith('# Generated by esp-idf-sbom')


def test_create_vex_output(hello_world_build: Path, tmp_path: Path) -> None:
    """--vex-format with a VEX format writes the assessments to their own document and leaves
    the SBOM clean. The VEX has to carry the exclusions the clean SBOM no longer
    can, which is why both files come out of one run."""
    manifest = hello_world_build / 'main' / 'sbom.yml'
    content = """
              cpe: cpe:2.3:a:espressif:hello_world:1.0:*:*:*:*:*:*:*
              cve-exclude-list:
                - cve: CVE-2020-1234
                  reason: not used in this configuration
              """
    manifest.write_text(dedent(content))
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'

    def create(fmt: str, vex_fmt: str, vex_file: Path) -> str:
        cmd = [
            sys.executable, '-m', 'esp_idf_sbom', 'create',
            '--format', fmt, '--vex-format', vex_fmt, '--vex-output', str(vex_file),
            str(proj_desc_path),
        ]  # fmt: skip
        return run(cmd, check=True, capture_output=True, text=True).stdout

    try:
        # OpenVEX works with the default SPDX 2.2 output, which has no VEX format
        # of its own.
        vex_file = tmp_path / 'app.openvex.json'
        text = create('spdx-tag-value', 'openvex', vex_file)
        assert 'CVE-2020-1234' not in text
        assert 'cve-exclude-list' not in text
        document = json.loads(vex_file.read_text())
        statement = next(s for s in document['statements'] if s['vulnerability']['name'] == 'CVE-2020-1234')
        assert statement['status'] == 'not_affected'
        assert statement['impact_statement'] == 'not used in this configuration'

        # CycloneDX links the VEX back to the SBOM it was written with.
        vex_file = tmp_path / 'app.vex.cdx.json'
        bom = json.loads(create('cyclonedx-json', 'cyclonedx-json', vex_file))
        assert 'vulnerabilities' not in bom
        vex_bom = json.loads(vex_file.read_text())
        link = 'urn:cdx:{}/{}'.format(bom['serialNumber'][len('urn:uuid:') :], bom['version'])
        assert vex_bom['externalReferences'][0]['url'] == link
        affected = next(v for v in vex_bom['vulnerabilities'] if v['id'] == 'CVE-2020-1234')
        assert affected['affects'][0]['ref'].startswith(f'{link}#')
    finally:
        manifest.unlink()


@pytest.mark.parametrize(
    'extra, message',
    [
        # A VEX format writes its own document, so it needs a path.
        (['--vex-format', 'openvex'], '--vex-output is needed'),
        # A VEX that stays in the SBOM has no separate file to name.
        (['--vex-format', 'embed', '--vex-output', 'vex.json'], 'writes no separate file'),
        (['--vex-format', 'none', '--vex-output', 'vex.json'], 'writes no separate file'),
        # Two documents written through two file handles would overwrite each other.
        (['--vex-format', 'openvex', '-o', 'same.json', '--vex-output', 'same.json'], 'same file'),
        # A CycloneDX VEX links by BOM-Link, so it needs a CycloneDX SBOM.
        (['--vex-format', 'cyclonedx-json', '--vex-output', 'vex.json'], 'same format'),
    ],
)
def test_create_vex_option_errors(hello_world_build: Path, tmp_path: Path, extra, message) -> None:
    """Combinations that cannot do what was asked for must fail, not do something
    else quietly."""
    proj_desc_path = hello_world_build / 'build' / 'project_description.json'
    p = run(
        [sys.executable, '-m', 'esp_idf_sbom', 'create', *extra, str(proj_desc_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert p.returncode != 0
    assert message in p.stderr
    assert list(tmp_path.iterdir()) == []


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
            # Spread empty_record so that adding a report field does not break this test.
            **report.empty_record,
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
            **report.empty_record,
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
            **report.empty_record,
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


def test_kev_fields() -> None:
    """CVEs in the CISA KEV catalog are reported, the others have empty kev fields."""
    import io

    from esp_idf_sbom.libsbom import log
    from esp_idf_sbom.libsbom import report

    def nvd_cve(cve_id: str, kev: bool) -> dict:
        cve = {
            'id': cve_id,
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang': 'en', 'value': f'description of {cve_id}'}],
        }
        if kev:
            cve['cisaExploitAdd'] = '2021-12-10'
            cve['cisaVulnerabilityName'] = 'Test Known Exploited Vulnerability'
        return {'cve': cve}

    def record(cve_id: str, kev: bool, pkg: str, exclude: bool = False) -> dict:
        exclude_list = {cve_id: _assessments({'cve': cve_id, 'reason': 'not applicable'})[0]} if exclude else {}
        return report.create_vulnerable_record(
            nvd_cve(cve_id, kev), exclude_list, f'cpe:2.3:a:test:{pkg}:1.0.0:*:*:*:*:*:*:*', '', pkg, '1.0.0'
        )

    in_kev = record('CVE-2023-10001', True, 'kev_package')
    assert in_kev['kev_added'] == '2021-12-10'
    assert in_kev['kev_name'] == 'Test Known Exploited Vulnerability'

    # A CVE outside the catalog has no KEV information.
    not_in_kev = record('CVE-2023-10002', False, 'plain_package')
    assert not_in_kev['kev_added'] == ''
    assert not_in_kev['kev_name'] == ''

    # An already excluded CVE is not counted in the summary, like every other
    # number there, even though its KEV information is kept in the record.
    excluded = record('CVE-2023-10003', True, 'excluded_package', exclude=True)
    assert excluded['vulnerable'] == 'EXCLUDED'
    assert excluded['kev_added'] == '2021-12-10'

    stdout = io.StringIO()
    log.set_console(stdout)
    report.show([in_kev, not_in_kev, excluded], {'format': 'json', 'local_db': False}, 'test_project', '1.0.0')
    kev_summary = json.loads(stdout.getvalue())['cves_summary']['kev']

    assert kev_summary['count'] == 1
    assert kev_summary['cves'] == ['CVE-2023-10001']
    assert kev_summary['packages'] == ['kev_package']


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
    excluded = {'CVE-2020-22283': _assessments({'cve': 'CVE-2020-22283', 'reason': 'fixed'})[0]}
    rec = report.create_vulnerable_record(vuln, excluded, cpe, '', 'lwip', '2.2.0', maybe=True)
    assert rec['vulnerable'] == 'EXCLUDED'


def test_create_vulnerable_record_vex_fields() -> None:
    """A record shows what the VEX says about its CVE. A record without a VEX
    statement leaves the fields empty."""
    from esp_idf_sbom.libsbom import report
    from esp_idf_sbom.libsbom.sbom import VexAssessment
    from esp_idf_sbom.libsbom.vexvalues import VexJustification
    from esp_idf_sbom.libsbom.vexvalues import VexStatus

    cpe = 'cpe:2.3:a:lwip_project:lwip:2.2.0:*:*:*:*:*:*:*'
    vuln = {
        'cve': {
            'id': 'CVE-2020-22283',
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang': 'en', 'value': 'buffer overflow'}],
            'metrics': {},
        }
    }
    fields = ('vex_status', 'vex_justification', 'vex_detail', 'vex_action')

    def record(assessment: VexAssessment) -> tuple:
        rec = report.create_vulnerable_record(vuln, {'CVE-2020-22283': assessment}, cpe, '', 'lwip', '2.2.0')
        return tuple(rec[field] for field in fields)

    affected = VexAssessment(
        vulnerability='CVE-2020-22283',
        status=VexStatus.AFFECTED,
        impact_statement='The product enables PPP.',
        action_statement='Update to lwIP 2.2.1.',
    )
    assert record(affected) == ('affected', '', 'The product enables PPP.', 'Update to lwIP 2.2.1.')
    not_affected = VexAssessment(
        vulnerability='CVE-2020-22283',
        status=VexStatus.NOT_AFFECTED,
        justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT,
    )
    assert record(not_affected) == ('not_affected', 'vulnerable_code_not_present', '', '')

    rec = report.create_vulnerable_record(vuln, {}, cpe, '', 'lwip', '2.2.0')
    assert all(rec[field] == '' for field in fields)


def test_create_vulnerable_record_uses_vex_status() -> None:
    """not_affected and fixed exclude the CVE. A fixed assessment needs no text of
    its own, so the status is the reason. affected confirms a MAYBE match, and
    under_investigation changes nothing."""
    from esp_idf_sbom.libsbom import report
    from esp_idf_sbom.libsbom.sbom import VexAssessment
    from esp_idf_sbom.libsbom.vexvalues import VexJustification
    from esp_idf_sbom.libsbom.vexvalues import VexStatus

    cpe = 'cpe:2.3:a:lwip_project:lwip:-:*:*:*:*:*:*:*'
    vuln = {
        'cve': {
            'id': 'CVE-2020-22283',
            'vulnStatus': 'Analyzed',
            'descriptions': [{'lang': 'en', 'value': 'buffer overflow'}],
            'metrics': {},
        }
    }

    def record(maybe: bool, **fields) -> tuple:
        assessments = {'CVE-2020-22283': VexAssessment(vulnerability='CVE-2020-22283', **fields)}
        rec = report.create_vulnerable_record(vuln, assessments, cpe, '', 'lwip', '2.2.0', maybe=maybe)
        return rec['vulnerable'], rec['exclude_reason']

    not_affected = VexStatus.NOT_AFFECTED
    assert record(False, status=not_affected, impact_statement='not used') == ('EXCLUDED', 'not used')
    justification = VexJustification.COMPONENT_NOT_PRESENT
    assert record(False, status=not_affected, justification=justification) == ('EXCLUDED', 'component_not_present')
    assert record(True, status=VexStatus.FIXED) == ('EXCLUDED', 'fixed')
    assert record(True, status=VexStatus.AFFECTED) == ('YES', '')
    assert record(True, status=VexStatus.UNDER_INVESTIGATION) == ('MAYBE', '')
    assert record(False, status=VexStatus.UNDER_INVESTIGATION) == ('YES', '')


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


def test_is_version_vulnerable_ignores_case() -> None:
    """CPE values are compared without case, as NVD does. The FatFs manifest
    uses version R0.16, while NVD writes r0.16."""
    from esp_idf_sbom.libsbom import nvd

    fatfs = 'cpe:2.3:a:elm-chan:fatfs:{}:*:*:*:*:*:*:*'

    def config(criteria: str, **versions: str) -> dict:
        return {'nodes': [{'cpeMatch': [{'vulnerable': True, 'criteria': criteria, **versions}]}]}

    ranged = fatfs.format('*')
    assert nvd.is_version_vulnerable(
        fatfs.format('R0.16'), config(ranged, versionStartIncluding='r0.15', versionEndIncluding='r0.16')
    )
    assert not nvd.is_version_vulnerable(fatfs.format('R0.16'), config(ranged, versionEndExcluding='r0.16'))
    assert not nvd.is_version_vulnerable(fatfs.format('R0.17'), config(ranged, versionEndIncluding='r0.16'))

    # Without a range, the versions must be equal. Vendor and product are checked too.
    assert nvd.is_version_vulnerable('cpe:2.3:a:ELM-CHAN:FATFS:R0.16:*:*:*:*:*:*:*', config(fatfs.format('r0.16')))


def test_get_cves_for_cpe_ignores_case(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CPE from the SBOM is compared without case, as NVD does."""
    from esp_idf_sbom.libsbom import nvd

    # Data from NVD.
    match = {'vulnerable': True, 'criteria': 'cpe:2.3:a:elm-chan:fatfs:*:*:*:*:*:*:*:*', 'versionEndIncluding': 'r0.16'}
    cve = {'cve': {'id': 'CVE-2026-6682', 'configurations': [{'nodes': [{'cpeMatch': [match]}]}]}}
    monkeypatch.setattr(nvd, 'CVE_CACHE', [cve])

    assert nvd.get_cves_for_cpe('cpe:2.3:a:ELM-CHAN:FATFS:R0.16:*:*:*:*:*:*:*') == [cve]


def test_cpe_product_must_match_in_full(monkeypatch: pytest.MonkeyPatch) -> None:
    """The product name must match in full. 'freertos' must not match 'freertos\\+fat'."""
    from esp_idf_sbom.libsbom import nvd

    def cve(cve_id: str, criteria: str, **versions: str) -> dict:
        match = {'vulnerable': True, 'criteria': criteria, **versions}
        return {'cve': {'id': cve_id, 'configurations': [{'nodes': [{'cpeMatch': [match]}]}]}}

    # Data from NVD. CVE-2019-18178 is for FreeRTOS+FAT, CVE-2024-28115 is for FreeRTOS.
    fat = cve('CVE-2019-18178', 'cpe:2.3:o:amazon:freertos\\+fat:160919a:*:*:*:*:*:*:*')
    kernel = cve('CVE-2024-28115', 'cpe:2.3:o:amazon:freertos:*:*:*:*:*:*:*:*', versionEndExcluding='10.6.2')
    monkeypatch.setattr(nvd, 'CVE_CACHE', [fat, kernel])

    assert nvd.get_cves_for_cpe('cpe:2.3:o:amazon:freertos:10.5.1:*:*:*:*:*:*:*') == [kernel]
    cpe = 'cpe:2.3:o:amazon:freertos:160919a:*:*:*:*:*:*:*'
    assert not nvd.is_version_vulnerable(cpe, fat['cve']['configurations'][0])


def test_validate_excluded_cves_justification(tmp_path: Path) -> None:
    """The validator of excluded_cves.yaml accepts every justification of the
    model, and rejects other values."""
    from esp_idf_sbom.libsbom import vex

    script = Path(__file__).parent / 'validate_excluded_cves.py'
    path = tmp_path / 'excluded_cves.yaml'
    cpes = [{'cpe': 'cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*', 'versionEndExcluding': '2.0'}]

    def validator(entries: dict):
        # YAML can read JSON.
        path.write_text(json.dumps(entries))
        return run([sys.executable, script, path], capture_output=True, text=True)

    entries = {
        f'CVE-2020-{1000 + i}': {'cpes': cpes, 'reason': 'test', 'justification': j.value}
        for i, j in enumerate(vex.VexJustification)
    }
    assert validator(entries).returncode == 0

    entry = {'cpes': cpes, 'reason': 'test', 'justification': 'code_not_present'}
    p = validator({'CVE-2020-1000': entry})
    assert p.returncode == 1
    assert '`justification` must be one of' in p.stderr


def test_assessment_from_exclusion() -> None:
    """A cve-exclude-list entry is a not_affected assessment, and the response is
    always will_not_fix. Other keys are ignored, and an unknown justification is
    skipped."""
    from esp_idf_sbom.libsbom import sbom

    entry = {
        'cve': 'CVE-2020-1',
        'reason': 'not used',
        'justification': 'vulnerable_code_not_present',
        'response': ['update'],
        'other': 'ignored',
    }
    assert sbom.assessment_from_exclusion(entry) == sbom.VexAssessment(
        vulnerability='CVE-2020-1',
        status=sbom.VexStatus.NOT_AFFECTED,
        justification=sbom.VexJustification.VULNERABLE_CODE_NOT_PRESENT,
        response=[sbom.VexResponse.WILL_NOT_FIX],
        impact_statement='not used',
    )

    unknown = sbom.assessment_from_exclusion({'cve': 'CVE-2020-2', 'reason': 'not used', 'justification': 'x'})
    assert unknown.justification is None


def test_spdx_comment_keeps_assessments() -> None:
    """SPDX 2.2 has no VEX fields, so the assessments go into the package comment
    as the cve-exclude-list, in the manifest form. Both SPDX 2.2 formats read
    them back."""
    from esp_idf_sbom.libsbom import spdx

    model = _sbom_with_file()
    model.packages[1].assessments = _assessments(
        {'cve': 'CVE-2020-1', 'reason': 'not used', 'justification': 'vulnerable_code_not_present'},
        {'cve': 'CVE-2020-2', 'reason': 'not reachable'},
    )

    assert 'justification: vulnerable_code_not_present' in spdx.render(model, format='tagvalue', version='2.2')
    for fmt in ('tagvalue', 'json'):
        back = spdx.parse(spdx.render(model, format=fmt, version='2.2'), format=fmt)
        by_ref = {pkg.ref: pkg for pkg in back.packages}
        assert by_ref['COMPONENT-lib'].assessments == model.packages[1].assessments


def test_spdx_comment_has_only_excluded_cves() -> None:
    """Released versions read every cve-exclude-list entry as excluded, so the
    package comment must not get an assessment that says the CVE applies."""
    from esp_idf_sbom.libsbom import spdx
    from esp_idf_sbom.libsbom.sbom import VexAssessment
    from esp_idf_sbom.libsbom.vexvalues import VexStatus

    model = _sbom_with_file()
    model.packages[1].assessments = [
        VexAssessment(vulnerability='CVE-2020-1', status=VexStatus.NOT_AFFECTED, impact_statement='not used'),
        VexAssessment(vulnerability='CVE-2020-2', status=VexStatus.FIXED),
        VexAssessment(vulnerability='CVE-2020-3', status=VexStatus.AFFECTED),
        VexAssessment(vulnerability='CVE-2020-4', status=VexStatus.UNDER_INVESTIGATION),
    ]

    text = spdx.render(model, format='tagvalue', version='2.2')
    assert 'CVE-2020-1' in text
    assert 'CVE-2020-2' in text
    assert 'CVE-2020-3' not in text
    assert 'CVE-2020-4' not in text


def test_merge_excluded_cves(tmp_path: Path) -> None:
    """The assessment of the package wins over the matching entry in
    excluded_cves.yaml, except for a justification that it does not set. A
    global entry is used only when its CPE matches."""
    from esp_idf_sbom.libsbom import nvd
    from esp_idf_sbom.libsbom import sbom

    global_file = tmp_path / 'excluded_cves.yaml'
    global_file.write_text(
        dedent(
            """\
            CVE-2020-1000:
              cpes:
                - cpe: cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*
                  versionEndExcluding: '2.0'
              reason: global reason
              justification: vulnerable_code_not_present
            CVE-2020-1001:
              cpes:
                - cpe: cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*
                  versionEndExcluding: '2.0'
              reason: only global
            """
        )
    )
    nvd.get_excluded_cves(path=str(global_file))

    assessments = _assessments(
        {'cve': 'CVE-2020-1000', 'reason': 'package reason'},
        {'cve': 'CVE-2020-1002', 'reason': 'only package'},
    )

    def expected(*entries: dict) -> dict:
        return {a.vulnerability: a for a in _assessments(*entries)}

    assert sbom.merge_excluded_cves(assessments, ['cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*']) == expected(
        {'cve': 'CVE-2020-1000', 'reason': 'package reason', 'justification': 'vulnerable_code_not_present'},
        {'cve': 'CVE-2020-1001', 'reason': 'only global'},
        {'cve': 'CVE-2020-1002', 'reason': 'only package'},
    )

    # Version 2.0 is out of the range, so nothing comes from the global file.
    assert sbom.merge_excluded_cves(assessments, ['cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*']) == expected(
        {'cve': 'CVE-2020-1000', 'reason': 'package reason'},
        {'cve': 'CVE-2020-1002', 'reason': 'only package'},
    )

    # An affected assessment of the package wins over the global exclusion, and a
    # justification is only for not_affected.
    affected = sbom.VexAssessment(vulnerability='CVE-2020-1000', status=sbom.VexStatus.AFFECTED)
    merged = sbom.merge_excluded_cves([affected], ['cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*'])
    assert merged['CVE-2020-1000'] == affected


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
        'CVE-2026-45160': {'cve': 'CVE-2026-45160', 'reason': 'Fixed on release/v6.0'}
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
        # Unknown keys are ignored, so that a newer version can add keys.
        ({'document': {'author': {'name': 'Organization: A', 'contact': 'a@b.io'}}}, True),
        ({'document': {'supplier': {'name': 'Organization: A', 'contact': 'a@b.io', 'phone': '1'}}}, True),
        # A name alone identifies the entity but gives no way to reach it.
        ({'document': {'supplier': {'name': 'Organization: A'}}}, False),
        # The "Person: "/"Organization: " prefix is required, as for suppliers.
        ({'document': {'supplier': {'name': 'A', 'contact': 'a@b.io'}}}, False),
        ({'document': {'supplier': {'name': 'Organization: A', 'contact': 'nope'}}}, False),
        ({'document': {'supplier': {'name': 'Organization: A', 'url': 'ssh://a.example'}}}, False),
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

    tagvalue = outputs['spdx-tag-value'].read_text()
    assert 'Creator: Organization: Acme Corp (psirt@acme.example)' in tagvalue
    assert 'Creator: Organization: Espressif' not in tagvalue

    graph = json.loads(outputs['spdx-json-ld'].read_text())['@graph']
    creation_info = next(e for e in graph if e.get('type') == 'CreationInfo')
    agent = next(e for e in graph if e.get('name') == 'Acme Corp')
    assert creation_info['createdBy'] == [agent['spdxId']]
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
