# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""Format-neutral SBOM data model for esp-idf-sbom.

esp-idf-sbom gathers package, file and relationship information once into this
model; pluggable backends render it to a concrete SBOM format and parse such a
format back into it. All format-agnostic operations (vulnerability scanning,
dependency filtering) run on this model, so they behave the same regardless of
the format an SBOM was produced in or read from.

An SBOM is a flat set of packages connected by a single relationship,
:attr:`Package.depends_on` (which package requires which), with one package
designated as the document root (:attr:`SBOM.root`). Nesting -- a component
and its subpackages or submodules -- is expressed the same way: the parent
depends on the child. There is deliberately one uniform relationship rather
than a separate containment tree, because that is all the relationship
information an SBOM carries, and it is therefore all that survives a render and
parse round trip.

The model stays purely semantic. Anything specific to a particular output
format -- identifiers, derived fields, placeholder/sentinel values, document
timestamps and namespaces -- is computed by the backend and never stored here.
That separation is what lets a new backend be added without changing the model
or how it is built.
"""

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from license_expression import ExpressionError
from license_expression import get_spdx_licensing

from esp_idf_sbom.libsbom import expr
from esp_idf_sbom.libsbom import git
from esp_idf_sbom.libsbom import log
from esp_idf_sbom.libsbom import mft
from esp_idf_sbom.libsbom import nvd
from esp_idf_sbom.libsbom import utils


class PackageKind(Enum):
    """The role of a package within an ESP-IDF build. Backends map it to their
    own notion of component type or identifier as needed."""

    PROJECT = 'project'
    FRAMEWORK = 'framework'
    TOOLCHAIN = 'toolchain'
    COMPONENT = 'component'
    SUBPACKAGE = 'subpackage'
    SUBMODULE = 'submodule'
    VIRTPACKAGE = 'virtpackage'


def kind_and_name(ref: str) -> Tuple[PackageKind, str]:
    """Recover a package's kind and name from its ref, which follows the
    KIND-name convention the build side emits (e.g. 'COMPONENT-cxx'). An
    unrecognized mark falls back to COMPONENT. Used by the parse backends to
    invert the ref; callers strip any backend-specific prefix (e.g. the SPDX 3.0
    namespace fragment) before passing it in.
    """
    mark, _, name = ref.partition('-')
    try:
        return PackageKind(mark.lower()), name
    except ValueError:
        return PackageKind.COMPONENT, name


@dataclass
class File:
    """A single analyzed file inside a package."""

    path: str  # path relative to the package, e.g. './main/foo.c'
    sha1: str
    sha256: str
    licenses_in_file: Set[str] = field(default_factory=set)
    license_concluded: str = ''
    copyrights: Set[str] = field(default_factory=set)
    contributors: Set[str] = field(default_factory=set)


@dataclass
class Package:
    """A project, framework, toolchain, component, subpackage, submodule or
    virtual package."""

    # --- identity --------------------------------------------------------
    # Stable cross-reference id, unique within the document. Backends use it as
    # their format's package identifier, and it is what ``depends_on`` entries
    # reference. It is computed once at build time so every backend agrees.
    ref: str
    name: str  # raw identifying name (registry key / directory name)
    package_name: str  # display name (manifest name, else CPE product, else derived)
    kind: PackageKind

    # --- core metadata ---------------------------------------------------
    version: str = ''
    description: str = ''
    supplier: str = ''  # empty = unspecified
    originator: str = ''  # empty = unspecified
    download_url: str = ''
    repository: str = ''  # source repository URL
    purl: str = ''
    cpes: List[str] = field(default_factory=list)
    checksum_sha256: str = ''  # SHA-256 of the packaged artifact, when known

    # --- license / copyright --------------------------------------------
    files_analyzed: bool = False  # whether files were collected for this package
    licenses_from_files: Set[str] = field(default_factory=set)  # individual license ids from files
    # Raw concluded/declared license expressions. Stored as sets of facts; the
    # single simplified expression is derived by render and the license report
    # via simplify_licenses().
    licenses_concluded: Set[str] = field(default_factory=set)
    licenses_declared: Set[str] = field(default_factory=set)
    copyrights: Set[str] = field(default_factory=set)

    # --- vulnerability metadata -----------------------------------------
    # CVEs evaluated and found not to apply, each {'cve': ..., 'reason': ...},
    # plus keywords for description-based CVE search. Backends choose how to
    # serialize them.
    cve_exclude_list: List[Dict[str, str]] = field(default_factory=list)
    cve_keywords: List[str] = field(default_factory=list)

    # --- contents and relationships -------------------------------------
    files: List[File] = field(default_factory=list)
    # Refs of the packages this package requires. The single relationship the
    # model carries: it covers both component dependencies and parent->child
    # nesting (a component "depends on" its subpackages and submodules), exactly
    # as the relationship is expressed on the wire.
    depends_on: List[str] = field(default_factory=list)


@dataclass
class SBOM:
    """A whole SBOM: a flat, ordered set of packages plus document metadata.

    Non-deterministic or format-specific document metadata (timestamps,
    namespaces, identifiers) is produced by the backend, not stored here.
    """

    name: str
    root: str  # ref of the top-level (project) package
    creator: str = 'ESP-IDF SBOM builder'
    packages: List[Package] = field(default_factory=list)


# ===========================================================================
# SBOMObject: project_description.json + build artifacts -> SBOM model
#
# This is "path 1": gather package, file and relationship information from a
# built ESP-IDF project and populate the format-neutral model defined above.
#
# It is a direct translation of the gathering logic in libsbom/spdx.py. The
# manifest reading, git remote lookups, file walking/hashing,
# license/copyright/contributor aggregation, the .map linked-libs parsing,
# component filtering and relationship computation are kept verbatim. The only
# thing that changes is the tail of each class: where the old SPDX* classes
# populated tag/value dictionaries (self['PackageName'] = ...) and rendered
# them via dump(), the SBOM* classes here populate Package / File objects.
#
# No SPDX serialization tokens ever enter the model: absent values are '' or an
# empty set (never NOASSERTION), raw strings are stored without <text> wrappers,
# refs carry no SPDXRef- prefix, the package verification code is left for the
# render backend to compute from pkg.files, and the cve-exclude-list is kept
# structured rather than serialized to YAML.
# ===========================================================================


_LICENSING = get_spdx_licensing()


def simplify_licenses(licenses: Set[str]) -> str:
    """Combine a set of SPDX license expressions with AND and return the
    simplified expression. Returns '' when there is nothing to simplify.

    The model stores license expressions as raw sets; render and the license
    report derive the single concluded/declared expression from them here.
    """
    # SPDX-specification-2-2 Appendix IV: order of precedence is +, WITH, AND,
    # OR (OR lowest). Parenthesize each expression so the combined concluded
    # license stays correct.
    exprs = [f'({expr})' for expr in licenses]
    expr = ' AND '.join(exprs)
    parsed = _LICENSING.parse(expr)
    if parsed is None:
        return ''
    return str(parsed.simplify())


class SBOMTags:
    """Base class representing the license/copyright/contributor tags found in
    source files (SPDX-License-Identifier, SPDX-FileCopyrightText,
    SPDX-FileContributor). This is a gathering helper; the tag names it matches
    refer to the input files, not to any output format."""

    # File tags searched for inside scanned source files.
    SPDX_LICENSE_RE = re.compile(r'SPDX-License-Identifier: *(.*)')
    SPDX_COPYRIGHT_RE = re.compile(r'SPDX-FileCopyrightText: *(.*)')
    SPDX_CONTRIBUTOR_RE = re.compile(r'SPDX-FileContributor: *(.*)')
    COPYRIGHT_RE = re.compile(r'([ \d,-]+)(.*)', flags=re.DOTALL)
    # Whole-line comment wrappers that hide tags inside delimiters.
    # Without unwrapping, the trailing delimiter gets captured by the
    # regexes and produces a malformed expression (e.g. "CC-BY-4.0)").
    COMMENT_WRAPPER_REs = [
        # Markdown invisible-comment: [//]: # (CONTENT)
        re.compile(r'^\s*\[//\]:\s*#\s*\((.*)\)\s*$'),
        # HTML/XML: <!-- CONTENT -->
        re.compile(r'^\s*<!--\s*(.*?)\s*-->\s*$'),
        # C / CSS / JS block on a single line: /* CONTENT */
        re.compile(r'^\s*/\*\s*(.*?)\s*\*/\s*$'),
    ]
    # SPDX license parser/validator
    licensing = get_spdx_licensing()

    @classmethod
    def _strip_comment_wrappers(cls, line: str) -> str:
        for rx in cls.COMMENT_WRAPPER_REs:
            m = rx.match(line)
            if m:
                return m.group(1)
        return line

    def simplify_licenses(self, licenses: Set[str]) -> str:
        return simplify_licenses(licenses)

    @staticmethod
    def simplify_copyrights(copyrights: Set[str]) -> Set[str]:
        """Simplify copyright years. If the same copyright is used at
        multiple places with different years, this will unify the years."""

        # Simple dict, where key is a copyright text and value is a list of
        # year ranges.
        copyrights_years: Dict[str, List[List[int]]] = dict()
        # Resulting copyrights with unified/simplified years.
        copyrights_simplified: Set[str] = set()
        for copr in copyrights:
            try:
                match = SBOMTags.COPYRIGHT_RE.match(copr)
                if match is None:
                    raise ValueError

                years = match.group(1).strip()
                text = match.group(2).strip()
                years_ranges = []

                for year in years.split(','):
                    if not year:
                        continue
                    year_nums = [int(y) for y in year.split('-') if y]
                    if len(year_nums) == 1:
                        # Simple year, expand it to a range. For example year 2023
                        # will be expanded to a range 2023-2023. This allows internally
                        # to work with single years and year ranges in a unified way.
                        year_nums = year_nums * 2
                    if len(year_nums) != 2:
                        raise ValueError

                    years_ranges.append(year_nums)

                if not years_ranges:
                    raise ValueError

                if text not in copyrights_years:
                    copyrights_years[text] = []

                copyrights_years[text] += years_ranges

            except ValueError:
                # Copyright does not match expected format, so just add it as it is.
                copyrights_simplified.add(copr)

        for text, ranges in copyrights_years.items():
            # Sort year ranges based on their sizes. Range covering
            # the most years is first.
            ranges.sort(key=lambda x: x[1] - x[0], reverse=True)

            # Remove ranges which are covered by other ranges.
            # For example 2020-2023 will be removed if e.g. 2015-2023 exists.
            ranges_simplified = []
            while ranges:
                cur = ranges.pop()
                for rng in ranges:
                    if rng[0] <= cur[0] and cur[1] <= rng[1]:
                        # Current range is subset of some other range, so remove it.
                        break
                else:
                    ranges_simplified.append(cur)

            # Sort simplified ranges by their starting years.
            ranges_simplified.sort(key=lambda x: x[0])

            # Check if year ranges can be merged. For example 2015-2018
            # and 2018-2023 can be merged into a single 2015-2023 range.
            ranges_merged = []
            cur = ranges_simplified.pop(0)
            while ranges_simplified:
                rng = ranges_simplified.pop(0)
                if rng[0] <= cur[1] + 1:
                    # merge
                    cur = [cur[0], rng[1]]
                else:
                    ranges_merged.append(cur)
                    cur = rng
            else:
                ranges_merged.append(cur)

            ranges_strs = [f'{rng[0]}' if rng[0] == rng[1] else f'{rng[0]}-{rng[1]}' for rng in ranges_merged]
            copyrights_simplified.add('{} {}'.format(', '.join(ranges_strs), text))

        return copyrights_simplified

    def __init__(self) -> None:
        self.licenses: Set[str] = set()
        self.licenses_expressions: Set[str] = set()
        self.licenses_expressions_declared: Set[str] = set()
        self.copyrights: Set[str] = set()
        self.contributors: Set[str] = set()

    def get_license_concluded(self) -> str:
        # SPDX-specification-2-2 Appendix IV: SPDX License Expressions
        # Composite License Expressions
        #   4) Order of Precedence and Parentheses
        #   +, WITH, AND, OR  (OR has lowest precedence)
        # Use parentheses around each found license expression to make
        # sure the concluded license is correct.
        return self.simplify_licenses(self.licenses_expressions)

    def get_license_declared(self) -> str:
        return self.simplify_licenses(self.licenses_expressions_declared)

    def __ior__(self, other):
        # SBOMTags unification.
        self.licenses_expressions |= other.licenses_expressions
        self.licenses_expressions_declared |= other.licenses_expressions_declared
        self.licenses |= other.licenses
        self.copyrights |= other.copyrights
        self.contributors |= other.contributors
        return self


class SBOMFileTags(SBOMTags):
    """SBOMTags found in a single file."""

    def __init__(self, file: str) -> None:
        super().__init__()
        self.path = file

        with open(file) as f:
            # check only first 10 lines
            for i in range(1, 10):
                try:
                    line = f.readline()
                except UnicodeDecodeError:
                    # ignore decode errors, the file may be some binary file
                    continue
                line = self._strip_comment_wrappers(line)
                match = self.SPDX_COPYRIGHT_RE.search(line)
                if match:
                    self.copyrights.add(match.group(1))
                    continue
                match = self.SPDX_CONTRIBUTOR_RE.search(line)
                if match:
                    self.contributors.add(match.group(1))
                    continue
                match = self.SPDX_LICENSE_RE.search(line)
                if match:
                    expr = match.group(1)
                    parsed = None
                    try:
                        parsed = self.licensing.parse(expr, validate=True)
                    except ExpressionError as e:
                        # validate=True can fail for two reasons:
                        #   - syntactic error    -> lenient parse will also fail
                        #   - unknown identifier -> lenient parse succeeds
                        # Try the lenient parse to recover the second case; if it
                        # also fails, the expression is genuinely malformed and we
                        # skip it rather than crash the tool.
                        log.warn(f'License expression "{expr}" found in "{self.path}" is not valid: {e}')
                        try:
                            parsed = self.licensing.parse(expr)
                        except ExpressionError as e2:
                            log.warn(
                                f'License expression "{expr}" found in "{self.path}" '
                                f'could not be parsed, skipping: {e2}'
                            )
                    if parsed is not None:
                        self.licenses_expressions.add(expr)
                        for lic in parsed.objects:
                            self.licenses.add(lic)


class SBOMFilesTags(SBOMTags):
    """Unified tags for a list of files."""

    def __init__(self, files: List[str]) -> None:
        super().__init__()
        self.files = files
        for file in files:
            self |= SBOMFileTags(file)


class SBOMFileObjsTags(SBOMTags):
    """Unified tags collected from already created SBOMFile objects."""

    def __init__(self, files: List['SBOMFile']) -> None:
        super().__init__()
        self.files = files
        for file in files:
            self |= file.tags


class SBOMDirTags(SBOMTags):
    """Unified tags found in the whole directory, except files in exclude_dirs."""

    def __init__(self, path: str, exclude_dirs: Optional[List[str]] = None) -> None:
        super().__init__()
        self.path = path

        for root, dirs, files in utils.pwalk(path, exclude_dirs):
            for fn in files:
                self |= SBOMFileTags(utils.pjoin(root, fn))


class SBOMObject:
    """Base class for all SBOM packages and files. It holds the gathering
    helpers shared by every package kind: manifest reading, version/supplier/purl
    guessing, file walking/hashing and ref sanitization."""

    # ref values may contain only letters, numbers, ., and/or -. Used in
    # sanitize() to derive a valid ref from an arbitrary package name. This is
    # the same constraint SPDXID carries, but the resulting value is the
    # format-neutral ref (no SPDXRef- prefix); a backend prefixes it as needed.
    SANITIZE_RE = re.compile(r'[^0-9a-zA-Z\.\-]')
    # Used to automatically identify Espressif as supplier if package URL or
    # git repository matches.
    ESPRESSIF_RE = re.compile(r'^(\w+://)?(\w+@)?(gitlab\.espressif\.|github.com[:/]espressif/).*')
    # Supplier value for Espressif.
    ESPRESSIF_SUPPLIER = 'Organization: Espressif Systems (Shanghai) CO LTD'
    EMPTY_MANIFEST = {
        'name': '',
        'version': '',
        'repository': '',
        'url': '',
        'cpe': [],
        'purl': '',
        'supplier': '',
        'originator': '',
        'description': '',
        'license': '',
        'copyright': [],
        'hash': '',
        'cve-exclude-list': [],
        'cve-keywords': [],
        'manifests': [],
        'virtpackages': [],
        'if': '',
    }

    # Global dictionary with manifest files referenced in sbom.yml or idf_component.yml
    # manifest files by the "manifests" key. Key is fullpath of destination directory,
    # where the manifest file would be stored, but for some reason it's not possible.
    # Value is full path to the referenced manifest file or embedded manifest dictionary.
    REFERENCED_MANIFESTS: Dict[str, Any] = {}

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any]) -> None:
        self.args = args
        self.proj_desc = proj_desc
        self.tags = SBOMTags()

    def hash_file(self, fn: str, alg: str = 'sha1') -> str:
        """Hash file with requested algorithm"""
        h = hashlib.new(alg)
        with open(fn, 'rb') as f:
            h.update(f.read())
            return h.hexdigest()

    def get_files(self, path: str, exclude_dirs: Optional[List[str]] = None) -> List['SBOMFile']:
        """Return list of SBOMFile objects for files found in path.

        :param path: path to recursively traverse
        :param exclude_dirs: list sub-dirs to skip
        :returns: list of SBOMFile objects for given path
        """
        sbom_files: List[SBOMFile] = []
        # prelpath() resolves symlinks, so a symlink file and its target -- both
        # yielded by the walk (e.g. the toolchain's xtensa-esp-elf-cc -> -gcc, or
        # a license LICENSE -> COPYING) -- collapse to the same relative path.
        # Keep the first and skip the rest so each file is listed once and the
        # per-file SPDXIDs derived from the relative path stay unique.
        seen: Set[str] = set()
        for root, dirs, files in utils.pwalk(path, exclude_dirs):
            for fn in files:
                full = utils.pjoin(root, fn)
                relpath = utils.prelpath(full, path)
                if relpath in seen:
                    continue
                seen.add(relpath)
                sbom_files.append(SBOMFile(self.args, self.proj_desc, full, path))

        return sbom_files

    def is_espressif_path(self, path: str) -> bool:
        """Check if given path is within idf_path as defined in project_description.json."""
        return path.startswith(self.proj_desc['idf_path'])

    def is_espressif_url(self, url: str) -> bool:
        """Check if given URL belongs to Espressif."""
        if self.ESPRESSIF_RE.match(url):
            return True
        else:
            return False

    def guess_version(self, path: str, comp_name: str = '') -> str:
        """Try to find out component/submodule version."""
        if self.args['no_guess']:
            return ''

        if comp_name == 'main':
            # For main component use project_version.
            return self.proj_desc['project_version']  # type: ignore

        elif self.is_espressif_path(path):
            # If in idf_path use git_revision.
            return self.proj_desc['git_revision']  # type: ignore

        else:
            # As last resort try git describe.
            return git.describe(path)

    def guess_supplier(self, path: str, url: str = '', repo: str = '') -> str:
        """Try to find out if supplier can be Espressif based on path, url or repository."""
        if self.args['no_guess']:
            return ''

        if self.is_espressif_url(url) or self.is_espressif_url(repo) or self.is_espressif_path(path):
            return self.ESPRESSIF_SUPPLIER
        else:
            return ''

    def update_manifest(self, dst: Dict[str, Any], src: Dict[str, Any], embedded_path: Optional[str] = None) -> None:
        """Update manifest dict with new values from src."""
        for key, val in src.items():
            if key not in dst:
                continue
            if not dst[key]:
                dst[key] = val

        if not embedded_path:
            return

        # For embedded manifests, maintain a record of their origin in the
        # private _embedded_path key. This is used during manifest validation
        # to identify its exact source.
        if 'manifests' in src:
            dst['_embeded_path'] = embedded_path

    def get_manifest(self, directory: str) -> Dict[str, Any]:
        """Return manifest information found in given directory."""

        # Set default/empty manifest values
        manifest = self.EMPTY_MANIFEST.copy()

        if directory in self.REFERENCED_MANIFESTS:
            sbom_src = self.REFERENCED_MANIFESTS[directory]
            if isinstance(sbom_src, str):
                sbom_yml = mft.load(sbom_src)
                sbom_path = sbom_src
            else:
                sbom_yml = sbom_src
                sbom_path = sbom_src['_embeded_path']

            mft.validate(sbom_yml, sbom_path, directory)
            self.update_manifest(manifest, sbom_yml, sbom_path)

        # Process sbom.yml manifest
        sbom_path = utils.pjoin(directory, 'sbom.yml')
        sbom_yml = mft.load(sbom_path)
        mft.validate(sbom_yml, sbom_path, directory)
        self.update_manifest(manifest, sbom_yml, sbom_path)

        # Process idf_component.yml manifest
        sbom_path = utils.pjoin(directory, 'idf_component.yml')
        idf_component_yml = mft.load(sbom_path)

        # idf_component.yml may contains special sbom section
        idf_component_sbom = idf_component_yml.get('sbom', dict())
        mft.fix(idf_component_sbom)
        mft.validate(idf_component_sbom, sbom_path, directory)
        self.update_manifest(manifest, idf_component_sbom, sbom_path)

        # try to fill missing info dirrectly from idf_component.yml
        self.update_manifest(manifest, idf_component_yml, sbom_path)

        if not manifest['supplier']:
            # Supplier not explicitly provided, use maintainers if present.
            if 'maintainers' in idf_component_yml and idf_component_yml['maintainers']:
                manifest['supplier'] = 'Person: ' + ', '.join(idf_component_yml['maintainers'])

        return manifest

    def include_files(self, repo: Optional[str] = None, url: Optional[str] = None, ver: Optional[str] = None) -> bool:
        """Check if package files should be included or not, based on user's
        preference or auto decide based on repo or url and version.
        """

        if self.args['files'] == 'add':
            return True
        elif self.args['files'] == 'rem':
            return False

        # Include files only if there is no reference to URL+version or git repository.
        if repo:
            return False
        elif url and ver:
            return False

        return True

    def sanitize(self, name: str) -> str:
        """Sanitize a name into a valid ref fragment: it should contain only
        letters, numbers, ., and/or -.
        """
        return self.SANITIZE_RE.sub('-', name)


class SBOMPackage(SBOMObject):
    """Base class for all SBOM packages: project, framework, toolchain,
    component, subpackage, virtpackage, submodule. It implements basic
    functionality, which may be customized by overriding selected methods.
    get_subpackages:   Build subpackages, virtpackages and submodules. If a
                       package cannot have any (e.g. toolchain or project) it
                       returns an empty list.
    get_manifest:      Return the manifest for a given package. For example, a
                       package may have manifest information in the .gitmodules
                       file, which needs to be transformed.
    add_relationships: Record the package's depends_on edges. For example the
                       project adds its own edges based on the component list.
    get_files:         Build SBOMFile objects for files included in the
                       package. For example the project contains only the final
                       bin file.
    get_tags:          Build a SBOMTags object for the package. For example the
                       project gathers tags from components and their
                       subpackages/submodules.
    include_package:   Return True if the package should be included in the
                       SBOM. Used for evaluating "if" expressions in manifest
                       files. Certain packages, such as project and component
                       packages, cannot be excluded.
    """

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any], path: str, name: str, mark: str):
        super().__init__(args, proj_desc)
        self.name = name
        self.mark = mark
        self.dir = path
        self.include = True
        self.args = args

        # Stable ref derived once so every relationship edge agrees on it.
        self.ref = f'{self.mark.upper()}-{self.sanitize(self.name)}'
        # Populated in the tail below; stays None for excluded packages.
        self.package: Optional[Package] = None

        self.subpackages: List[SBOMPackage] = []
        self.files: List[SBOMFile] = []
        self.tags: SBOMTags = SBOMTags()

        self.manifest = self.get_manifest(self.dir)

        if not self.include_package():
            self.include = False
            return

        if not self.manifest['version']:
            self.manifest['version'] = self.guess_version(self.dir, self.name)

        if not self.manifest['repository']:
            self.manifest['repository'] = git.get_remote_location(self.dir)

        if not self.manifest['supplier']:
            self.manifest['supplier'] = self.guess_supplier(self.dir, self.manifest['url'], self.manifest['repository'])

        if not self.manifest['purl']:
            self.manifest['purl'] = self.guess_purl()

        all_subpackages = self.get_subpackages()
        self.subpackages = [subpkg for subpkg in all_subpackages if subpkg.include]

        # exclude subpackage paths if any
        exclude_dirs = [subpkg.dir for subpkg in all_subpackages]

        self.files = self.get_files(self.dir, exclude_dirs)

        self.tags = self.get_tags(exclude_dirs)

        if self.manifest['copyright']:
            # The model has no separate "declared" channel for copyrights, so
            # merge manifest copyrights into the package copyright set.
            self.tags.copyrights |= set(self.manifest['copyright'])

        if self.manifest['license']:
            # Store license declared in manifest, so we can use it later in
            # the project package.
            self.tags.licenses_expressions_declared |= set([self.manifest['license']])

        cpe_name = None
        if self.manifest['cpe']:
            cpe_name = self.manifest['cpe'][0].split(':')[4]

        # Merge manifest-level cve-exclude-list with globally-applicable exclusions
        # from excluded_cves.yaml for any of this package's CPEs. Manifest entries
        # take precedence over global ones for the same CVE (more specific).
        merged_excludes: Dict[str, str] = {}
        for cpe in self.manifest['cpe']:
            for cve_id, reason in nvd.get_excluded_cves_for_cpe(cpe).items():
                merged_excludes.setdefault(cve_id, reason)
        for entry in self.manifest['cve-exclude-list']:
            merged_excludes[entry['cve']] = entry['reason']

        # Licenses gathered from files are only meaningful when files were
        # actually collected for the package.
        licenses_from_files: Set[str] = set()
        if self.files:
            licenses_from_files = set(self.tags.licenses)

        self.package = Package(
            ref=self.ref,
            name=self.name,
            package_name=self.manifest['name'] or cpe_name or f'{self.mark}-{self.name}',
            kind=PackageKind(self.mark),
            version=self.manifest['version'],
            description=self.manifest['description'],
            supplier=self.manifest['supplier'],
            originator=self.manifest['originator'],
            download_url=self.manifest['url'],
            repository=self.manifest['repository'],
            purl=self.manifest['purl'],
            cpes=list(self.manifest['cpe']),
            files_analyzed=bool(self.files),
            licenses_from_files=licenses_from_files,
            licenses_concluded=set(self.tags.licenses_expressions),
            licenses_declared=set(self.tags.licenses_expressions_declared),
            copyrights=set(self.tags.copyrights),
            cve_exclude_list=[{'cve': cve_id, 'reason': reason} for cve_id, reason in merged_excludes.items()],
            cve_keywords=list(self.manifest['cve-keywords']),
            files=[f.file for f in self.files],
        )

        self.add_relationships()

    def guess_purl(self) -> str:
        """Try to derive a PURL from the manifest url or repository.

        Tries manifest['url'] first (explicit, maintainer-curated upstream
        URL set in sbom.yml or sbom-url in .gitmodules). If that does not
        yield a PURL -- e.g. a release-asset download URL like the
        toolchain's .../releases/download/.../foo.tar.xz -- falls back to
        manifest['repository'], stripping the @<sha>#<path> suffix that
        get_remote_location() appends.

        The repository fallback is skipped when the auto-filled URL has a
        "#<path>" fragment, which marks the package directory as a
        subdirectory of a parent git repository (typical for in-tree
        wrapper components and the project itself when both live inside
        esp-idf). Without this guard every in-tree wrapper would
        auto-derive the same pkg:github/espressif/esp-idf@<ver> PURL --
        identical lines on dozens of packages add no identification
        information that the per-package repository reference (which retains
        the subpath) doesn't already provide.

        Returns empty string when neither source yields a PURL; the
        caller is then expected to leave manifest['purl'] empty so no
        purl is emitted.
        """
        if self.args['no_guess']:
            return ''

        ver = self.manifest['version']
        purl = utils.derive_purl(self.manifest['url'], ver)
        if purl or not self.manifest['repository']:
            return purl

        # A "#" anywhere in the repository value signals the auto-filled
        # "<URL>@<sha>#<path>" form from get_remote_location() where the
        # package lives inside a parent repo. Skip rather than emit a
        # PURL pointing at the parent.
        if '#' in self.manifest['repository']:
            return ''
        return utils.derive_purl(self.manifest['repository'].split('@', 1)[0], ver)

    def include_package(self) -> bool:
        if self.args['disable_conditions']:
            # Expressions disregarded due to the --disable-conditions command line option.
            return True
        if not self.manifest['if']:
            return True
        return expr.evaluate(self.manifest['if'])

    def add_relationships(self) -> None:
        # Only ever called from __init__ after self.package has been populated.
        assert self.package is not None
        for subpkg in self.subpackages:
            self.package.depends_on.append(subpkg.ref)

    def get_subpackages(self) -> List['SBOMPackage']:
        """Return list of SBOMPackage objects found in package's directory."""

        subpackages: List[SBOMPackage] = []

        # Add referenced manifests into the global list
        for cnt, referenced_manifest in enumerate(self.manifest['manifests']):
            # get full paths to the referenced manifest file and its destination directory
            dest = utils.pjoin(self.dir, referenced_manifest['dest'])
            if 'path' in referenced_manifest:
                # Manifest referenced by file.
                src = utils.pjoin(self.dir, referenced_manifest['path'])
                path = src
            else:
                # Manifest embedded.
                src = referenced_manifest['manifest']
                assert isinstance(src, dict)
                # Get information where exactly this embedded manifest is coming from.
                # See get_manifest and update_manifest functions.
                path = self.manifest['_embeded_path']
                path = f'{path} in embedded manifest {cnt}'
                src['_embeded_path'] = path

            if dest in self.REFERENCED_MANIFESTS:
                existing_src = self.REFERENCED_MANIFESTS[dest]
                if isinstance(existing_src, str):
                    existing_path = existing_src
                else:
                    existing_path = existing_src['_embeded_path']
                log.die(
                    f'Destination "{dest}" for referenced manifest "{path}" already has manifest '
                    f'file "{existing_path}". Two manifest files are referencing same destination.'
                )

            self.REFERENCED_MANIFESTS[dest] = src

        if self.args['rem_submodules'] and self.args['rem_subpackages']:
            return subpackages

        pkg: Optional[SBOMPackage] = None

        for virtpkg in self.manifest['virtpackages']:
            fullpath = utils.pjoin(self.dir, virtpkg)
            name = f'{self.name}-{utils.prelpath(fullpath, self.dir)}'
            pkg = SBOMVirtpackage(self.args, self.proj_desc, fullpath, name)
            subpackages.append(pkg)

        submodules_info: List[Dict[str, str]] = []
        if not self.args['rem_submodules']:
            git_wdir = git.get_gitwdir(self.dir)
            if git_wdir:
                submodules_info = git.submodule_foreach_enum(git_wdir)

        submodules_info_dict = {i['path']: i for i in submodules_info}

        for root, dirs, files in utils.pwalk(self.dir, [self.dir]):
            pkg = None
            # submodules_info_dict is only populated when submodules are kept
            # (not rem_submodules), so membership alone is the right gate here --
            # it must NOT depend on rem_subpackages, which only drops subpackages.
            if root in submodules_info_dict:
                submodule_info = submodules_info_dict[root]
                name = '{}-{}'.format(self.name, utils.prelpath(submodule_info['path'], self.dir))
                pkg = SBOMSubmodule(self.args, self.proj_desc, name, submodule_info)
                dirs.clear()
            elif not self.args['rem_subpackages'] and ('sbom.yml' in files or root in self.REFERENCED_MANIFESTS):
                name = f'{self.name}-{utils.prelpath(root, self.dir)}'
                pkg = SBOMSubpackage(self.args, self.proj_desc, root, name)
                dirs.clear()

            if pkg is not None:
                subpackages.append(pkg)

        return subpackages

    def get_files(self, path: str, exclude_dirs: Optional[List[str]] = None) -> List['SBOMFile']:
        files: List[SBOMFile] = []
        if self.include_files(repo=self.manifest['repository'], url=self.manifest['url'], ver=self.manifest['version']):
            files = super().get_files(path, exclude_dirs)
        return files

    def get_tags(self, exclude_dirs: Optional[List[str]] = None) -> SBOMTags:
        tags: SBOMTags = SBOMTags()

        if not self.args['file_tags']:
            return tags

        if self.files:
            tags = SBOMFileObjsTags(self.files)
        else:
            tags = SBOMDirTags(self.dir, exclude_dirs)
        return tags


class SBOMProject(SBOMPackage):
    """SBOM package representing the project binary."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any]):
        self.args = args
        self.proj_desc = proj_desc

        self._resolve_req_aliases()
        self.linked_libs = self._get_linked_libs()
        self.components = self._get_components()
        self.framework = SBOMFramework(args, proj_desc)
        self.toolchain = SBOMToolchain(args, proj_desc)

        name = proj_desc['project_name']
        path = proj_desc['project_path']
        super().__init__(args, proj_desc, path, name, 'project')

    def _resolve_req_aliases(self) -> None:
        # Component requirements may use aliases (e.g. "idf::fatfs" instead of "fatfs")
        # when specified with the prefix::name syntax in idf_component_register().
        # The build system stores these verbatim in project_description.json, but
        # build_component_info is keyed by plain component names. Normalize all
        # requirement names to plain component names.
        build_components = self.proj_desc['build_component_info']
        alias_map = {}
        for name, info in build_components.items():
            alias = info.get('alias', '')
            if alias and alias != name:
                alias_map[alias] = name

        if not alias_map:
            return

        req_types = ['reqs', 'priv_reqs', 'managed_reqs', 'managed_priv_reqs']
        for info in build_components.values():
            for req_type in req_types:
                info[req_type] = [alias_map.get(r, r) for r in info[req_type]]

    def _remove_components(self, remove: List[str], components: Dict[str, Dict]) -> Dict[str, Dict]:
        # Helper to remove components and dependencies on them from component list.
        def remove_from_reqs(req_type: str, info: Dict):
            info[req_type] = list(set(info[req_type]) - set(remove))

        for comp in remove:
            del components[comp]

        for name, info in components.items():
            for req_type in ['reqs', 'priv_reqs', 'managed_reqs', 'managed_priv_reqs']:
                remove_from_reqs(req_type, info)

        return components

    def _remove_config_only(self, components: Dict[str, Dict]) -> Dict[str, Dict]:
        # Remove configuration only components.
        if not self.args['rem_config']:
            return components

        remove = []
        for name, info in components.items():
            if info['type'] == 'CONFIG_ONLY':
                remove.append(name)

        return self._remove_components(remove, components)

    def _get_linked_libs(self) -> List[str]:
        # Return list of libraries linked to the final binary based on info in linker map file.
        map_file = utils.pjoin(self.proj_desc['build_dir'], self.proj_desc['project_name']) + '.map'

        if not os.path.isfile(map_file):
            log.die(f'file "{map_file}" does not exist, please make sure your project is configured and built')

        with open(map_file) as f:
            lines = f.read().splitlines()

        build_components = self.proj_desc['build_component_info']
        libs = set()
        for line in lines[2:]:
            if not line:
                break
            if line[0].isspace():
                continue
            lib = line.split('(', 1)[0]
            if not os.path.isabs(lib):
                # The archive path in the map file is relative. First, check if
                # any of the build components end with the relative path. If
                # not, simply join it with the build directory.
                for name, info in build_components.items():
                    if info['file'].endswith(lib):
                        lib = info['file']
                        break
                else:
                    lib = utils.pjoin(self.proj_desc['build_dir'], lib)
            libs.add(lib)

        return list(libs)

    def _remove_not_linked(self, components: Dict[str, Dict]) -> Dict[str, Dict]:
        # Remove components not linked into the final binary.
        if not self.args['rem_unused']:
            return components

        remove = []
        for name, info in components.items():
            if info['type'] == 'CONFIG_ONLY':
                continue
            if info['file'] not in self.linked_libs:
                remove.append(name)

        return self._remove_components(remove, components)

    def _filter_components(self, components: Dict[str, Dict]) -> Dict[str, Dict]:
        # Wrapper for all filtering functions.
        components = self._remove_config_only(components)
        components = self._remove_not_linked(components)

        return components

    def _component_used(self, info: Dict) -> bool:
        """Helper to check if component was used as part of the project.
        Configuration only components and components not linked into the final binary
        are considered as not used, unless explicitly requested."""
        # Configuration only component.
        if not self.args['add_config_deps'] and info['type'] == 'CONFIG_ONLY':
            return False
        # Components not linked into final binary.
        if not self.args['add_unused_deps'] and info['type'] == 'LIBRARY' and info['file'] not in self.linked_libs:
            return False

        return True

    def _get_components(self) -> Dict[str, 'SBOMComponent']:
        """Get information about components from project_description.json.
        Components are filtered based on preferences and their dependencies are
        recorded as depends_on edges."""
        build_components = self.proj_desc['build_component_info']
        build_components = self._filter_components(build_components)
        components: Dict[str, SBOMComponent] = {}

        for name, info in build_components.items():
            components[name] = SBOMComponent(self.args, self.proj_desc, name, info)

        for name, info in build_components.items():
            reqs = set(info['reqs'] + info['priv_reqs'] + info['managed_reqs'] + info['managed_priv_reqs'])
            log.debug(f'component {name} requires: {reqs}')
            for req in sorted(reqs):
                try:
                    if not self._component_used(build_components[req]):
                        continue
                except KeyError:
                    # This is a workaround for components that are required by other components, but
                    # are not actually registered. For instance, "esp_phy" might be required by "bt",
                    # but "esp_phy" is not registered as a component on the esp32p4. This situation
                    # can occur in the early stages of new chip support. This should be fixed in
                    # build system by https://github.com/espressif/esp-idf/issues/13447.
                    continue
                # A component excluded from the SBOM (e.g. by an `if` condition) emits no edges.
                package = components[name].package
                if package is not None:
                    package.depends_on.append(components[req].ref)

        return components

    def include_package(self):
        if self.manifest['if']:
            log.warn(
                f'The manifest file for the project "{self.dir}" includes an "if" expression '
                f'that will be disregarded. The project package cannot be excluded.'
            )
        return True

    def get_files(self, path: str, exclude_dirs: Optional[List[str]] = None) -> List['SBOMFile']:
        # project has just the final binary file
        if not self.include_files():
            return []
        fn = utils.pjoin(self.proj_desc['build_dir'], self.proj_desc['app_bin'])
        sbom_file = SBOMFile(self.args, self.proj_desc, fn, self.proj_desc['build_dir'])
        return [sbom_file]

    def get_subpackages(self):
        # There are not subpackages for project
        return []

    def get_manifest(self, path: str) -> Dict[str, str]:
        # Get manifest information and try to fill in missing pieces.
        manifest = super().get_manifest(path)
        if not manifest['version']:
            manifest['version'] = self.proj_desc['project_version']

        return manifest

    def walk_packages(self) -> Iterator[SBOMPackage]:
        def walk_subpackages(subpackages):
            for subpkg in subpackages:
                yield subpkg
                yield from walk_subpackages(subpkg.subpackages)

        for component in self.components.values():
            if not self._component_used(component.info):
                continue
            yield component
            yield from walk_subpackages(component.subpackages)

    def get_tags(self, exclude_dirs: Optional[List[str]] = None) -> SBOMTags:
        # Collect tags from components and subpackages which have a
        # relationship with the project package.
        tags: SBOMTags = SBOMTags()

        for package in self.walk_packages():
            tags |= package.tags
        return tags

    def get_reachable_components(self, names: List[str]) -> Set[str]:
        # Return a set of all components that can be reached directly or
        # indirectly through requirements from the components in the names
        # list, including the names themselves.
        build_components = self.proj_desc['build_component_info']
        reachable = set()
        seen = set()
        todo = set(names)
        while todo:
            name = todo.pop()
            seen.add(name)
            if name not in build_components:
                # A required component may not be registered. For instance, "esp_phy"
                # might be required by "bt", but not registered on the esp32p4. See
                # the similar workaround in _get_components() and
                # https://github.com/espressif/esp-idf/issues/13447.
                continue
            if not self._component_used(build_components[name]):
                continue
            reachable.add(name)
            info = build_components[name]
            reqs = set(info['reqs'] + info['priv_reqs'] + info['managed_reqs'] + info['managed_priv_reqs'])
            todo |= reqs - seen
        return reachable

    def add_relationships(self) -> None:
        assert self.package is not None
        # The project package no longer carries the espressif:esp-idf CPE
        # itself; instead it depends on the dedicated framework package, which
        # owns the application / hardware / firmware CPEs for the ESP-IDF
        # version + target this build was made against. The framework may
        # opt out of being emitted when version.cmake cannot be read; only
        # add the relationship when the package is actually in the SBOM.
        if self.framework.include:
            self.package.depends_on.append(self.framework.ref)

        # Dependency on toolchain if toolchain info is available
        if self.toolchain.info:
            self.package.depends_on.append(self.toolchain.ref)

        # 1. Gather all component requirements into a `requirements set`.
        # 2. Gather components not present in the `requirements set` into the
        #    `project requirements set`.
        # 3. Create a `reachable set` by going through direct and indirect dependencies
        #    reachable from the `project requirements set`.
        # 4. For each component, verify if it is in the `reachable set`. If it is
        #    not, add it to the `project requirements set` and include its direct
        #    and indirect dependencies in the `reachable set`.

        build_components = self.proj_desc['build_component_info']

        reqs: Set[str] = set()
        for name, info in build_components.items():
            if not self._component_used(build_components[name]):
                # Do not include requirements from a component that the project
                # binary did not use, as it might be a transitional component.
                # This means its library is not linked, but its requirements could be.
                # In such cases, we want the requirements to be added as project
                # dependencies if they are not required by any other linked component.
                # This might be an instance of common components. For example, newlib,
                # which is listed under common components, is required for nvs_flash.
                # If nvs_flash is not linked, newlib is not included in the SPDX
                # project package relationships.
                continue
            reqs |= set(info['reqs'] + info['priv_reqs'] + info['managed_reqs'] + info['managed_priv_reqs'])

        # Only components, which are not required by other components are added as direct
        # dependency for the project binary.
        proj_reqs: List[str] = []
        for name, info in build_components.items():
            if name in reqs:
                continue
            if not self._component_used(build_components[name]):
                continue
            proj_reqs.append(name)

        # Get all used components reachable from the immediate project dependencies.
        reachable = self.get_reachable_components(proj_reqs)

        # Ensure that all components included in the project can be reached from the
        # project's package dependency tree. It's possible for a component to be
        # required by another component yet still not be reachable from the project
        # package. This situation can occur if the project doesn't explicitly define
        # its dependencies and instead depends on the build system's current behavior
        # which includes all discovered components in the build. For instance, esp_wifi
        # depends on wpa_supplicant and vice versa, but if the main component doesn't
        # specify a dependency on, say, esp_wifi, neither wpa_supplicant nor esp_wifi
        # will be included in the project package dependencies.
        for name, info in build_components.items():
            if name in reachable:
                continue
            if not self._component_used(build_components[name]):
                continue
            # The component is not reachable, so include it as a direct dependency in the
            # project package. Additionally, add all its direct and indirect
            # dependencies into the set of reachable components.
            proj_reqs.append(name)
            reachable |= self.get_reachable_components([name])

        for req in sorted(proj_reqs):
            self.package.depends_on.append(self.components[req].ref)


class SBOMFramework(SBOMPackage):
    """SBOM package representing the ESP-IDF framework itself.

    Emitted as a separate package so the application/project package can depend
    on it instead of carrying the espressif:esp-idf CPE directly. The
    framework's version is read from ``tools/cmake/version.cmake`` inside the
    IDF tree (so it matches what NVD has registered, e.g. ``6.1.0`` rather than
    ``git describe`` output); the download location is composed from the IDF
    checkout's git remote and HEAD, so a fork at a non-GitHub location gets
    attributed to the customer's actual repository.

    When the IDF version cannot be read the framework package is omitted
    rather than emitted with empty fields -- matching the manifest-check
    injection path's behavior.
    """

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any]):
        self.proj_desc = proj_desc
        super().__init__(args, proj_desc, proj_desc.get('idf_path', ''), 'esp-idf', 'framework')

    def get_manifest(self, path: str) -> Dict[str, Any]:
        manifest = self.EMPTY_MANIFEST.copy()
        manifest.update(mft.build_idf_framework_manifest(path))
        return manifest

    def include_package(self):
        # Emit the framework package only when version.cmake was read
        # successfully. Otherwise we'd ship a meaningless package with no CPEs
        # for the project to depend on.
        if not self.manifest.get('version'):
            log.warn(f'cannot read ESP-IDF version from {self.dir}; framework package not added to the SBOM')
            return False
        return True

    def get_subpackages(self):
        return []

    def get_files(self, path: str, exclude_dirs: Optional[List[str]] = None) -> List['SBOMFile']:
        # The framework package is a meta-package; it does not own files.
        return []

    def get_tags(self, exclude_dirs: Optional[List[str]] = None) -> SBOMTags:
        # No files to scan, no tags to aggregate.
        return SBOMTags()

    def add_relationships(self):
        return


class SBOMToolchain(SBOMPackage):
    """SBOM package representing the toolchain."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any]):
        self.proj_desc = proj_desc
        self.info = self._get_toolchain_info()
        if self.info:
            name = self.info['name']
            super().__init__(args, proj_desc, self.info['path'], name, 'toolchain')
            # tools.json carries the SHA256 of the toolchain release tarball.
            # Record it so the SBOM pins the exact binary used to build the
            # firmware, independent of --files add (which would hash files
            # unpacked on disk rather than the distributed artifact). Important
            # for CRA/SLSA-style provenance: identifies "the compiler that built
            # this", not just "some version named X".
            if self.include and self.info.get('sha256'):
                assert self.package is not None
                self.package.checksum_sha256 = self.info['sha256']
        else:
            log.warn(
                'The toolchain cannot be identified and will not be included '
                'in the generated SBOM. This is most likely due to the toolchain '
                'not being installed with the ESP-IDF.'
            )

    def get_manifest(self, path: str) -> Dict[str, Any]:
        # create manifest based on info from toolchain
        manifest = self.EMPTY_MANIFEST.copy()
        if self.info:  # make mypy happy, because this method will not be called if self.info in None
            manifest['description'] = self.info['description']
            manifest['url'] = self.info['url']
            # info_url points at the toolchain's upstream repository (e.g.
            # https://github.com/espressif/crosstool-NG for xtensa-esp-elf)
            # and is suitable input for PURL derivation. info['url'] is the
            # release-asset download URL (.../releases/download/...) which
            # is the right download location but does not match the
            # PURL "owner/repo" shape.
            manifest['repository'] = self.info.get('info_url', '')
            manifest['version'] = self.info['version']
            manifest['supplier'] = self.ESPRESSIF_SUPPLIER
        return manifest

    def include_package(self):
        # The toolchain package cannot be excluded using an "if" expression in the manifest file.
        return True

    def get_subpackages(self):
        # There are not subpackages for toolchain
        return []

    def _get_current_platform(self) -> str:
        # Get current platform directly from idf_tools.py.
        idf_tools = utils.pjoin(self.proj_desc['idf_path'], 'tools')
        sys.path.append(idf_tools)
        from idf_tools import CURRENT_PLATFORM

        return str(CURRENT_PLATFORM)

    def _get_toolchain_info(self) -> Optional[Dict[str, str]]:
        # Get toolchain info from idf tools.json file.
        info: Dict[str, str] = {}

        # Get toolchain name and version from the full c_compiler path.
        compiler_path_components = utils.psplit(self.proj_desc['c_compiler'])
        try:
            name = compiler_path_components[-5]
            version = compiler_path_components[-4]
        except IndexError:
            compiler_path = self.proj_desc['c_compiler']
            log.warn(f'cannot identify toolchain from compiler path "{compiler_path}"')
            return None
        platform = self._get_current_platform()
        tools_fn = utils.pjoin(self.proj_desc['idf_path'], 'tools', 'tools.json')
        try:
            with open(tools_fn) as f:
                tools = json.load(f)
        except (OSError, ValueError) as e:
            log.warn(f'cannot read idf tools description file: {e}')
            return None

        log.debug('toolchain: tools.json:')
        log.debug(json.dumps(tools, indent=4))

        # Get toolchain info based on name found in compiler's path.
        tool_info = next((t for t in tools['tools'] if t['name'] == name), None)
        if not tool_info:
            log.warn(f'cannot find "{name}" tool in "{tools_fn}"')
            return None

        # Get tool version based on version found in compiler's path.
        tool_version = next((v for v in tool_info['versions'] if v['name'] == version), None)  # type: ignore
        if not tool_version:
            log.warn(f'cannot find "{version}" for "{name}" tool in "{tools_fn}"')
            return None

        if platform not in tool_version:  # type: ignore
            log.warn(f'cannot find "{platform}" platform for "{version}" for "{name}" tool in "{tools_fn}"')
            return None

        info['name'] = name
        info['path'] = utils.pjoin('/', *compiler_path_components[:-4])
        info['version'] = version
        info['platform'] = platform
        info['description'] = tool_info['description']  # type: ignore
        info['info_url'] = tool_info['info_url']  # type: ignore
        info['url'] = tool_version[platform]['url']  # type: ignore
        info['size'] = tool_version[platform]['size']  # type: ignore
        info['sha256'] = tool_version[platform]['sha256']  # type: ignore

        log.debug('toolchain info:')
        log.debug(json.dumps(info, indent=4))

        return info


class SBOMComponent(SBOMPackage):
    """SBOM package representing a component."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any], name: str, info: dict):
        self.info = info
        super().__init__(args, proj_desc, info['dir'], name, 'component')

    def include_package(self):
        if self.manifest['if']:
            log.warn(
                f'The manifest file for the component "{self.dir}" includes an "if" expression '
                f'that will be disregarded. The component package cannot be excluded.'
            )
        return True


class SBOMVirtpackage(SBOMPackage):
    """SBOM package representing a virtual package."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any], path: str, name: str):
        self.manifest_path = path
        super().__init__(args, proj_desc, utils.pdirname(path), name, 'virtpackage')

    def get_manifest(self, directory: str) -> Dict[str, Any]:
        manifest = self.EMPTY_MANIFEST.copy()
        sbom_yml = mft.load(self.manifest_path)
        mft.validate(sbom_yml, self.manifest_path, utils.pdirname(self.manifest_path))
        self.update_manifest(manifest, sbom_yml)
        if len(manifest['manifests']) > 0:
            log.warn(
                f'Disregarding referenced manifests in the virtual package manifest located at {self.manifest_path}'
            )
        return manifest

    def get_subpackages(self):
        # A virtual package cannot have subpackages.
        return []

    def get_files(self, path: str, exclude_dirs: Optional[List[str]] = None) -> List['SBOMFile']:
        # A virtual package cannot have files.
        return []

    def get_tags(self, exclude_dirs: Optional[List[str]] = None) -> SBOMTags:
        # A virtual package cannot include file tags since it lacks any files.
        return SBOMTags()

    def add_relationships(self):
        return


class SBOMSubpackage(SBOMPackage):
    """SBOM package representing a subpackage."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any], path: str, name: str):
        super().__init__(args, proj_desc, path, name, 'subpackage')


class SBOMSubmodule(SBOMPackage):
    """SBOM package representing a submodule."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any], name: str, info: dict):
        self.info = info
        super().__init__(args, proj_desc, info['path'], name, 'submodule')

    def get_manifest(self, directory: str) -> Dict[str, Any]:
        # Convert sbom information from .gitmodule config into expected manifest dictionary
        # and extend already created manifest if it's missing some information.
        manifest = super().get_manifest(directory)

        # Get submodule information form .gitmodules
        module_cfg = git.get_submodule_config(self.info['git_wdir'], self.info['name'])

        # Transform manifest information from variables in gitconfig into manifest dict
        module_sbom = mft.get_submodule_manifest(module_cfg)

        sbom_path = utils.pjoin(self.info['git_wdir'], '.gitmodules')
        mft.validate(module_sbom, f'{sbom_path} submodule {self.info["name"]}', self.info['path'])
        self.update_manifest(manifest, module_sbom)

        return manifest


class SBOMFile(SBOMObject):
    """SBOMObject for a single analyzed file."""

    def __init__(self, args: Dict[str, Any], proj_desc: Dict[str, Any], fn: str, basedir: str):
        super().__init__(args, proj_desc)
        self.path = fn
        self.sha1 = self.hash_file(fn, 'sha1')
        self.sha256 = self.hash_file(fn, 'sha256')
        relpath = utils.prelpath(fn, basedir)

        if args['file_tags']:
            self.tags = SBOMFileTags(self.path)

        # Concluded license is only meaningful when the file actually carried
        # license expressions; otherwise it stays empty.
        license_concluded = ''
        if self.tags.licenses_expressions:
            license_concluded = self.tags.get_license_concluded()

        self.file = File(
            path='./' + relpath,
            sha1=self.sha1,
            sha256=self.sha256,
            licenses_in_file=set(self.tags.licenses),
            license_concluded=license_concluded,
            copyrights=set(self.tags.copyrights),
            contributors=set(self.tags.contributors),
        )


def _read_proj_desc(proj_desc_path: str) -> Dict[str, Any]:
    try:
        with open(proj_desc_path) as f:
            proj_desc = json.load(f)
    except (OSError, ValueError) as e:
        log.die(f'cannot read project description file: {e}')

    if 'version' not in proj_desc:
        log.die(
            f'Project description file "{proj_desc_path}" does not support SBOM generation. '
            f'Please see the list of IDF versions required by esp-idf-sbom.'
        )

    # ESP-IDF built without git and without version.txt (pre-esp-idf#18240)
    # writes git describe's failure marker, e.g. "-128-NOTFOUND", into
    # git_revision. guess_version() uses git_revision as the version of
    # in-tree ESP-IDF components, so recover the real version from the
    # committed tools/cmake/version.cmake instead of propagating the marker.
    git_revision = proj_desc.get('git_revision', '')
    if git_revision.endswith('-NOTFOUND'):
        idf_ver = utils.read_idf_version(proj_desc.get('idf_path', ''))
        if idf_ver:
            log.warn(
                f'ESP-IDF git revision in the project description is "{git_revision}", a git describe '
                f'failure marker from building ESP-IDF without git or version.txt. '
                f'Using "v{idf_ver}" from tools/cmake/version.cmake instead.'
            )
            proj_desc['git_revision'] = f'v{idf_ver}'
        else:
            log.warn(
                f'ESP-IDF git revision in the project description is "{git_revision}" and the version '
                f'could not be read from tools/cmake/version.cmake; ESP-IDF component versions will be omitted.'
            )
            proj_desc['git_revision'] = ''

    return proj_desc  # type: ignore


def _set_expr_variables(proj_desc: Dict[str, Any], args: Dict[str, Any]) -> None:
    sdkconfig_path = utils.pjoin(proj_desc['build_dir'], 'config', 'sdkconfig.json')
    try:
        with open(sdkconfig_path) as f:
            sdkconfig = json.load(f)
    except (OSError, ValueError) as e:
        log.warn(
            f'Unable to read configuration variables from the sdkconfig JSON file: {e}. '
            'Conditional statements in manifest files will not be considered.'
        )
        args['disable_conditions'] = True
    else:
        expr.set_variables(sdkconfig)


def _flatten(pkg: SBOMPackage, out: List[Package]) -> None:
    """Append pkg.package and, depth-first, all of its subpackages to out.

    This matches the order the SPDX render path emits packages in: a package is
    immediately followed by its subpackages/submodules/virtpackages, recursively.
    """
    if pkg.package is not None:
        out.append(pkg.package)
    for subpkg in pkg.subpackages:
        _flatten(subpkg, out)


def build(args: Dict[str, Any], proj_desc_path: str) -> SBOM:
    """Build the format-neutral SBOM model from a built ESP-IDF project.

    Reads project_description.json (plus the manifests, git metadata and build
    artifacts it points at) and returns a populated :class:`SBOM`. The packages
    are flattened into a single ordered list, in the same depth-first order the
    SPDX render path emits them (project, framework, toolchain, then each
    component with its subpackages nested immediately after), connected only by
    :attr:`Package.depends_on`.
    """
    proj_desc = _read_proj_desc(proj_desc_path)
    _set_expr_variables(proj_desc, args)

    # Honor a repository-local excluded_cves.yaml at the ESP-IDF root before any
    # package is built, since package construction bakes the applicable
    # exclusions into Package.cve_exclude_list.
    idf_path = proj_desc.get('idf_path', '')
    if idf_path:
        nvd.merge_local_excluded_cves(idf_path)

    project = SBOMProject(args, proj_desc)

    packages: List[Package] = []
    # Project first (it has no subpackages of its own), then framework and
    # toolchain when present, then every component in build order. Each is
    # expanded depth-first so subpackages follow their parent.
    _flatten(project, packages)
    if project.framework.include:
        _flatten(project.framework, packages)
    if project.toolchain.info:
        _flatten(project.toolchain, packages)
    for component in project.components.values():
        _flatten(component, packages)

    return SBOM(name=proj_desc['project_name'], root=project.ref, packages=packages)


def load(path: str) -> SBOM:
    """Read an SBOM file (or stdin when path is '-'), detect its format and parse
    it into the format-neutral model.

    This is the parse-side entry point, mirroring build() on the gather side.
    """
    if path == '-':
        text = sys.stdin.read()
    else:
        with open(path) as f:
            text = f.read()

    # Late import: the backends import this module, so importing them at module
    # scope would be circular. load() is just a format-sniffing dispatcher.
    from esp_idf_sbom.libsbom import cyclonedx
    from esp_idf_sbom.libsbom import spdx

    # Parse the structure first and dispatch on the top-level keys, rather than
    # substring-matching the raw text (which misroutes a JSON SBOM that merely
    # mentions e.g. "SPDXID:" in a path or description). Tag/value SPDX is the
    # only non-JSON serialization, so it is the fallback.
    try:
        obj = json.loads(text)
    except ValueError:
        obj = None

    if isinstance(obj, dict):
        if 'bomFormat' in obj:
            return cyclonedx.parse(text)
        if 'spdxVersion' in obj:
            return spdx.parse(text, format='json')
        raise ValueError('unrecognized JSON SBOM format')

    if 'SPDXVersion:' in text or 'SPDXID:' in text:
        return spdx.parse(text)
    raise ValueError('unrecognized SBOM format')


@dataclass
class LicenseSummary:
    """Aggregated license/copyright information for a set of packages."""

    license_concluded: str  # single simplified concluded license expression
    licenses: List[str]  # sorted union of concluded + declared license expressions
    copyrights: List[str]  # sorted, optionally year-unified, copyright notices


def app_packages(sbom: SBOM) -> List[Package]:
    """Return the packages used by the application: those reachable from the root
    package by following depends_on, in breadth-first order starting at the root.

    This is how an SBOM is meant to be consumed -- the DESCRIBES root and the
    DEPENDS_ON edges -- so it needs no per-kind special casing. It relies only on
    refs and depends_on, which survive a load(), so it is valid on both built and
    parsed models (unlike summarize_licenses).
    """
    by_ref = {pkg.ref: pkg for pkg in sbom.packages}
    order: List[Package] = []
    seen: Set[str] = set()
    queue = [sbom.root]
    while queue:
        ref = queue.pop(0)
        if ref in seen:
            continue
        seen.add(ref)
        pkg = by_ref.get(ref)
        if pkg is None:
            continue
        order.append(pkg)
        queue.extend(pkg.depends_on)
    return order


def summarize_licenses(packages: List[Package], unify_copyrights: bool = False) -> LicenseSummary:
    """Collect license and copyright information over packages.

    Unions the packages' concluded and declared license expressions and their
    copyrights, then returns the simplified concluded license, the sorted list of
    all license expressions and the sorted copyrights (with copyright years
    unified across notices when unify_copyrights is set).

    Expects packages from a freshly built model (build()). A model from load()
    deliberately recovers no license or copyright data, so summarizing one yields
    an empty result.
    """
    licenses: Set[str] = set()
    copyrights: Set[str] = set()
    for pkg in packages:
        licenses |= pkg.licenses_concluded
        licenses |= pkg.licenses_declared
        copyrights |= pkg.copyrights

    if unify_copyrights:
        copyrights = SBOMTags.simplify_copyrights(copyrights)

    return LicenseSummary(
        license_concluded=simplify_licenses(licenses),
        licenses=sorted(licenses),
        copyrights=sorted(copyrights),
    )
