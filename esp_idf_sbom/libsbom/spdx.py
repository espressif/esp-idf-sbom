# SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0

"""
Module generating SPDX SBOM based on information provided in project_description.json,
manifest files and information from git repository.
"""

import datetime
import hashlib
import json
import os
import re
import sys
import uuid
from argparse import Namespace
from typing import Any, Dict, List, Optional, Set

import yaml
from license_expression import ExpressionError, get_spdx_licensing

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom import git, log, mft, utils


class SPDXTags:
    """Base class representing SPDX tags found in files."""
    # SPDX file tags
    SPDX_LICENSE_RE = re.compile(r'SPDX-License-Identifier: *(.*)')
    SPDX_COPYRIGHT_RE = re.compile(r'SPDX-FileCopyrightText: *(.*)')
    SPDX_CONTRIBUTOR_RE = re.compile(r'SPDX-FileContributor: *(.*)')
    # SPDX license parser/validator
    licensing = get_spdx_licensing()

    def __init__(self) -> None:
        self.licenses: Set[str] = set()
        self.licenses_expressions: Set[str] = set()
        self.copyrights: Set[str] = set()
        self.contributors: Set[str] = set()

    def get_license_concluded(self) -> str:
        # SPDX-specification-2-2 Appendix IV: SPDX License Expressions
        # Composite License Expressions
        #   4) Order of Precedence and Parentheses
        #   +, WITH, AND, OR  (OR has lowest precedence)
        # Use parentheses around each found license expression to make
        # sure the concluded license is correct.
        # Use parentheses around each found license expression to make
        # sure the concluded license is correct.

        exprs = [f'({expr})' for expr in self.licenses_expressions]
        expr = ' AND '.join(exprs)
        parsed = self.licensing.parse(expr)
        return str(parsed.simplify())

    def __ior__(self, other):
        # Tags unification.
        self.licenses_expressions |= other.licenses_expressions
        self.licenses |= other.licenses
        self.copyrights |= other.copyrights
        self.contributors |= other.contributors
        return self


class SPDXFileTags(SPDXTags):
    """SPDX file tags found in single file."""
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
                    try:
                        parsed = self.licensing.parse(expr, validate=True)
                    except ExpressionError as e:
                        log.err.warn(f'License expression "{expr}" found in "{self.path}" is not valid: {e}')
                        parsed = self.licensing.parse(expr)
                    self.licenses_expressions.add(expr)
                    for lic in parsed.objects:
                        self.licenses.add(lic)


class SPDXFilesTags(SPDXTags):
    """Unified SPDX file tags for list of files."""
    def __init__(self, files: List[str]) -> None:
        super().__init__()
        self.files = files
        for file in files:
            self |= SPDXFileTags(file)


class SPDXFileObjsTags(SPDXTags):
    """Unified SPDX file tags collected from already created SPDXFile objects."""
    def __init__(self, files: List['SPDXFile']) -> None:
        super().__init__()
        self.files = files
        for file in files:
            self |= file.tags


class SPDXDirTags(SPDXTags):
    """Unified SPDX file tags found in the whole directory, except file in exclude_dirs."""
    def __init__(self, path: str, exclude_dirs: Optional[List[str]]=None) -> None:
        super().__init__()
        self.path = path

        for root, dirs, files in utils.pwalk(path, exclude_dirs):
            for fn in files:
                self |= SPDXFileTags(utils.pjoin(root, fn))


class SPDXObject:
    """Base class for all SPDX objects, which contains some common methods and helpers.
    It stores the tag/value SPDX data in a simple dictionary, where tag is a key
    and value is stored in a list of values for given tag.
    self[tag]  = [value, ...] # assign new list of value(s) to tag
    self[tag] += [value, ...] # add value(s) to existing tag
    """
    # SPDXID tag value has an requirement that it should contain
    # only letters, numbers, ., and/or -. Used in sanitize_spdxid()
    # to create valid SPDXID value.
    SPDXID_RE = re.compile(r'[^0-9a-zA-Z\.\-\+]')
    SPDX_TAGS = ['SPDXVersion', 'DataLicense', 'SPDXID', 'DocumentName', 'DocumentNamespace',
                 'Creator', 'Created', 'CreatorComment', 'Relationship', 'PackageName', 'PackageSummary',
                 'PackageVersion', 'PackageSupplier', 'PackageOriginator', 'PackageDownloadLocation', 'FilesAnalyzed',
                 'PackageVerificationCode', 'PackageLicenseInfoFromFiles', 'PackageLicenseConcluded',
                 'PackageLicenseDeclared', 'PackageCopyrightText', 'PackageComment', 'FileName',
                 'LicenseInfoInFile', 'FileCopyrightText', 'FileChecksum', 'ExternalRef', 'LicenseConcluded',
                 'FileContributor']
    # Used to automatically identify Espressif as supplier if package URL or
    # git repository matches.
    ESPRESSIF_RE = re.compile(r'^(\w+://)?(\w+@)?(gitlab\.espressif\.|github.com[:/]espressif/).*')
    # Supplier tag value for Espressif.
    ESPRESSIF_SUPPLIER = 'Organization: Espressif Systems (Shanghai) CO LTD'
    EMPTY_MANIFEST = {
        'name': '',
        'version': '',
        'repository': '',
        'url': '',
        'cpe': '',
        'supplier': '',
        'originator': '',
        'description': '',
        'license': '',
        'cve-exclude-list': [],
        'manifests': [],
    }

    # Global dictionary with manifest files referenced in sbom.yml or idf_component.yml
    # manifest files by the "manifests" key. Key is fullpath of destination directory,
    # where the manifest file would be stored, but for some reason it's not possible.
    # Value is full path to the referenced manifest file.
    REFERENCED_MANIFESTS: Dict[str, str] = {}

    def __init__(self, args: Namespace, proj_desc: Dict[str, Any]) -> None:
        self.args = args
        self.proj_desc = proj_desc
        self.spdx: Dict[str, List[str]] = {}
        self.tags = SPDXTags()

    def dump(self, colors=False) -> str:
        """Return SPDX tag/value string representing the SPDX object."""
        out = log.LogString(colors=colors)
        out += ''
        for tag, value in self.spdx.items():
            for v in value:
                out += f'{out.GREEN}{tag}{out.RESET}: {out.YELLOW}{v}{out.RESET}\n'
        return str(out)

    def _check_spdx_tag(self, tag: str) -> None:
        if tag not in self.SPDX_TAGS:
            raise KeyError(f'Key "{tag}" is not supported SPDX tag')

    def __getitem__(self, key: str) -> List[str]:
        # If key doesn't exists return empty list.
        self._check_spdx_tag(key)
        return self.spdx.get(key, [])

    def __setitem__(self, key: str, value: List[str]) -> None:
        self._check_spdx_tag(key)
        self.spdx[key] = value

    # SPDX-specification-2-2 3.2.4
    def sanitize_spdxid(self, spdxid: str) -> str:
        """Sanitize SPDXID value as required by specification. It should contain only
        letters, numbers, ., and/or -.
        """
        return self.SPDXID_RE.sub('-', spdxid)

    # SPDX-specification-2-2 3.9 3.9.4
    def get_verification_code(self, sha1s: list) -> str:
        """Calculate package verification code from file SHA1 values"""
        sha1s_joined = ''.join(sorted(sha1s))
        return hashlib.sha1(sha1s_joined.encode()).hexdigest()

    def hash_file(self, fn: str, alg: str='sha1') -> str:
        """Hash file with requested algorithm"""
        h = hashlib.new(alg)
        with open(fn, 'rb') as f:
            h.update(f.read())
            return h.hexdigest()

    def get_files(self, path: str, prefix: str, exclude_dirs: Optional[List[str]]=None) -> List['SPDXFile']:
        """Return list of SPDXFile objects for files found in path.

        :param path: path to recursively traverse
        :param prefix: prefix to use in SPDXID for files to avoid possible SPDXID collisions
        :param exclude_dirs: list sub-dirs to skip
        :returns: list of SPDXFile objects for given path
        """
        spdx_files: List[SPDXFile] = []
        for root, dirs, files in utils.pwalk(path, exclude_dirs):
            for fn in files:
                spdx_files.append(SPDXFile(self.args, self.proj_desc,
                                           utils.pjoin(root, fn), path, prefix))

        return spdx_files

    def is_espressif_path(self, path: str) -> bool:
        """Check if given path is within idf_path as defined in project_description.json."""
        return path.startswith(self.proj_desc['idf_path'])

    def is_espressif_url(self, url: str) -> bool:
        """Check if given URL belongs to Espressif."""
        if self.ESPRESSIF_RE.match(url):
            return True
        else:
            return False

    def guess_version(self, path: str, comp_name: str='') -> str:
        """Try to find out component/submodule version."""
        if self.args.no_guess:
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

    def guess_supplier(self, path: str, url: str='', repo: str='') -> str:
        """Try to find out if supplier can be Espressif based on path, url or repository."""
        if self.args.no_guess:
            return ''

        if (self.is_espressif_url(url) or
                self.is_espressif_url(repo) or
                self.is_espressif_path(path)):
            return self.ESPRESSIF_SUPPLIER
        else:
            return ''

    def update_manifest(self, dst: Dict[str,Any], src: Dict[str,Any]) -> None:
        """Update manifest dict with new values from src."""
        for key, val in src.items():
            if key not in dst:
                continue
            if not dst[key]:
                dst[key] = val

    def get_manifest(self, directory: str) -> Dict[str,Any]:
        """Return manifest information found in given directory."""

        # Set default/empty manifest values
        manifest = self.EMPTY_MANIFEST.copy()

        if directory in self.REFERENCED_MANIFESTS:
            sbom_path = self.REFERENCED_MANIFESTS[directory]
            sbom_yml = mft.load(sbom_path)
            mft.validate(sbom_yml, sbom_path, directory)
            self.update_manifest(manifest, sbom_yml)

        # Process sbom.yml manifest
        sbom_path = utils.pjoin(directory, 'sbom.yml')
        sbom_yml = mft.load(sbom_path)
        mft.validate(sbom_yml, sbom_path, directory)
        self.update_manifest(manifest, sbom_yml)

        # Process idf_component.yml manifest
        sbom_path = utils.pjoin(directory, 'idf_component.yml')
        idf_component_yml = mft.load(sbom_path)

        # idf_component.yml may contains special sbom section
        idf_component_sbom = idf_component_yml.get('sbom', dict())
        mft.validate(idf_component_sbom, sbom_path, directory)
        self.update_manifest(manifest, idf_component_sbom)

        # try to fill missing info dirrectly from idf_component.yml
        self.update_manifest(manifest, idf_component_yml)

        if not manifest['supplier']:
            # Supplier not explicitly provided, use maintainers if present.
            if 'maintainers' in idf_component_yml and idf_component_yml['maintainers']:
                manifest['supplier'] = 'Person: ' + ', '.join(idf_component_yml['maintainers'])

        return manifest

    def include_files(self,
                      repo: Optional[str] = None,
                      url: Optional[str] = None,
                      ver: Optional[str] = None) -> bool:
        """Check if package files should be included or not, based on user's
        preference or auto decide based on repo or url and version.
        """

        if self.args.files == 'add':
            return True
        elif self.args.files == 'rem':
            return False

        # Include files only if there is no reference to URL+version or git repository.
        if repo:
            return False
        elif url and ver:
            return False

        return True


class SPDXDocument(SPDXObject):
    """Main SPDX Creation Information"""
    def __init__(self, args: Namespace, proj_desc_path: str):
        proj_desc = self._get_proj_desc(proj_desc_path)

        super().__init__(args, proj_desc)

        self.name = self.proj_desc['project_name']
        self.project = SPDXProject(self.args, self.proj_desc)

        ns = 'http://spdx.org/spdxdocs/' + self.name + '-' + str(uuid.uuid4())
        created = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

        self['SPDXVersion'] = ['SPDX-2.2']
        self['DataLicense'] = ['CC0-1.0']
        self['SPDXID'] = ['SPDXRef-DOCUMENT']
        self['DocumentName'] = [self.name]
        self['DocumentNamespace'] = [ns]
        self['Creator'] = ['Tool: ESP-IDF SBOM builder']
        self['Created'] = [created]
        self['CreatorComment'] = [('<text>'
                                   'Draft esp-idf POC SBOM document in SPDX format. '
                                   'Unofficial content for demonstration purposes only.'
                                   '</text>')]
        self['Relationship'] += [f'{self["SPDXID"][0]} DESCRIBES {self.project["SPDXID"][0]}']

    def _get_proj_desc(self, proj_desc_path: str) -> Dict[str, Any]:
        try:
            with open(proj_desc_path, 'r') as f:
                proj_desc = json.load(f)
        except (OSError, ValueError) as e:
            log.err.die(f'cannot read project description file: {e}')

        if 'version' not in proj_desc:
            log.err.die((f'Project description file "{proj_desc_path}" does not support SBOM generation. '
                         f'Please see the list of IDF versions required by esp-idf-sbom.'))

        return proj_desc  # type: ignore

    def dump(self, colors=False) -> str:
        out = log.LogString(colors=colors)
        header = ' '.join('\"' + arg + '\"' if ' ' in arg else arg for arg in sys.argv)
        out.set_color(out.BLUE)
        out += f'# Generated by esp-idf-sbom {__version__} with {header}\n\n'
        out += f'# SPDX document for project {self.name}\n'
        out.reset_color()
        out += super().dump(colors)
        out += '\n'

        out += f'{out.BLUE}# project {self.project.name}{out.RESET}\n'
        out += self.project.dump(colors)

        return str(out)

    def write(self, fn: Optional[str]=None, force_colors=False) -> None:
        """Write full SPDX document to stdout or file."""
        try:
            if fn:
                dirpath = os.path.dirname(fn)
                if dirpath:
                    os.makedirs(dirpath, exist_ok=True)
                fd = open(fn, 'w')
            else:
                fd = sys.stdout  # type: ignore

            colors = not self.args.no_colors
            if colors and not fd.isatty() and not force_colors:
                colors = False

            fd.write(self.dump(colors))
            fd.flush()
        except OSError as e:
            # This also catches BrokenPipeError in case the output is redirected
            # and the receiver is closed. Some additional hardening is probably needed
            # but this works for most of the time.
            # https://docs.python.org/3/library/signal.html#note-on-sigpipe
            log.err.die('cannot write to "{}": {}'.format(fn or 'stdout', e))
        finally:
            if fn:
                fd.close()


class SPDXPackage(SPDXObject):
    """Base class for all SPDX packages: project, toolchain, component, subpackage, submodule.
    It implements basic functionality, which may be customized by overriding selected methods.
    get_subpackages:   Create packages for subpackages and submodules. If package doesn't have
                       any subpackages, e.g. toolchain o project, it may return empty list, so
                       the base class doesn't attempt to find subpackages.
    add_relationships: Add package SPDX relationships. For example project adds its own relationships
                       based on the component list.
    get_files:         Create SPDXFile objects for files included in the package. For example
                       project contains only the final bin file.
    get_tags:          Create SPDXTags object for package. For example project gathers tags from
                       components and thier subpackages/submodules.
    dump:              Print package SPDX representation.
    """

    def __init__(self, args: Namespace, proj_desc: Dict[str, Any],
                 path: str, name: str, mark: str):
        super().__init__(args, proj_desc)
        self.name = name
        self.mark = mark
        self.dir = path

        self.subpackages: List['SPDXPackage'] = []
        self.files: List['SPDXFile'] = []
        self.tags: SPDXTags = SPDXTags()

        self.manifest = self.get_manifest(self.dir)
        if self.manifest['cpe']:
            # CPE may contain version placeholder.
            self.manifest['cpe'] = self.manifest['cpe'].format(self.manifest['version'])

        if not self.manifest['version']:
            self.manifest['version'] = self.guess_version(self.dir, self.name)

        if not self.manifest['repository']:
            self.manifest['repository'] = git.get_remote_location(self.dir)

        if not self.manifest['supplier']:
            self.manifest['supplier'] = self.guess_supplier(self.dir, self.manifest['url'], self.manifest['repository'])

        # Add referenced manifests into the global list
        for referenced_manifest in self.manifest['manifests']:
            # get full paths to the referenced manifest file and its destination directory
            path = utils.pjoin(self.dir, referenced_manifest['path'])
            dest = utils.pjoin(self.dir, referenced_manifest['dest'])
            if dest in self.REFERENCED_MANIFESTS:
                existing_path = self.REFERENCED_MANIFESTS[dest]
                log.err.die((f'Destination "{dest}" for referenced manifest "{path}" already has manifest '
                             f'file "{existing_path}". Two manifest files are referencing same destination.'))

            self.REFERENCED_MANIFESTS[dest] = path

        self.subpackages = self.get_subpackages()

        # exclude subpackage paths if any
        exclude_dirs = [subpkg.dir for subpkg in self.subpackages]

        self.files = self.get_files(self.dir, self.name, exclude_dirs)

        if args.file_tags:
            self.tags = self.get_tags(exclude_dirs)

        cpe_name = None
        if self.manifest['cpe']:
            cpe_name = self.manifest['cpe'].split(':')[4]
        self['PackageName'] = [self.manifest['name'] or cpe_name or f'{self.mark}-{self.name}']
        if self.manifest['description']:
            self['PackageSummary'] = [f'<text>{self.manifest["description"]}</text>']
        self['SPDXID'] = ['SPDXRef-{}-{}'.format(self.mark.upper(), self.sanitize_spdxid(self.name))]
        if self.manifest['version']:
            self['PackageVersion'] = [self.manifest['version']]
        self['PackageSupplier'] = [self.manifest['supplier'] or 'NOASSERTION']
        if self.manifest['originator']:
            self['PackageOriginator'] = [self.manifest['originator']]
        self['PackageDownloadLocation'] = [self.manifest['url'] or 'NOASSERTION']
        if self.files:
            self['FilesAnalyzed'] = ['true']
            self['PackageVerificationCode'] = [self.get_verification_code([f.sha1 for f in self.files])]
            if self.tags.licenses:
                self['PackageLicenseInfoFromFiles'] = list(self.tags.licenses)
            else:
                self['PackageLicenseInfoFromFiles'] = ['NOASSERTION']
        else:
            self['FilesAnalyzed'] = ['false']
        if self.tags.licenses_expressions:
            self['PackageLicenseConcluded'] = [self.tags.get_license_concluded()]
        else:
            self['PackageLicenseConcluded'] = ['NOASSERTION']
        self['PackageLicenseDeclared'] = [self.manifest['license'] or 'NOASSERTION']
        if self.tags.copyrights:
            self['PackageCopyrightText'] = ['<text>{}</text>'.format('\n'.join(self.tags.copyrights))]
        else:
            self['PackageCopyrightText'] = ['NOASSERTION']

        if self.manifest['repository']:
            self['ExternalRef'] += [f'OTHER repository {self.manifest["repository"]}']

        if self.manifest['cpe']:
            self['ExternalRef'] += [f'SECURITY cpe23Type {self.manifest["cpe"]}']

        if self.manifest['cve-exclude-list']:
            cve_info = {'cve-exclude-list': self.manifest['cve-exclude-list']}
            cve_info_yaml = yaml.dump(cve_info, indent=4)
            cve_info_desc = ('# The cve-exclude-list list contains CVEs, which were '
                             'already evaluated and the package is not vulnerable.')
            self['PackageComment'] = [f'<text>\n{cve_info_desc}\n{cve_info_yaml}</text>']

        self.add_relationships()

    def add_relationships(self):
        for subpkg in self.subpackages:
            self['Relationship'] += [f'{self["SPDXID"][0]} DEPENDS_ON {subpkg["SPDXID"][0]}']

    def get_subpackages(self) -> List['SPDXPackage']:
        """Return list of SPDXPackage objects found in package's directory."""

        subpackages: List['SPDXPackage'] = []

        if self.args.rem_submodules and self.args.rem_subpackages:
            return subpackages

        submodules_info: List[Dict[str,str]] = []
        if not self.args.rem_submodules:
            git_wdir = git.get_gitwdir(self.dir)
            if git_wdir:
                submodules_info = git.submodule_foreach_enum(git_wdir)

        submodules_info_dict = {i['path']:i for i in submodules_info}

        for root, dirs, files in utils.pwalk(self.dir, [self.dir]):
            if not self.args.rem_subpackages and root in submodules_info_dict:
                submodule_info = submodules_info_dict[root]
                name = '{}-{}'.format(self.name, utils.prelpath(submodule_info['path'], self.dir))
                subpackages.append(SPDXSubmodule(self.args, self.proj_desc, name, submodule_info))
                dirs.clear()
            elif not self.args.rem_subpackages and ('sbom.yml' in files or root in self.REFERENCED_MANIFESTS):
                name = '{}-{}'.format(self.name, utils.prelpath(root, self.dir))
                subpackages.append(SPDXSubpackage(self.args, self.proj_desc, root, name))
                dirs.clear()

        return subpackages

    def get_files(self, path: str, prefix: str, exclude_dirs: Optional[List[str]]=None) -> List['SPDXFile']:
        files: List['SPDXFile'] = []
        if self.include_files(repo=self.manifest['repository'],
                              url=self.manifest['url'],
                              ver=self.manifest['version']):
            files = super().get_files(path, f'{prefix}-{self.name}', exclude_dirs)
        return files

    def get_tags(self, exclude_dirs: Optional[List[str]]=None) -> SPDXTags:
        tags: SPDXTags = SPDXTags()
        if self.files:
            tags = SPDXFileObjsTags(self.files)
        else:
            tags = SPDXDirTags(self.dir, exclude_dirs)
        return tags

    def dump(self, colors=False) -> str:
        out = log.LogString(colors=colors)
        out += super().dump(colors)

        if self.files:
            out += '\n'
            out += f'{out.BLUE}# {self.name} {self.mark} files{out.RESET}'
            for f in self.files:
                out += '\n'
                out += f.dump(colors)

        for subpkg in self.subpackages:
            out += '\n'
            out += f'{out.BLUE}# {subpkg.name} {subpkg.mark}{out.RESET}\n'
            out += subpkg.dump(colors)

        return str(out)


class SPDXProject(SPDXPackage):
    """SPDX Package Information for the project binary."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any]):
        self.args = args
        self.proj_desc = proj_desc

        self.linked_libs = self._get_linked_libs()
        self.components = self._get_components()
        self.toolchain = SPDXToolchain(args, proj_desc)

        name = proj_desc['project_name']
        path = proj_desc['project_path']
        super().__init__(args, proj_desc, path, name, 'project')

    def _remove_components(self, remove: List[str],
                           components: Dict[str, Dict]) -> Dict[str, Dict]:
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
        if not self.args.rem_config:
            return components

        remove = []
        for name, info in components.items():
            if info['type'] == 'CONFIG_ONLY':
                remove.append(name)

        return self._remove_components(remove, components)

    def _get_linked_libs(self) -> List[str]:
        # Return list of libraries linked to the final binary based on info in linker map file.
        map_file = utils.pjoin(self.proj_desc['build_dir'],
                               self.proj_desc['project_name']) + '.map'

        if not os.path.isfile(map_file):
            log.err.die((f'file "{map_file}" does not exist, please make '
                         f'sure your project is configured and built'))

        with open(map_file, 'r') as f:
            lines = f.read().splitlines()

        libs = set()
        for line in lines[2:]:
            if not line:
                break
            if line[0].isspace():
                continue
            lib = line.split('(',1)[0]
            if not os.path.isabs(lib):
                lib = utils.pjoin(self.proj_desc['build_dir'], lib)
            libs.add(lib)

        return list(libs)

    def _remove_not_linked(self, components: Dict[str, Dict]) -> Dict[str, Dict]:
        # Remove components not linked into the final binary.
        if not self.args.rem_unused:
            return components

        remove = []
        for name, info in components.items():
            if info['type'] == 'CONFIG_ONLY':
                continue
            if not info['file'] in self.linked_libs:
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
        if not self.args.add_config_deps and info['type'] == 'CONFIG_ONLY':
            return False
        # Components not linked into final binary.
        if not self.args.add_unused_deps and info['type'] == 'LIBRARY' and info['file'] not in self.linked_libs:
            return False

        return True

    def _get_components(self) -> Dict[str, 'SPDXComponent']:
        """Get information about components from project_description.json.
        Components are filtered based on preferences and their dependencies linked
        via SPDX Relationship tag."""
        build_components = self.proj_desc['build_component_info']
        build_components = self._filter_components(build_components)
        components: Dict[str, SPDXComponent] = {}

        for name, info in build_components.items():
            components[name] = SPDXComponent(self.args, self.proj_desc, name, info)

        for name, info in build_components.items():
            reqs = set(info['reqs'] + info['priv_reqs'] + info['managed_reqs'] + info['managed_priv_reqs'])
            log.err.debug(f'component {name} requires: {reqs}')
            for req in reqs:
                if not self._component_used(build_components[req]):
                    continue
                components[name]['Relationship'] += [f'{components[name]["SPDXID"][0]} DEPENDS_ON {components[req]["SPDXID"][0]}']

        return components

    def get_files(self, path: str, prefix: str, exclude_dirs: Optional[List[str]]=None) -> List['SPDXFile']:
        # project has just the final binary file
        if not self.include_files():
            return []
        fn = utils.pjoin(self.proj_desc['build_dir'], self.proj_desc['app_bin'])
        file = SPDXFile(self.args, self.proj_desc, fn, self.proj_desc['build_dir'], self.name)
        return [file]

    def get_subpackages(self):
        # There are not subpackages for project
        return []

    def get_manifest(self, path: str) -> Dict[str, str]:
        # Get manifest information and try to fill in missing pieces.
        manifest = super().get_manifest(path)
        if not manifest['version']:
            manifest['version'] = self.proj_desc['project_version']

        return manifest

    def get_tags(self, exclude_dirs: Optional[List[str]]=None) -> SPDXTags:
        # Collect tags from components and subpackages which have
        # relationship with Project package.
        tags: SPDXTags = SPDXTags()

        def walk_subpackages(subpackages):
            for subpackage in subpackages:
                yield subpackage
                yield from walk_subpackages(subpackage.subpackages)

        for component in self.components.values():
            if not self._component_used(component.info):
                continue
            tags |= component.tags
            for subpackage in walk_subpackages(component.subpackages):
                tags |= subpackage.tags
        return tags

    def add_relationships(self) -> None:
        if not self.manifest['cpe']:
            # CPE for whole espressif:esp-idf.
            ver = self.proj_desc['git_revision']
            if ver[0] == 'v':
                ver = ver[1:]
            cpe = f'cpe:2.3:a:espressif:esp-idf:{ver}:*:*:*:*:*:*:*'
            self['ExternalRef'] += [f'SECURITY cpe23Type {cpe}']

        # Dependency on toolchain.
        self['Relationship'] += [f'{self["SPDXID"][0]} DEPENDS_ON {self.toolchain["SPDXID"][0]}']

        # Dependencies on components. Only components, which are not required by other
        # components are added as direct dependency for the project binary.
        build_components = self.proj_desc['build_component_info']
        reqs = set()
        for name, info in build_components.items():
            tmp = info['reqs'] + info['priv_reqs'] + info['managed_reqs'] + info['managed_priv_reqs']
            reqs |= set(tmp)

        for name, info in build_components.items():
            if name in reqs:
                continue
            if not self._component_used(build_components[name]):
                continue
            self['Relationship'] += [f'{self["SPDXID"][0]} DEPENDS_ON {self.components[name]["SPDXID"][0]}']

    def dump(self, colors=False) -> str:
        out = log.LogString(colors=colors)
        out += super().dump(colors)

        out += '\n'
        out += f'{out.BLUE}# {self.toolchain.name} toolchain{out.RESET}\n'
        out += self.toolchain.dump(colors)

        for comp_name, comp in self.components.items():
            out += '\n'
            out += f'{out.BLUE}# {comp_name} component{out.RESET}\n'
            out += comp.dump(colors)

        return str(out)


class SPDXToolchain(SPDXPackage):
    """SPDX Package Information for toolchain."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any]):
        self.proj_desc = proj_desc
        self.info = self._get_toolchain_info()
        name = self.info['name']
        super().__init__(args, proj_desc, self.info['path'], name, 'toolchain')

    def get_manifest(self, path: str) -> Dict[str, Any]:
        # create manifest based on info from toolchain
        manifest = self.EMPTY_MANIFEST.copy()
        manifest['description'] = self.info['description']
        manifest['url'] = self.info['url']
        manifest['version'] = self.info['version']
        manifest['supplier'] = self.ESPRESSIF_SUPPLIER
        return manifest

    def get_subpackages(self):
        # There are not subpackages for toolchain
        return []

    def _get_current_platform(self) -> str:
        # Get current platform directly from idf_tools.py.
        idf_tools = utils.pjoin(self.proj_desc['idf_path'], 'tools')
        sys.path.append(idf_tools)
        from idf_tools import CURRENT_PLATFORM
        return str(CURRENT_PLATFORM)

    def _get_toolchain_info(self) -> Dict[str, str]:
        # Get toolchain info from idf tools.json file.
        info: Dict[str,str] = {}

        # Get toolchain name and version from the full c_compiler path.
        compiler_path_components = utils.psplit(self.proj_desc['c_compiler'])
        name = compiler_path_components[-5]
        version = compiler_path_components[-4]
        platform = self._get_current_platform()
        tools_fn = utils.pjoin(self.proj_desc['idf_path'], 'tools', 'tools.json')
        try:
            with open(tools_fn, 'r') as f:
                tools = json.load(f)
        except (OSError, ValueError) as e:
            log.err.die(f'cannot read idf tools description file: {e}')

        log.err.debug(f'toolchain: tools.json:')
        log.err.debug(json.dumps(tools, indent=4))

        # Get toolchain info based on name found in compiler's path.
        tool_info = next((t for t in tools['tools'] if t['name'] == name), None)
        if not tool_info:
            log.err.die(f'cannot find "{name}" tool in "{tools_fn}"')

        # Get tool version based on version found in compiler's path.
        tool_version = next((v for v in tool_info['versions'] if v['name'] == version), None)  # type: ignore
        if not tool_version:
            log.err.die(f'cannot find "{version}" for "{name}" tool in "{tools_fn}"')

        if platform not in tool_version:  # type: ignore
            log.err.die((f'cannot find "{platform}" platform for "{version}" '
                         f'for "{name}" tool in "{tools_fn}"'))

        info['name'] = name
        info['path'] = utils.pjoin('/',*compiler_path_components[:-4])
        info['version'] = version
        info['platform'] = platform
        info['description'] = tool_info['description']  # type: ignore
        info['info_url'] = tool_info['info_url']  # type: ignore
        info['url'] = tool_version[platform]['url']  # type: ignore
        info['size'] = tool_version[platform]['size']  # type: ignore
        info['sha256'] = tool_version[platform]['sha256']  # type: ignore

        log.err.debug('toolchain info:')
        log.err.debug(json.dumps(info, indent=4))

        return info


class SPDXComponent(SPDXPackage):
    """SPDX Package Information for component."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any], name: str, info: dict):
        self.info = info
        super().__init__(args, proj_desc, info['dir'], name, 'component')


class SPDXSubpackage(SPDXPackage):
    """SPDX Package Information for subpackage."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any], path: str, name: str):
        super().__init__(args, proj_desc, path, name, 'subpackage')


class SPDXSubmodule(SPDXPackage):
    """SPDX Package Information for submodule."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any], name: str, info: dict):
        self.info = info
        super().__init__(args, proj_desc, info['path'], name, 'submodule')

    def get_manifest(self, directory: str) -> Dict[str,str]:
        # Convert sbom information from .gitmodule config into expected manifest dictionary
        # and extend already created manifest if it's missing some information.
        manifest = super().get_manifest(directory)

        # Get submodule information form .gitmodules
        module_cfg = git.get_submodule_config(self.info['git_wdir'], self.info['name'])

        # Transform manifest information from variables in gitconfig into manifest dict
        module_sbom = mft.get_submodule_manifet(module_cfg)

        sbom_path = utils.pjoin(self.info['git_wdir'], '.gitmodules')
        mft.validate(module_sbom, f'{sbom_path} submodule {self.info["name"]}', self.info['path'])
        self.update_manifest(manifest, module_sbom)

        return manifest


class SPDXFile(SPDXObject):
    """SPDX File Information."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any], fn: str, basedir: str, prefix: str):
        super().__init__(args, proj_desc)
        self.path = fn
        self.sha1 = self.hash_file(fn, 'sha1')
        self.sha256 = self.hash_file(fn, 'sha256')
        relpath = utils.prelpath(fn, basedir)

        if args.file_tags:
            self.tags = SPDXFileTags(self.path)

        self['FileName'] = ['./' + relpath]
        self['SPDXID'] = ['SPDXRef-FILE-' + self.sanitize_spdxid(f'{prefix}-{relpath}')]
        self['FileChecksum'] += [f'SHA1: {self.sha1}']
        self['FileChecksum'] += [f'SHA256: {self.sha256}']

        if self.tags.licenses:
            self['LicenseInfoInFile'] = list(self.tags.licenses)
        else:
            self['LicenseInfoInFile'] = ['NOASSERTION']

        if self.tags.licenses_expressions:
            self['LicenseConcluded'] = [self.tags.get_license_concluded()]
        else:
            self['LicenseConcluded'] = ['NOASSERTION']

        if self.tags.copyrights:
            self['FileCopyrightText'] = ['<text>' + '\n'.join(self.tags.copyrights) + '</text>']
        else:
            self['FileCopyrightText'] = ['NOASSERTION']

        if self.tags.contributors:
            self['FileContributor'] = list(self.tags.contributors)

    def dump(self, colors=False) -> str:
        return super().dump(colors)


def parse_packages(buf: str) -> Dict[str, Dict[str, List[str]]]:
    """Very dummy SPDX file parser. Returns dictionary, where key is
    package SPDXID and value is dictionary with SPDX tag/values."""
    in_package = False
    in_text = False
    idx = -1
    packages: Dict[int, Dict[str, List[str]]] = {}
    tag = ''
    val = ''

    def add_tag_value(tag: str, val: str):
        if not in_package:
            return

        if tag not in packages[idx]:
            packages[idx][tag] = []

        packages[idx][tag].append(val)

    lines = buf.splitlines(keepends=True)
    for line in lines:
        if in_text:
            val += line
            if '</text>' not in line:
                # still in text value
                continue
            val = val.rstrip()
            in_text = False
            add_tag_value(tag, val)

        if not line.strip() or line[0] == '#':
            # skip empty lines or comments
            continue

        if ':' not in line:
            # line not in tag:value format
            continue

        tag, val = line.split(':', maxsplit=1)

        tag = tag.strip()
        if tag == 'FileName':
            # files are listed after package, so this is
            # end of current package if any
            in_package = False
            continue

        val = val.lstrip()
        if val.startswith('<text>') and '</text>' not in val:
            # text value may have multiple lines
            in_text = True
            continue

        val = val.rstrip()

        if tag == 'PackageName':
            in_package = True
            idx += 1
            packages[idx] = {}

        add_tag_value(tag, val)

    spdx_packages = {pkg['SPDXID'][0]: pkg for pkg in packages.values()}
    log.err.debug('parsed spdx packages:')
    log.err.debug(json.dumps(spdx_packages, indent=4))
    return spdx_packages


def filter_packages(packages: Dict[str, Dict[str, List[str]]]):
    """Return only packages which are project package dependencies.
    For example configuration only packages are by default included, but not
    linked via relationship to the main project package. Such packages will
    be filtered out.
    """
    queue = []
    seen = []
    out = {}
    # Dictionary should be ordered and the first package should be the main application package
    queue.append(next(iter(packages)))

    while queue:
        pkg_spdxid = queue.pop(0)
        out[pkg_spdxid] = packages[pkg_spdxid]
        seen.append(pkg_spdxid)

        if 'Relationship' not in packages[pkg_spdxid]:
            continue

        for relationship in packages[pkg_spdxid]['Relationship']:
            src, rel, dst = relationship.split()
            if rel != 'DEPENDS_ON':
                continue
            if dst not in seen:
                queue.append(dst)

    log.err.debug('filtered spdx packages:')
    log.err.debug(json.dumps(out, indent=4))
    return out
