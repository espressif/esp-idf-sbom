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

import schema
import yaml
from license_expression import ExpressionError, get_spdx_licensing

from esp_idf_sbom import __version__
from esp_idf_sbom.libsbom import git, log, utils


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

        for root, dirs, files in os.walk(path):
            if exclude_dirs and root in exclude_dirs:
                continue
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
        with open(fn, 'rb') as f:
            return hashlib.file_digest(f, alg).hexdigest()  # type: ignore

    def get_files(self, path: str, prefix: str, exclude_dirs: Optional[List[str]]=None) -> List['SPDXFile']:
        """Return list of SPDXFile objects for files found in path.

        :param path: path to recursively traverse
        :param prefix: prefix to use in SPDXID for files to avoid possible SPDXID collisions
        :param exclude_dirs: list sub-dirs to skip
        :returns: list of SPDXFile objects for given path
        """
        spdx_files: List[SPDXFile] = []
        for root, dirs, files in os.walk(path):
            if exclude_dirs and root in exclude_dirs:
                continue
            for fn in files:
                spdx_files.append(SPDXFile(self.args, self.proj_desc,
                                           utils.pjoin(root, fn), path, prefix))

        return spdx_files

    def get_submodules(self, path: str, prefix: str) -> List['SPDXSubmodule']:
        """Return list of SPDXSubmodule objects found in path.

        :param path: path to look for submodules
        :param prefix: prefix to use in SPDXID for submodules to avoid possible SPDXID collisions
        :returns: list of SPDXSubmodule objects for given path
        """
        submodules: List[SPDXSubmodule] = []

        if self.args.rem_submodules:
            return submodules

        git_wdir = git.get_gitwdir(path)
        if not git_wdir:
            return submodules

        submodules_info = git.submodule_foreach_enum(git_wdir)
        if not submodules_info:
            return submodules

        for submodule_info in submodules_info:
            if not submodule_info['path'].startswith(path):
                continue
            # Submodule relative path to component/submodule directory
            submodule_info['rel_path'] = utils.prelpath(submodule_info['path'], path)

            submodules.append(SPDXSubmodule(self.args, self.proj_desc,
                                            prefix, submodule_info))

        return submodules

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

    def check_person_organization(self, s: str) -> bool:
        if s.startswith('Person: ') or s.startswith('Organization: '):
            return True
        raise schema.SchemaError((f'Value "{s}" must have "Person: " or "Organization: " prefix.'))

    def check_url(self, url: str) -> bool:
        if utils.is_remote_url(url):
            return True
        raise schema.SchemaError((f'Value {url} must have "git", "http" or "https" scheme and domain.'))

    def check_cpe(self, cpe: str) -> bool:
        # Note: WFN, well-formed CPE name, attributes rules are stricter
        if re.match(r'^cpe:2\.3:[aho](?::\S+){10}', cpe):
            return True
        raise schema.SchemaError((f'Value "{cpe}" does not seem to be well-formed CPE name (WFN)'))

    def check_license(self, lic: str) -> bool:
        try:
            self.tags.licensing.parse(lic, validate=True)
        except ExpressionError as e:
            raise schema.SchemaError((f'License expression "{lic}" is not valid: {e}'))
        return True

    def get_manifest(self, directory: str) -> Dict[str,str]:
        """Return manifest information found in given directory."""
        def validate_sbom_manifest(manifest: Dict[str,str]) -> None:
            try:
                sbom_schema = schema.Schema(
                    {
                        schema.Optional('version'): str,
                        schema.Optional('repository'): schema.And(str, self.check_url),
                        schema.Optional('url'): schema.And(str, self.check_url),
                        schema.Optional('cpe'): schema.And(str, self.check_cpe),
                        schema.Optional('supplier'): schema.And(str, self.check_person_organization),
                        schema.Optional('originator'): schema.And(str, self.check_person_organization),
                        schema.Optional('description'): str,
                        schema.Optional('license'): schema.And(str, self.check_license),
                    })

                sbom_schema.validate(manifest)
            except schema.SchemaError as e:
                log.err.die(f'The sbom.yml manifest file in "{directory}" is not valid: {e}')

        def load(fn: str) -> Dict[str,str]:
            # Helper to load yml files.
            path = utils.pjoin(directory, fn)
            if not os.path.isfile(path):
                return {}

            with open(path, 'r') as f:
                return yaml.safe_load(f.read()) or {}

        def update(dst: Dict[str,str], src: Dict[str,str]) -> None:
            # Update manifest dict with new values from src.
            for key, val in src.items():
                if key not in dst:
                    continue
                if not dst[key]:
                    dst[key] = val

        # Set default manifest values, which are updated with
        # manifest file information if presented in component/submodule
        # directory.
        manifest = {
            'version': '',
            'repository': '',
            'url': '',
            'cpe': '',
            'supplier': '',
            'originator': '',
            'description': '',
            'license': '',
        }

        sbom_yml = load('sbom.yml')
        validate_sbom_manifest(sbom_yml)
        update(manifest, sbom_yml)
        idf_component_yml = load('idf_component.yml')
        update(manifest, idf_component_yml)

        if not manifest['supplier']:
            # Supplier not explicitly provided, use maintainers if present.
            if 'maintainers' in idf_component_yml and idf_component_yml['maintainers']:
                manifest['supplier'] = 'Person: ' + ', '.join(idf_component_yml['maintainers'])

        if manifest['cpe']:
            # CPE may contain version placeholder.
            manifest['cpe'] = manifest['cpe'].format(manifest['version'])

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


class SPDXProject(SPDXObject):
    """SPDX Package Information for the project binary."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any]):
        super().__init__(args, proj_desc)

        self.name = self.proj_desc['project_name']
        self.manifest = self._get_manifest()
        self.version = self.manifest['version']
        self.linked_libs = self._get_linked_libs()
        self.components = self._get_components()
        self.toolchain = SPDXToolchain(self.args, self.proj_desc)
        self.file = None

        if self.include_files():
            fn = utils.pjoin(self.proj_desc['build_dir'], self.proj_desc['app_bin'])
            self.file = SPDXFile(self.args, self.proj_desc, fn, self.proj_desc['build_dir'], self.name)

        self._add_spdx_file_tags()

        self['PackageName'] = [self.name]
        if self.manifest['description']:
            self['PackageSummary'] = [f'<text>{self.manifest["description"]}</text>']
        self['SPDXID'] = ['SPDXRef-PROJECT-' + self.sanitize_spdxid(self.name)]
        self['PackageVersion'] = [self.version]
        self['PackageSupplier'] = [self.manifest['supplier'] or 'NOASSERTION']
        self['PackageDownloadLocation'] = [self.manifest['url'] or 'NOASSERTION']
        if self.file:
            self['FilesAnalyzed'] = ['true']
            self['PackageVerificationCode'] = [self.get_verification_code([self.file.sha1])]
            self['PackageLicenseInfoFromFiles'] = list(self.tags.licenses)
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

        self._add_relationships()

    def _get_manifest(self) -> Dict[str, str]:
        # Get manifest information and try to fill in missing pieces.
        manifest = self.get_manifest(self.proj_desc['project_path'])
        if not manifest['version']:
            manifest['version'] = self.proj_desc['project_version']

        return manifest

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

    def _add_spdx_file_tags(self) -> None:
        # Collect tags from components and submodules which have
        # relationship with Project package.
        def walk_submodules(submodules):
            for submodule in submodules:
                yield submodule
                yield from walk_submodules(submodule.submodules)

        for component in self.components.values():
            if not self._component_used(component.info):
                continue
            self.tags |= component.tags
            for submodule in walk_submodules(component.submodules):
                self.tags |= submodule.tags

    def _add_relationships(self) -> None:
        if self.manifest['repository']:
            self['ExternalRef'] += [f'OTHER repository {self.manifest["repository"]}']

        if self.manifest['cpe']:
            self['ExternalRef'] += [f'SECURITY cpe23Type {self.manifest["cpe"]}']
        else:
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

        if self.file:
            out += '\n'
            out += f'{out.BLUE}# {self.name} binary{out.RESET}\n'
            out += self.file.dump(colors)

        out += '\n'
        out += f'{out.BLUE}# {self.toolchain.name} toolchain{out.RESET}\n'
        out += self.toolchain.dump(colors)

        for comp_name, comp in self.components.items():
            out += '\n'
            out += f'{out.BLUE}# {comp_name} component{out.RESET}\n'
            out += comp.dump(colors)

        return str(out)


class SPDXToolchain(SPDXObject):
    """SPDX Package Information for toolchain."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any]):
        super().__init__(args, proj_desc)

        self.info = self._get_toolchain_info()
        self.name = self.info['name']
        self.version = self.info['version']
        self.files = None

        path = utils.pjoin(self.info['path'], self.info['version'])
        if self.include_files(url=self.info['url'], ver=self.info['version']):
            self.files = self.get_files(path, self.name)
        if args.file_tags:
            self.tags = SPDXDirTags(path)

        self['PackageName'] = [self.name]
        self['PackageSummary'] = [f'<text>{self.info["description"]}</text>']
        self['SPDXID'] = ['SPDXRef-TOOLCHAIN-' + self.sanitize_spdxid(self.name)]
        self['PackageVersion'] = [self.version]
        self['PackageSupplier'] = [self.ESPRESSIF_SUPPLIER]
        self['PackageDownloadLocation'] = [self.info['url']]
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
        self['PackageLicenseDeclared'] = ['NOASSERTION']
        if self.tags.copyrights:
            self['PackageCopyrightText'] = ['<text>{}</text>'.format('\n'.join(self.tags.copyrights))]
        else:
            self['PackageCopyrightText'] = ['NOASSERTION']

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

    def dump(self, colors=False) -> str:
        out = log.LogString(colors=colors)
        out += super().dump(colors)

        if self.files:
            out += '\n'
            out += f'{out.BLUE}# {self.name} toolchain files{out.RESET}'
            for f in self.files:
                out += '\n'
                out += f.dump(colors)
        return str(out)


class SPDXComponent(SPDXObject):
    """SPDX Package Information for component."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any], name: str, info: dict):
        super().__init__(args, proj_desc)
        self.name = name
        self.dir = info['dir']
        self.info = info
        self.manifest = self._get_manifest()
        self.submodules = self.get_submodules(self.dir, self.name)
        self.files = []

        # exclude submodule paths if any
        exclude_dirs = [submod.dir for submod in self.submodules]

        if self.include_files(repo=self.manifest['repository'],
                              url=self.manifest['url'],
                              ver=self.manifest['version']):
            self.files = self.get_files(self.dir, self.name, exclude_dirs)

        if args.file_tags:
            if self.files:
                self.tags = SPDXFileObjsTags(self.files)
            else:
                self.tags = SPDXDirTags(self.dir, exclude_dirs)

        self['PackageName'] = [f'component-{self.name}']
        if self.manifest['description']:
            self['PackageSummary'] = [f'<text>{self.manifest["description"]}</text>']
        self['SPDXID'] = ['SPDXRef-COMPONENT-' + self.sanitize_spdxid(self.name)]
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

        self._add_relationships()

    def _get_manifest(self) -> Dict[str, str]:
        # Get manifest information and try to fill in missing pieces.
        manifest = self.get_manifest(self.dir)
        if not manifest['version']:
            manifest['version'] = self.guess_version(self.dir, self.name)

        if not manifest['repository']:
            manifest['repository'] = git.get_remote_location(self.dir)

        if not manifest['supplier']:
            manifest['supplier'] = self.guess_supplier(self.dir, manifest['url'], manifest['repository'])

        return manifest

    def _add_relationships(self) -> None:
        if self.manifest['repository']:
            self['ExternalRef'] += [f'OTHER repository {self.manifest["repository"]}']

        if self.manifest['cpe']:
            self['ExternalRef'] += [f'SECURITY cpe23Type {self.manifest["cpe"]}']

        for submod in self.submodules:
            self['Relationship'] += [f'{self["SPDXID"][0]} DEPENDS_ON {submod["SPDXID"][0]}']

    def dump(self, colors=False) -> str:
        out = log.LogString(colors=colors)
        out += super().dump(colors)

        if self.files:
            out += '\n'
            out += f'{out.BLUE}# {self.name} component files{out.RESET}'
            for f in self.files:
                out += '\n'
                out += f.dump(colors)

        if not self.submodules:
            return str(out)

        for submod in self.submodules:
            out += '\n'
            out += f'{out.BLUE}# {submod.name} submodule{out.RESET}\n'
            out += submod.dump(colors)

        return str(out)


class SPDXSubmodule(SPDXObject):
    """SPDX Package Information for submodule."""
    def __init__(self, args: Namespace, proj_desc: Dict[str, Any], parent_name: str, info: dict):
        super().__init__(args, proj_desc)
        self.name = info['rel_path']
        self.info = info
        self.dir = info['path']
        self.manifest = self._get_manifest()
        self.submodules = self.get_submodules(self.dir, f'{parent_name}-{self.name}')
        self.files = []

        # exclude submodule paths if any
        exclude_dirs = [submod.dir for submod in self.submodules]

        if self.include_files(repo=self.manifest['repository'],
                              url=self.manifest['url'],
                              ver=self.manifest['version']):
            self.files = self.get_files(self.dir, f'{parent_name}-{self.name}', exclude_dirs)

        if args.file_tags:
            if self.files:
                self.tags = SPDXFileObjsTags(self.files)
            else:
                self.tags = SPDXDirTags(self.dir, exclude_dirs)

        self['PackageName'] = [f'submodule-./{self.name}']
        if self.manifest['description']:
            self['PackageSummary'] = [f'<text>{self.manifest["description"]}</text>']
        self['SPDXID'] = ['SPDXRef-SUBMODULE-' + self.sanitize_spdxid(f'{parent_name}-{self.name}')]
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

        self._add_relationships()

    def _get_manifest(self) -> Dict[str, str]:
        # Get manifest information and try to fill in missing pieces from .gitmodules
        # if available.
        def get_submodule_config() -> Dict[str,str]:
            # Return validated submodule git configuration.
            def validate_submodule_config(config: Dict[str,str]) -> None:
                try:
                    submodule_schema = schema.Schema(
                        {
                            schema.Optional('sbom-version'): str,
                            schema.Optional('sbom-repository'): schema.And(str, self.check_url),
                            schema.Optional('sbom-url'): schema.And(str, self.check_url),
                            schema.Optional('sbom-cpe'): schema.And(str, self.check_cpe),
                            schema.Optional('sbom-supplier'): schema.And(str, self.check_person_organization),
                            schema.Optional('sbom-originator'): schema.And(str, self.check_person_organization),
                            schema.Optional('sbom-description'): str,
                            schema.Optional('sbom-license'): schema.And(str, self.check_license),
                        }, ignore_extra_keys=True)

                    submodule_schema.validate(config)
                except schema.SchemaError as e:
                    fn = utils.pjoin(self.info['git_wdir'], '.gitmodules')
                    log.err.die(f'The submodule "{self.info["sm_path"]}" sbom information in "{fn}" is not valid: {e}')

            module_cfg = git.get_submodule_config(self.info['git_wdir'], self.info['name'])
            validate_submodule_config(module_cfg)
            return module_cfg

        manifest = self.get_manifest(self.dir)
        module_cfg = get_submodule_config()
        if not manifest['version']:
            if 'sbom-version' in module_cfg:
                manifest['version'] = module_cfg['sbom-version']
            else:
                manifest['version'] = self.guess_version(self.dir)

        if not manifest['cpe']:
            manifest['cpe'] = module_cfg.get('sbom-cpe', '').format(manifest['version'])

        if not manifest['originator']:
            manifest['originator'] = module_cfg.get('sbom-originator', '')

        if not manifest['url']:
            manifest['url'] = module_cfg.get('sbom-url', '')

        if not manifest['description']:
            manifest['description'] = module_cfg.get('sbom-description', '')

        if not manifest['license']:
            manifest['license'] = module_cfg.get('sbom-license', '')

        if not manifest['repository']:
            if 'sbom-repository' in module_cfg:
                manifest['repository'] = module_cfg['sbom-repository']
            else:
                manifest['repository'] = git.get_remote_location(self.dir)

        if not manifest['supplier']:
            if 'sbom-supplier' in module_cfg:
                manifest['supplier'] = module_cfg['sbom-supplier']
            else:
                manifest['supplier'] = self.guess_supplier(self.dir, manifest['url'],
                                                           manifest['repository'])

        return manifest

    def _add_relationships(self) -> None:
        if self.manifest['repository']:
            self['ExternalRef'] += [f'OTHER repository {self.manifest["repository"]}']

        if self.manifest['cpe']:
            self['ExternalRef'] += [f'SECURITY cpe23Type {self.manifest["cpe"]}']

        for submod in self.submodules:
            self['Relationship'] += [f'{self["SPDXID"][0]} DEPENDS_ON {submod["SPDXID"][0]}']

    def dump(self, colors=False) -> str:
        out = log.LogString(colors=colors)
        out += super().dump(colors)

        if self.files:
            out += '\n'
            out += f'{out.BLUE}# {self.name} submodule files{out.RESET}'
            for f in self.files:
                out += '\n'
                out += f.dump(colors)

        if not self.submodules:
            return str(out)

        for submod in self.submodules:
            out += '\n'
            out += f'{out.BLUE}# {submod.name} submodule{out.RESET}\n'
            out += submod.dump(colors)

        return str(out)


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
    idx = 0
    packages: Dict[int, Dict[str, List[str]]] = {}
    lines = buf.splitlines()
    for line in lines:
        line = line.strip()

        if not line or line[0] == '#':
            continue

        try:
            tag, val = line.split(':', maxsplit=1)
        except ValueError:
            # can be multiline text inside <text>...</text>
            continue

        tag = tag.strip()
        val = val.strip()

        if tag == 'PackageName':
            in_package = True
            idx += 1
            packages[idx] = {}

        if not in_package:
            continue

        if tag == 'FileName':
            in_package = False
            continue

        if tag not in packages[idx]:
            packages[idx][tag] = []

        packages[idx][tag].append(val)

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
