# ESP-IDF SBOM Tool (**esp-idf-sbom**)

> :warning: **This is experimental implementation, which is subject to change without prior
> notice and no backward compatibility is guaranteed.**

The esp-idf-sbom tool creates [Software bill of materials][1] (SBOM)
files in the [Software Package Data Exchange][2] (SPDX) format for applications
generated by the [Espressif IoT Development Framework][3] (ESP-IDF).
It also allows to check generated SBOM files for know vulnerabilities against
the [National Vulnerability Database][4] (NVD) based on the
[Common Platform Enumeration][5] (CPE) provided in the SBOM.

## Required ESP-IDF versions

All release branches of currently supported ESP-IDF versions allow to
generate the SBOM file.

| ESP-IDF version | branch with SBOM support  | commits
|-----------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| 4.3             | release/v4.3              | [befb32b45bc9314b48c29624f9a2c2ef30e34260](https://github.com/espressif/esp-idf/commit/befb32b45bc9314b48c29624f9a2c2ef30e34260) |
|                 |                           | [f1eef50947ab5770ae4d904c07615e7acab06002](https://github.com/espressif/esp-idf/commit/f1eef50947ab5770ae4d904c07615e7acab06002) |
| 4.4             | release/v4.4              | [ee505a996045c3657711c3d70c58af8dd48b1426](https://github.com/espressif/esp-idf/commit/ee505a996045c3657711c3d70c58af8dd48b1426) |
|                 |                           | [53f271ce108d6fa99cf92d59fe9b9dcc4b8fb45b](https://github.com/espressif/esp-idf/commit/53f271ce108d6fa99cf92d59fe9b9dcc4b8fb45b) |
| 5.0             | release/v5.0              | [30735b33efabd6cf038bcb258b674cf828ad5ecf](https://github.com/espressif/esp-idf/commit/30735b33efabd6cf038bcb258b674cf828ad5ecf) |
|                 |                           | [9156bbb55c920d6704329975311c331b931ed6bc](https://github.com/espressif/esp-idf/commit/9156bbb55c920d6704329975311c331b931ed6bc) |
| 5.1             | release/v5.1              | [0f781c718c8548cd2b0e41a30e1814f1c6ed93a2](https://github.com/espressif/esp-idf/commit/0f781c718c8548cd2b0e41a30e1814f1c6ed93a2) |
|                 |                           | [03162bb276d4155760e8aa839020f0587f5ef599](https://github.com/espressif/esp-idf/commit/03162bb276d4155760e8aa839020f0587f5ef599) |
| latest          | master                    |                                                                                                                                  |

Older versions, e.g. `v5.0.2`, do not have the required code merged and the following error
message will be printed.

    E: Project description file "build/project_description.json" does not support SBOM generation. Please see the list of IDF versions required by esp-idf-sbom.

If you see this error message and want to try `esp-idf-sbom`, you can

1. switch to the release branch for version you are using. For example `release/v5.0` if you are using `v5.0.2`.
2. use future ESP-IDF versions to experiment with esp-idf-sbom.
3. use `git-cherry-pick` and apply commits for your release from the table above. For example for `v5.0.2` use

    $ git cherry-pick 30735b33efabd6cf038bcb258b674cf828ad5ecf 9156bbb55c920d6704329975311c331b931ed6bc


## Installation

Currently esp-idf-sbom is not integrated into ESP-IDF and needs to by installed
separately from Python Package Index (PyPI) with

    pip install esp-idf-sbom

After installation the `esp-idf-sbom` command should be available or the esp_idf_sbom
python module can be used with

    python -m esp_idf_sbom


## Creating SBOM

The application has to be built before the SBOM file can be created. This step should
not be required in the future once esp-idf-sbom is integrated into ESP-IDF.

The SBOM file can be created with

    esp-idf-sbom create <project description file>

The `project description file` is a path to the *project_description.json* file, which
is by default created by the ESP-IDF build system in the project's *build* directory.
The generated SBOM file is printed to the standard output stream by default or can be
saved in a file if the `--output-file` option is used.


## Checking vulnerabilities

Vulnerabilities are checked based on the [Common Platform Enumeration][5] (CPE) information
included in the SBOM file for SPDX packages. While checking for vulnerabilities, only packages
with direct or indirect relationship to the **project** package are examined. For example if mbedtls
component is compiled, due to component dependecies, but it's actually not linked into the
final binary, it will be by default presented in the SBOM file, but it will not be reachable
from the root **project** package and hence it will not be checked for vulnerabilities.
The reason for this is to avoid possible false positives, because such packages
have no direct impact on the resulting application. This can be changed with the `--check-all-packages`
option. If used, all packages in the SBOM file will be checked for possible vulnerabilities
regardless their relationships to the application binary.

SBOM file generated by the esp-idf-sbom tool can be checked for known vulnerabilities
with

    esp-idf-sbom check [SBOM file]

If *SBOM file* is not provided, the standard input stream is used.

The default report format consists of multiple tables:

1. Report summary
2. Packages with identified vulnerabilities
3. Packages with excluded vulnerabilities
4. Packages with no identified vulnerabilities
5. Packages without CPE information not applicable for vulnerability check

The output format may be changed with the `--format` option, which supports exporting
the report into **json**, **csv** or **markdown** format.

If package is not vulnerable to a specific CVE, it can be added to the manifest **cve-exclude-list**
list and checker will not report it as identified vulnerability, but as excluded vulnerability.


## Usage example

This is an example of basic usage for the blink project, which is part of the ESP-IDF.
It's expected that ESP-IDF is installed and set.

    $ cd examples/get-started/blink/ # In esp-idf directory go to the blink example
    $ idf.py build                   # Project has to be built first
    $ esp-idf-sbom create -o blink.spdx build/project_description.json
    $ esp-idf-sbom check blink.spdx

    $ esp-idf-sbom create build/project_description.json | esp-idf-sbom check

The resulting `blink.spdx` sbom file can be found in the `blink` project directory.


## SPDX SBOM layout

The SBOM file is created based on application sources, build artefacts, information
provided by the ESP-IDF build system and SBOM manifest files. The resulting SBOM
file contains SPDX packages for the final **project** application, used **toolchain**,
**components** used during build, git **submodules** and **subpackages**. The **subpackages**
are created based on `sbom.yml` manifest files found in **submodules** and **subpackages**
sub-directories or referenced manifest files. Please see [Manifest file](#manifest-file).

Packages are linked together with SPDX *DEPENDS_ON* relationships with the **project** package
as the root package. By default packages for configuration only components and components not
linked into the application are present in SBOM, but are not linked through SPDX
relationships. In other worlds dependencies on such packages are removed. This behaviour
can be altered with `--add-config-deps` and `--add-unused-deps` command line options.


## Manifest file

During SBOM generation the esp-idf-sbom tool is looking for `sbom.yml` manifest files.
They are used as a source of information for the corresponding SPDX package in the SBOM file
as described above.

The manifest file may be present at root of **project**, **component**, **submodule** or
in any of their sub-directories. If `sbom.yml` is found in a sub-directory a new **subpackage**
SPDX package is created and linked with the parent SPDX package. This can be used in cases
where e.g. one **component** contains multiple libraries and they should be represented
by separate SPDX packages.

Example of multiple `sbom.yml` files usage for the `console` component.

    console
    ├── argtable3
    │   └── sbom.yml
    ├── linenoise
    │   └── sbom.yml
    └── sbom.yml

The `esp-idf-sbom` tool will create main console **component** package, which will
contain two **subpackages** for `argtable3` and `linenoise` libraries. Please note that
the manifest file in the `console` component root directory is not necessary to create
SPDX package, because `esp-idf-sbom` automatically creates SPDX package for each
**component**. The `sbom.yml` files may be placed at any sub-directory depth and
`esp-idf-sbom` will create proper SPDX package hierarchy for them.

The `sbom.yml` is a simple yaml file, which may contain the following entries.

* **name**:
    Package name that will be used in the SPDX package.
* **version**:
    Package version.
* **description**:
    Short package description.
* **repository**:
    Link to git repository.
* **url**:
    Link to package download location.
* **cpe**:
    CPE used for vulnerabilities check against NVD. This can be single CPE value or a
    list of CPEs.
* **supplier**:
    Package supplier. Person or organization distributing the package. Should be prefixed
    with *Person:* or *Organization:* as described in SPDX specification.
* **originator**:
    Package originator. If the package comes from another person or organization
    that has been identified as a supplier. For example if a component is based
    on 3rd party code with some modifications, the originator is the 3rd party code
    author, but the supplier is the person or organization distributing the final
    component. For more detailed information please see the SPDX specification.
    As for supplier, *Person:* or *Organization:* prefix should be used for
    originator value.
* **hash**:
    SHA of the directory(`git-tree` object) the manifest file describes or HEAD SHA of a submodule. This value
    is used during the manifest file validation to check if the hash in the manifest file matches the
    SHA recorded in the `git-tree`. Its purpose is to make sure that the information in the manifest
    file is up-to-date. For example if a submodule or 3rd party library is updated, the
    version in the manifest file should be probably updated too. The SHA value can be obtained
    e.g. with `git ls-tree HEAD <path>`, where `<path>` is a package directory, which is described by
    the manifest file. Please note that a hash value for a directory, not a submodule, cannot
    be placed in manifest file, which is stored within the same directory, because the directory SHA
    in `git-tree` will change every time the manifest file changes(chicken egg problem). To make
    the hash variable work, it needs to be placed in a referenced manifest, which is not stored
    within a directory it describes. For example freertos component can have main `sbom.yml`
    manifest file, which refers to `sbom_FreeRTOS-Kernel.yml` manifest describing the `FreeRTOS-Kernel`
    package in the `FreeRTOS-Kernel` directory.

components/freertos/sbom.yml
```
manifests:
  - path: sbom_FreeRTOS-Kernel.yml
    dest: FreeRTOS-Kernel
```
components/freertos/sbom_FreeRTOS-Kernel.yml
```
name: 'freertos'
version: '10.4.3'
cpe: cpe:2.3:o:amazon:freertos:{}:*:*:*:*:*:*:*
supplier: 'Organization: Espressif Systems (Shanghai) CO LTD'
originator: 'Organization: Amazon Web Services'
description: An open-source, real-time operating system (RTOS) with additional features and patches from Espressif.
hash: 4e8101b6f57a0640ae54c6da605c1b532c0f8f89
cve-exclude-list:
  - cve: CVE-2021-43997
    reason: This vulnerability only affects ARMv7-M and ARMv8-M ports of FreeRTOS and hence does not affect Espressif SoCs which are not based on these architectures.
```

* **license**:
    License expression explicitly declared by the author.
* **cve-exclude-list**:
    List of already evaluated CVEs, which do not apply to this package. This can be used
    to exclude CVEs from the `esp-idf-sbom` checker report in case the package is not
    vulnerable to specific CVEs. Each CVE in the exclude list is represented as dictionary with
    the `cve` and `reason` keys. Information about excluded CVEs is added to the generated
    SBOM file into `PackageComment` SPDX tag and later used by the checker.

    * cve: CVE-ID
    * reason : description why this package is not vulnerable to this CVE
```
      version: 0.1.0
      description: Blink application example
      cve-exclude-list:
        - cve: CVE-2023-1234
          reason: Description why this package is not vulnerable
```

* **manifests**:
    List of manifest files which cannot be added directly into the **component** or **submodule**
    sub-directories to create **subpackage**. For example the following will create a new
    SPDX package for the `subpackage` directory with information from the `subpackage.yml` manifest file.
    This manifest file is treated as it would be actually stored in the `subpackage` directoery.

    * path: path of manifest file relatitve to the sbom.yml
    * dest: destination directory for path, again relative to sbom.yml
```
      version: 0.1.0
      description: Blink application example
      manifests:
        - path: subpackage.yml
          dest: subpackage
```


Example of the `sbom.yml` manifest file for the ESP-IDF blink project.

    version: 0.1.0
    description: Blink application example
    url: https://blink.org/blink-0.1.0.tar.gz # non-existing package download URL example
    cpe: cpe:2.3:a:hrbata:blink:{}:*:*:*:*:*:*:* # non-existing CPE example
    supplier: 'Person: Frantisek Hrbata (frantisek.hrbata@espressif.com)'
    originator: 'Organization: Espressif Systems (Shanghai) CO LTD'
    cve-exclude-list:
       - cve: CVE-2023-1234
         reason: Description why this package is not vulnerable
       - cve: CVE-2023-1235
         reason: Description why this package is not vulnerable


Information from the `sbom.yml` manifest file are mapped to the following SPDX tags.

| manifest        | SPDX                         |
|-----------------|------------------------------|
| name            | PackageName                  |
| version         | PackageVersion               |
| description     | PackageSummary               |
| repository      | ExternalRef OTHER repository |
| url             | PackageDownloadLocation      |
| cpe             | ExternalRef cpe23Type        |
| supplier        | PackageSupplier              |
| originator      | PackageOriginator            |
| license         | PackageLicenseDeclared       |
| cve-exclude-list| PackageComment               |

Even though the `sbom.yml` file is the primary source of information, the esp-idf-sbom tool
is also looking at other places if it's not present. The `idf_component.yml` manifest file,
used for components managed by the component manager, may contain `sbom` dictionary/namespace,
which will be used by esp-idf-sbom if presented. This dictionary may contain the same information
as `sbom.yml`.

Example of the `idf_component.yml` manifest file for led_strip managed component.

    dependencies:
      idf:
        version: '>=5.0'
    description: Driver for Addressable LED Strip (WS2812, etc)
    url: https://github.com/espressif/idf-extra-components/tree/master/led_strip
    version: 2.4.1
    sbom:
      cpe: cpe:2.3:a:hrbata:led_strip:{}:*:*:*:*:*:*:* # non-existing CPE example
      supplier: 'Organization: Espressif Systems (Shanghai) CO LTD'
      cve-exclude-list:
         - cve: CVE-2023-1234
           reason: Description why this package is not vulnerable
         - cve: CVE-2023-1235
           reason: Description why this package is not vulnerable

If the `sbom` dictionary is not presented in `idf_component.yml` or it's missing some information,
the version, description, maintainers and url information from `idf_component.yml` manifest is used.

Information from the `idf_component.yml` manifest file are mapped to the following SPDX tags.

| manifest     | SPDX                         |
|--------------|------------------------------|
| name         | PackageName                  |
| version      | PackageVersion               |
| description  | PackageSummary               |
| maintainers  | PackageSupplier              |
| url          | PackageDownloadLocation      |

Component version may be guessed based on git-describe and Espressif
as a default supplier may be guessed based on git repository or package URL. The guessing
may be disabled by using the '--no-guess' option.

For git submodules, the `.gitmodules` configuration file is also checked for additional submodule
information. Submodule configuration may contain variables with the `sbom-` prefix, which are considered as
SBOM manifest information. All keys used in the `sbom.yml` manifest file can also be specified in
`.gitmodules` with the `git-config` format instead of yaml.

Example of manifest information added for the `micro-ecc` submodule in `.gitmodules`.

    [submodule "components/bootloader/subproject/components/micro-ecc/micro-ecc"]
            path = components/bootloader/subproject/components/micro-ecc/micro-ecc
            url = ../../kmackay/micro-ecc.git
            sbom-version = 1.0
            sbom-cpe = cpe:2.3:a:micro-ecc_project:micro-ecc:{}:*:*:*:*:*:*:*
            sbom-supplier = Person: Ken MacKay
            sbom-url = https://github.com/kmackay/micro-ecc
            sbom-description = A small and fast ECDH and ECDSA implementation for 8-bit, 32-bit, and 64-bit processors
            sbom-hash = d037ec89546fad14b5c4d5456c2e23a71e554966
            sbom-cve-exclude-list = CVE-2023-1234 Description why this package is not vulnerable
            sbom-cve-exclude-list = CVE-2023-1235 Description why this package is not vulnerable


Manifest information is gathered in the following order and only missing
values are added. If e.g. `version` is found in `sbom.yml` any other
`version` value found e.g. in `.gitmodules` is ignored.

1. referenced manifest from parent package
2. `sbom.yml`
3. `sbom` dictionary/namespace in `idf_component.yml`
4. sbom information contained in submodule configuration in `.gitmodules`
5. `idf_component.yml` information provided for component manager


### Validating manifest files

Manifest files are validated while the SBOM is generated. They can be also validated explicitly
with the `esp-idf-sbom manifest validate` command.

    esp-idf-sbom manifest validate [PATH_TO_VALIDATE...]

`PATH_TO_VALIDATE` is an optional path to a manifest file(sbom.yml, idf_manifest.yml or .gitmodules) or
directory, which will be searched for manifest files. If `PATH_TO_VALIDATE` is not provided, the current
working directory is used.

Usage example:

    $ esp-idf-sbom manifest validate ~/work/esp-idf ~/work/idf-extra-components/
    $ esp-idf-sbom manifest validate ~/work/esp-idf/.gitmodules ~/work/esp-idf/components/freertos/FreeRTOS-Kernel/sbom.yml


### Checking manifest files for vulnerabilities

The `esp-idf-sbom` tool uses the generated SBOM SPDX file to check for possible vulnerabilities.
It also allows to scan for vulnerabilities based on the information presented in manifest
files. This can be used e.g. to scan a whole repository without a need to generate the SBOM SPDX file.

    esp-idf-sbom validate-submodule-hash [PATH_TO_CHECK...]

`PATH_TO_CHECK` is an optional path to a manifest file(sbom.yml, idf_manifest.yml or .gitmodules) or
directory, which will be searched for manifest files. If `PATH_TO_CHECK` is not provided, the current
working directory is used.

Usage example:

    $ esp-idf-sbom manifest check ~/work/esp-idf ~/work/idf-extra-components/
    $ esp-idf-sbom manifest check ~/work/esp-idf/.gitmodules ~/work/esp-idf/components/freertos/FreeRTOS-Kernel/sbom.yml


## Licenses and Copyrights

Adding licenses and copyrights information into the SBOM file has to be explicitly
requested by using the `--file-tags` option. This requires to scan all files and
may take some time. It also may result in a quite big SBOM file.

All **component** and **submodule** files are scanned for the `SPDX-License-Identifier`,
`SPDX-FileCopyrightText` and `SPDX-FileContributor` SPDX file tags. Information from
these tags is used in the generated SBOM file to specify licenses and copyrights for
SPDX packages which represent **project**, **component** or **submodule**. The project's
final license expression is a logical AND of all licenses concluded from **components**
and **submodules** used in the final project binary.

The license can be also explicitly declared by the author in the `sbom.yml` file with the `license`
variable. This information is used as a value for the `PackageLicenseDeclared` SPDX tag for
given **project**, **component** or **submodule**.


## Return Values

* **0**:
    No error, no vulnerability found, manifest file(s) valid.
* **1**:
    Vulnerability found or manifest file not valid.
* **128**:
    Fatal error.


[1]: https://en.wikipedia.org/wiki/Software_supply_chain
[2]: https://spdx.dev
[3]: https://docs.espressif.com/projects/esp-idf/en/latest
[4]: https://nvd.nist.gov
[5]: https://en.wikipedia.org/wiki/Common_Platform_Enumeration
