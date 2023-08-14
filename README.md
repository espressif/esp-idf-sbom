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


## SPDX SBOM layout

The SBOM file is created based on application sources, build artefacts, information
provided by the ESP-IDF build system and SBOM manifest files. The resulting SBOM
file contains SPDX packages for the final **project** application, used **toolchain**,
**components** used during build, git **submodules** and **subpackages**. The **subpackages**
are created based on `sbom.yml` manifest files found in **submodules** and **subpackages**
sub-directories. Please see [Manifest file](#manifest-file).

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
    CPE used for vulnerabilities check against NVD.
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
* **license**:
    License expression explicitly declared by the author.


Example of the `sbom.yml` manifest file for the ESP-IDF blink example.

    version: 0.1.0
    description: Blink application example
    url: https://blink.org/blink-0.1.0.tar.gz # non-existing package download URL example
    cpe: cpe:2.3:a:hrbata:blink:{}:*:*:*:*:*:*:* # non-existing CPE example
    supplier: 'Person: Frantisek Hrbata (frantisek.hrbata@espressif.com)'
    originator: 'Organization: Espressif Systems (Shanghai) CO LTD'

Example of the `sbom.yml` manifest file for the blink's main component.

    version: 0.1.0
    description: Main component for blink application
    repository: https://github.com/espressif/esp-idf.git@dc016f59877d13e6e7d4fc193aa5aa764547f16d#examples/get-started/blink
    supplier: 'Organization: Espressif Systems (Shanghai) CO LTD'

Information from the `sbom.yml` manifest file are mapped to the following SPDX tags.

| manifest     | SPDX                         |
|--------------|------------------------------|
| name         | PackageName                  |
| version      | PackageVersion               |
| description  | PackageSummary               |
| repository   | ExternalRef OTHER repository |
| url          | PackageDownloadLocation      |
| cpe          | ExternalRef cpe23Type        |
| supplier     | PackageSupplier              |
| originator   | PackageOriginator            |
| license      | PackageLicenseDeclared       |

Even though the `sbom.yml` file is the primary source of information, the esp-idf-sbom tool
is also looking at other places if it's not present. The `idf_component.yml` manifest file,
used for components managed by the component manager, may have `sbom` dictionary/namespace,
which will be used by esp-idf-sbom if presented. This dictionary may contain the same information
as `sbom.yml`.

Example of the `idf_component.yml` manifest file for the blink's main component.

    dependencies:
      idf:
        version: '>=5.0'
    description: Driver for Addressable LED Strip (WS2812, etc)
    url: https://github.com/espressif/idf-extra-components/tree/master/led_strip
    version: 2.4.1
    sbom:
      version: 0.1.0
      description: Main component for blink application
      repository: https://github.com/espressif/esp-idf.git@dc016f59877d13e6e7d4fc193aa5aa764547f16d#examples/get-started/blink
      supplier: 'Organization: Espressif Systems (Shanghai) CO LTD'

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
may be disabled by using the '--no-guess' option. For submodules, the .gitmodules file is
also checked for additional submodule information.


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
The reason for this is to avoid possible false possitives, because such packages
have no direct impact on the resulting application. This can be changed with the `--check-all-packages`
option. If used, all packages in the SBOM file will be checked for possible vulnerabilities
regardless their relationships to the application binary.

SBOM file generated by the esp-idf-sbom tool can be checked for known vulnerabilities
with

    esp-idf-sbom check [SBOM file]

If *SBOM file* is not provided, the stardard input stream is used.


## Licenses and Copyrights

All **component** and **submodule** files are scanned for the `SPDX-License-Identifier`,
`SPDX-FileCopyrightText` and `SPDX-FileContributor` SPDX file tags. Information from
these tags is used in the generated SBOM file to specify licenses and copyrights for
SPDX packages which represent **project**, **component** or **submodule**. The project's
final license expression is a logical AND of all licenses concluded from **components**
and **submodules** used in the final project binary.

The license can be also explicitly declared by the author in the `sbom.yml` file with the `license`
variable. This information is used as a value for the `PackageLicenseDeclared` SPDX tag for
given **project**, **component** or **submodule**.

The `--no-file-tags` option disables scanning for SPDX file tags. When used the license and
copyright information from files will not be presented in the generated SBOM file.


## Usage example

This is an example of basic usage for the blink project, which is part of the ESP-IDF. The
two `sbom.yml` files for project and main component showed above were added. It's expected
that ESP-IDF is installed and set.

    $ cd examples/get-started/blink/ # In esp-idf directory go to the blink example
    $ idf.py build                   # Project has to be built first
    $ esp-idf-sbom create -o blink.spdx build/project_description.json
    $ esp-idf-sbom check blink.spdx

    $ esp-idf-sbom create build/project_description.json | esp-idf-sbom check

The resulting `blink.spdx` sbom file can be found in the `examples` directory.


[1]: https://en.wikipedia.org/wiki/Software_supply_chain
[2]: https://spdx.dev
[3]: https://docs.espressif.com/projects/esp-idf/en/latest
[4]: https://nvd.nist.gov
[5]: https://en.wikipedia.org/wiki/Common_Platform_Enumeration
