## v1.5.0 (2026-10-26)

### ✨ New Features

- add a report of the statements to vex update *(Frantisek Hrbata - dec5c44)*
- add the vex update command *(Frantisek Hrbata - 7f246fd)*
- accept the VEX values of CISA and CycloneDX *(Frantisek Hrbata - ecfc680)*
- show the VEX statement of each CVE in the check report *(Frantisek Hrbata - d4cb8f1)*
- use the status of each VEX statement in check *(Frantisek Hrbata - bc79138)*
- link each VEX statement to the NVD page of its CVE *(Frantisek Hrbata - 9e8e88e)*
- add justification to excluded CVEs *(Frantisek Hrbata - a87f070)*
- Add support for Python 3.15 *(Roland Dobai - 771b1ab)*
- rename the create --vex option to --vex-format *(Frantisek Hrbata - 1e1ab52)*
- describe custom licenses in the manifest *(Frantisek Hrbata - 0bdb56f)*
- add --vex to idf.py sbom-create *(Frantisek Hrbata - 8a77bac)*
- add check --vex for standalone VEX *(Frantisek Hrbata - 065dc59)*
- parse standalone VEX documents *(Frantisek Hrbata - f30d02c)*
- write a standalone VEX alongside the SBOM *(Frantisek Hrbata - 8d7048f)*
- render standalone VEX documents *(Frantisek Hrbata - a395b55)*
- add the create --vex option *(Frantisek Hrbata - a56531c)*
- add a format-neutral VEX model *(Frantisek Hrbata - 25f96e9)*

### 🐛 Bug Fixes

- write the aggregated manifests to the output file *(Frantisek Hrbata - 0f7167d)*
- use the newest VEX statement about a CVE in check *(Frantisek Hrbata - 4f14684)*
- show text in brackets in warnings and errors *(Frantisek Hrbata - b5438dc)*
- do not write an empty CycloneDX detail *(Frantisek Hrbata - 758615e)*
- write an OpenVEX product @id only for a package with a purl *(Frantisek Hrbata - 730058c)*
- apply a VEX statement to every package with its CPE *(Frantisek Hrbata - 06812f8)*
- accept a cpe string and the {} placeholder in embedded manifests *(Frantisek Hrbata - 0719aa7)*
- do not name Espressif as the creator of SBOM and VEX documents *(Frantisek Hrbata - 2c474a9)*
- match the ESP-IDF path in full when guessing the supplier *(Frantisek Hrbata - 876b100)*
- apply a global CVE exclusion to every CPE of the package *(Frantisek Hrbata - 8a1e2ae)*
- match the CPE product name in full *(Frantisek Hrbata - c58231d)*
- compare CPEs without case *(Frantisek Hrbata - 386eb21)*
- avoid pyparsing 3.3 deprecation warnings in expr.py *(Frantisek Hrbata - d0f0b2b)*
- Declare the license without deprecated metadata *(Peter Dragun - 13bbb4e)*
- ignore unknown keys under the manifest document key *(Frantisek Hrbata - f29e1c2)*
- recover a submodule PURL when git fails in the submodule *(Frantisek Hrbata - 0c54243)*
- report the supplier email as a CycloneDX contact *(Frantisek Hrbata - 6aa330e)*
- keep the declared license and copyright in CycloneDX *(Frantisek Hrbata - a35b454)*
- keep the declared copyright in the SPDX copyright field *(Frantisek Hrbata - 95885b7)*
- define custom licenses in the generated SPDX documents *(Frantisek Hrbata - ed70a46)*
- accept custom LicenseRef identifiers in license expressions *(Frantisek Hrbata - 2a43db5)*
- write PackageChecksum before the package relationships *(Frantisek Hrbata - 612faea)*
- write the output file only after the command succeeded *(Frantisek Hrbata - 84c1ab6)*
- strip the document namespace from parsed SPDX 3.0.1 refs *(Frantisek Hrbata - 481509e)*

### 📖 Documentation

- describe the CVE statements in one README section *(Frantisek Hrbata - 2c827e9)*
- correct the SPDX text in the output formats section *(Frantisek Hrbata - f988cbf)*
- describe your own project and components *(Frantisek Hrbata - a2c2383)*
- say that the supplier prefix is required *(Frantisek Hrbata - 15e6ffe)*
- say that the manifest license is a validated SPDX expression *(Frantisek Hrbata - 1702cd4)*
- describe how declared and scanned licenses are reported *(Frantisek Hrbata - caadf27)*
- describe the custom-licenses manifest key *(Frantisek Hrbata - 68f091a)*
- document the standalone VEX workflow *(Frantisek Hrbata - 4363605)*


## v1.4.0 (2026-09-10)

### ✨ New Features

- report CVEs listed in the CISA KEV catalog *(Frantisek Hrbata - 3d09e8d)*
- derive Package URLs from the commit a package was built from *(Frantisek Hrbata - 685e8ef)*
- declare the ESP-IDF framework license *(Frantisek Hrbata - 5e20a7b)*
- record the SBOM supplier and manufacturer *(Frantisek Hrbata - a06c05d)*
- attribute generated SBOMs to their producing tool *(Frantisek Hrbata - ad99965)*
- Add project specific cve exclusion list *(Dalton Verhagen - dc47bf7)*


## v1.3.1 (2026-07-23)

### 🐛 Bug Fixes

- prune the whole excluded subtree in pwalk *(Frantisek Hrbata - adc67c9)*
- recover orphaned sbom manifests of managed components *(Frantisek Hrbata - 4c20ef3)*
- do not exclude virtual package dirs from the component files *(Frantisek Hrbata - 054a4b5)*
- keep _embeded_path in sync with the manifests list it describes *(Frantisek Hrbata - ebcd86b)*
- correct CVE-2020-22283 exclusion version range *(Frantisek Hrbata - ac6e240)*
- use the component version in the sbom section from idf_component.yml *(Frantisek Hrbata - b528a75)*


## v1.3.0 (2026-07-15)

### ✨ New Features

- let the idf.py sbom-create wrapper select the output format *(Frantisek Hrbata - 9ef09e9)*
- add SPDX 3.0 JSON-LD output (create --format spdx-json-ld) *(Frantisek Hrbata - a84fdb6)*
- add CycloneDX 1.6 JSON output (create --format cyclonedx-json) *(Frantisek Hrbata - ff13994)*
- add SPDX 2.2 JSON output and a create --format option *(Frantisek Hrbata - 589637e)*
- scan NA (unversioned) CPEs under --extended-scan *(Frantisek Hrbata - 69f6ba6)*
- add CPE vendor aliases so renamed-vendor CVEs are found *(Frantisek Hrbata - 768d644)*
- hint about the NVD API key when scanning online without one *(Frantisek Hrbata - 2cee56c)*

### 🐛 Bug Fixes

- sort vulnerability report entries by package within each group *(Frantisek Hrbata - 6cd9756)*
- correct "affect by" to "affected by" in the vulnerability report *(Frantisek Hrbata - f02f145)*
- report NVD API-key status up front and drop the 403 key hint *(Frantisek Hrbata - 0d5cae4)*
- sort the directory walk so SBOM file and package order is deterministic *(Frantisek Hrbata - 88c6da3)*
- honor global CPE-scoped exclusions for keyword-matched CVEs *(Frantisek Hrbata - c97a184)*
- report NVD's Primary CVSS score instead of a Secondary one *(Frantisek Hrbata - 611721b)*

### 📖 Documentation

- rework the README for format-neutral, multi-format output *(Frantisek Hrbata - 5f34ac8)*

### 🔧 Code Refactoring

- switch to a format-neutral SBOM model *(Frantisek Hrbata - dbdd908)*
- rename --extended-scan option dest to extended_scan *(Frantisek Hrbata - c7d4fe0)*


## v1.2.0 (2026-06-24)

### ✨ New Features

- speed up NVD queries when an API key is provided *(Frantisek Hrbata - cd90189)*
- support repository-local excluded_cves.yaml *(Frantisek Hrbata - 9c3938d)*
- adopt esp-pylib for logging and convert the CLI to rich-click *(Frantisek Hrbata - 43f3e47)*

### 🐛 Bug Fixes

- make SBOM and report output deterministic *(Frantisek Hrbata - 558b93b)*


## v1.1.0 (2026-06-09)

### ✨ New Features

- report version-independent esp32_firmware CVEs *(Frantisek Hrbata - 671c08a)*
- inject ESP-IDF framework manifest in manifest check *(Frantisek Hrbata - a842aa5)*
- emit ESP-IDF as a separate SPDX package *(Frantisek Hrbata - 87898b1)*
- support SBOM_EXCLUDED_CVES_FILE env var override *(Frantisek Hrbata - 5aee6db)*
- add --no-sync-excluded-cves option for air-gapped runs *(Frantisek Hrbata - 5f48799)*
- include CPE-scoped exclusions in generated SBOM *(Frantisek Hrbata - dd50b89)*
- apply CPE-scoped exclusions during scan *(Frantisek Hrbata - 3616f3b)*
- extend excluded_cves.yaml schema with CPE-scoped exclusions *(Frantisek Hrbata - 4951864)*
- emit Package URLs (PURL) in generated SBOM *(Frantisek Hrbata - 64ab791)*
- add --version option to CLI *(Frantisek Hrbata - e0ed7dd)*

### 🐛 Bug Fixes

- avoid -128-NOTFOUND version for in-tree ESP-IDF components *(Frantisek Hrbata - 57028e8)*
- filter globally-excluded CVEs at the NVD layer *(Frantisek Hrbata - 4318407)*
- restore pyparsing 2.x compatibility in expr.py *(Frantisek Hrbata - e899bde)*
- support symlinked component directories *(Frantisek Hrbata - 9a42a1d)*
- filter out CVEs with vulnerable=false CPE matches in REST path *(Frantisek Hrbata - cc3e1ea)*
- do not crash on malformed SPDX-License-Identifier *(Frantisek Hrbata - 600ac11)*
- decouple test_validate_report_json from NVD analysis state *(Frantisek Hrbata - b4c4dce)*
- resolve aliased component requirement names in build_component_info *(Frantisek Hrbata - 07a4b27)*

### 📖 Documentation

- document the ESP-IDF framework SPDX package *(Frantisek Hrbata - dabd9e6)*


## v1.0.1 (2026-01-29)

## v1.0.0 (2026-01-28)

### New Features

- add extension for idf.py

### Bug Fixes

- recognize NONE as baseSeverity value in CVSS
- harden linked components identification
- ignore the toolchain package if it cannot be identified

## v0.21.1 (2025-12-29)

### Bug Fixes

- add NONE to severity color map
- exclude DuckDB related CVE

## v0.21.0 (2025-07-19)

### New Features

- add a JSON schema for a vulnerability report in JSON format

### Bug Fixes

- handle version comparison when version ranges are not available
- use stricter validation of CPE string binding
- url encode cpe value before querying NVD REST API

## v0.20.1 (2025-03-18)

### Bug Fixes

- bump python to 3.13 in release_pypi.yml

## v0.20.0 (2025-03-18)

### New Features

- add support for embedded manifests

### Bug Fixes

- use version comparison as a fallback to CPE match strings
- evaluate CPE attribute relations correctly
- avoid calling git-grep if neither cpe nor keyword is present
- clone and fetch only the master branch

## v0.19.1 (2024-10-18)

### Bug Fixes

- include all used components in the project's SPDX dependencies

## v0.19.0 (2024-10-14)

### New Features

- enable keyword search in CVE description

## v0.18.0 (2024-09-10)

### New Features

- allow usage of local NVD mirror for vulnerability scanning

### Bug Fixes

- skip manifest validation in pre-commit if a git rebase is in progress
- exclude files from sub-package if it's not included
- properly manage input paths for the manifest license sub-command
- include missing dependencies for the SPDX project package

## v0.17.1 (2024-07-11)

### Bug Fixes

- correct global variable annotation for Python versions prior to 3.8
- ensure pyparsing usage remains compatible with version 2.2.2 or newer

## v0.17.0 (2024-07-10)

### New Features

- add a global list of excluded CVEs
- allow conditional expressions in manifest files
- introduce virtual package support

## v0.16.0 (2024-06-19)

### New Features

- introduce -n/--name option to enable querying NVD by package name

### Bug Fixes

- skip unregistered components

## v0.15.0 (2024-04-29)

### New Features

- add esp-idf-sbom manifest license command

### Bug Fixes

- remove '+' from set of valid SPDXID characters

## v0.14.0 (2024-01-02)

### New Features

- add support for unified copyright years in license command
- add per package license and copyright report
- add license command
- add declared licenses into project package
- add copyright support to manifest

### Bug Fixes

- harden NVD connection error handling
