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
