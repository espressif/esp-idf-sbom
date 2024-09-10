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
