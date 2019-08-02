# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Added GetDirectoryListing of a specific path
- Added stderr to output of ShellExecute functions
- Added ShellCmdExecute function
- Added registry class with improved read/write functions
- Added remote registry functions

### Changed
- Updated mimikatz binaries
- Changed mimikatz function to load in new thread, free input/output pointers
- Updated registry tests

### Fixed
- Fixed XML warning, removed angle brackets in comment

## [v1.3] - 2019-03-03
### Fixed
- Fixed SharpSploit.Enumeration.Host.ChangeCurrentDirectory() to accept absolute paths
- Fixed SharpSploit.Enumeration.Host.GetProcessList() retrieves valid ppid values

## [v1.2] - 2019-02-12
### Added
- Added CHANGELOG.md
- Added Assembly EntryPoint execution

## [v1.1] - 2018-11-03
### Added
- Added DCOM lateral movement
- Added nuget package

### Changed
- Updated README

### Fixed
- Fixed Domain warnings
- Fixed XML path
- Fixed Mimikatz quoting

## v1.0 - 2018-09-20
- Initial release

[v1.1]: https://github.com/cobbr/SharpSploit/compare/v1.0...v1.1
[v1.2]: https://github.com/cobbr/SharpSploit/compare/v1.1...v1.2
[v1.3]: https://github.com/cobbr/SharpSploit/compare/v1.2...v1.3
