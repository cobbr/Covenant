# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.2] - 2019-02-14
### Added
- Added Rubeus as a git submodule
- Added Rubeus task
- Added AssemblyReflect task
- Added 'ReferenceSourceLibrary' and 'EmbeddedResources' properties to GruntTask

### Changed
- Changed Assembly task to execute EntryPoint
- Changed SharpSploit source to a git submodule
- Changed Compiler source optimization

### Fixed
- Fixed Assembly task

## [v0.1.1] - 2019-02-09
### Added
- Added CHANGELOG.md

### Changed
- Updated SharpSploit Mimikatz.cs source code

### Fixed
- Temporary fix for source code optimization removing "System" imports, causing issues with PortScan task

## v0.1 - 2019-02-07
- Initial release

[v0.1.1]: https://github.com/cobbr/Covenant/compare/v0.1...v0.1.1
[v0.1.2]: https://github.com/cobbr/Covenant/compare/v0.1.1...v0.1.2
