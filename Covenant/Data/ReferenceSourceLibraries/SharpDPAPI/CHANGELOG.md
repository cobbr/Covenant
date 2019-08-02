# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.2.0] - 2019-03-24 (Troopers edition ;)

### Added
* **masterkeys/vaults/creds/triage** actions
    * Remote server support for user vault/credential triage with /server:X
* **machinemasterkeys** perform master key triage for the local machine
    * implicitly elevates to SYSTEM to extract the machine's local DPAPI key
    * uses this key to triage all machine Credential files
* **machinecredentials** perform Credential file triage for the local machine
    * implicitly elevates to SYSTEM via the **machinemasterkeys** approach
    * uses the extracted masterkeys to decrypt any Credential files
* **machinevaults** perform vault triage for the local machine
    * implicitly elevates to SYSTEM via the **machinemasterkeys** approach
    * uses the extracted masterkeys to decrypt any machine Vaults
* **machinetriage** performs all machine triage actions (currently vault and credential)
    * implicitly elevates to SYSTEM via the **machinemasterkeys** approach

### Changed
* Expanded Vault credential format to handle vault credential clear attributes
* Expanded machine vault/credential search locations
* Broke out commands/files into the same general structure as Rubeus


## [1.1.1] - 2019-03-15

### Added
* **SharpDPAPI.cna** Cobalt Strike aggressor script to automate the usage of SharpDPAPI (from @leechristensen)

### Changed
* Wrapped main in try/catch

### Fixed
* Fixed Policy.vpol parsing to handle the "KSSM" (?) format. Thank you @gentilkiwi :)


## [1.1.0] - 2019-03-14

### Added
* **masterkeys** action
    * decrypts currently reachable master keys (current users or all if elevated) and attempts to decrypt them using a passed {GUI}:SHA1 masterkey lookup table, or a /pvk base64 blob representation of the domain DPAPI backup key
* **credentials** action
    * decrypts currently reachable Credential files (current users or all if elevated) and attempts to decrypt them using a passed {GUI}:SHA1 masterkey lookup table, or a /pvk base64 blob representation of the domain DPAPI backup key
* **vaults** action
    * decrypts currently reachable Vault files (current users or all if elevated) and attempts to decrypt them using a passed {GUI}:SHA1 masterkey lookup table, or a /pvk base64 blob representation of the domain DPAPI backup key
* **triage** action
    * performs all triage actions (currently vault and credential)
* CHANGELOG

### Changed
* modified the argument formats for the **backupkey** command
* retructured files so code isn't in a single file
* revamped README


## [1.0.0] - 2018-08-22

* Initial release
