# win32-certstore Change Log

<!-- latest_release 0.6.4 -->
## [v0.6.4](https://github.com/chef/win32-certstore/tree/v0.6.4) (2021-08-31)

#### Merged Pull Requests
- Replace deprecated --without flag with bundle config [#82](https://github.com/chef/win32-certstore/pull/82) ([jayashrig158](https://github.com/jayashrig158))
<!-- latest_release -->

<!-- release_rollup since=0.6.2 -->
### Changes not yet released to rubygems.org

#### Merged Pull Requests
- Replace deprecated --without flag with bundle config [#82](https://github.com/chef/win32-certstore/pull/82) ([jayashrig158](https://github.com/jayashrig158)) <!-- 0.6.4 -->
- Upgrade to GitHub-native Dependabot [#80](https://github.com/chef/win32-certstore/pull/80) ([dependabot-preview[bot]](https://github.com/dependabot-preview[bot])) <!-- 0.6.3 -->
<!-- release_rollup -->

<!-- latest_stable_release -->
## [v0.6.2](https://github.com/chef/win32-certstore/tree/v0.6.2) (2021-04-15)

#### Merged Pull Requests
- Updated Certstore to correctly understand CurrentUser vs LocalMachine stores [#79](https://github.com/chef/win32-certstore/pull/79) ([johnmccrae](https://github.com/johnmccrae))
<!-- latest_stable_release -->

## [v0.6.1](https://github.com/chef/win32-certstore/tree/v0.6.1) (2021-04-15)

## [v0.6.1](https://github.com/chef/win32-certstore/tree/v0.6.1) (2021-03-04)

#### Merged Pull Requests
- added support to properly export a pfx object to disk [#75](https://github.com/chef/win32-certstore/pull/75) ([johnmccrae](https://github.com/johnmccrae))
- Remove the release notes [#77](https://github.com/chef/win32-certstore/pull/77) ([tas50](https://github.com/tas50))
- refactoring the helper.rb to put a default for output_path. Generic calls to cert_ps_cmd fail since they won&#39;t provide a path by default [#76](https://github.com/chef/win32-certstore/pull/76) ([johnmccrae](https://github.com/johnmccrae))

## [v0.5.3](https://github.com/chef/win32-certstore/tree/v0.5.3) (2021-02-01)

#### Merged Pull Requests
- Remove redundant coding comment [#62](https://github.com/chef/win32-certstore/pull/62) ([tas50](https://github.com/tas50))
- Simplify our use of expand_path [#64](https://github.com/chef/win32-certstore/pull/64) ([tas50](https://github.com/tas50))
- refactored the code to be properly location aware. Previously, certs … [#66](https://github.com/chef/win32-certstore/pull/66) ([johnmccrae](https://github.com/johnmccrae))
- updated the unit tests to verify connecting to the CurrentUser store [#67](https://github.com/chef/win32-certstore/pull/67) ([johnmccrae](https://github.com/johnmccrae))
- Updated the expeditor verify pipeline to test against Ruby 3.0 [#68](https://github.com/chef/win32-certstore/pull/68) ([johnmccrae](https://github.com/johnmccrae))
- Update mixlib-shellout requirement from &lt; 3.0.12 to &lt; 3.2.3 [#69](https://github.com/chef/win32-certstore/pull/69) ([dependabot-preview[bot]](https://github.com/dependabot-preview[bot]))
- Require Ruby 2.5+ and test on Ruby 3.0 [#71](https://github.com/chef/win32-certstore/pull/71) ([johnmccrae](https://github.com/johnmccrae))

## [v0.4.1](https://github.com/chef/win32-certstore/tree/v0.4.1) (2020-08-21)

#### Merged Pull Requests
- Optimize our requires [#61](https://github.com/chef/win32-certstore/pull/61) ([tas50](https://github.com/tas50))

## [v0.4.0](https://github.com/chef/win32-certstore/tree/v0.4.0) (2020-01-14)

#### Merged Pull Requests
- Move testing to Buildkite [#58](https://github.com/chef/win32-certstore/pull/58) ([tas50](https://github.com/tas50))
- Update testing for Buildkite [#59](https://github.com/chef/win32-certstore/pull/59) ([tas50](https://github.com/tas50))
- Add the ability to set specify properties in add_pfx method [#57](https://github.com/chef/win32-certstore/pull/57) ([amunoz951](https://github.com/amunoz951))

## [v0.3.0](https://github.com/chef/win32-certstore/tree/v0.3.0) (2019-03-11)

#### Merged Pull Requests
- Update appveyor config and use that badge the readme [#54](https://github.com/chef/win32-certstore/pull/54) ([tas50](https://github.com/tas50))
- Import all the certificates (Main &amp; Nested) while importing a PFX certificate [#53](https://github.com/chef/win32-certstore/pull/53) ([Nimesh-Msys](https://github.com/Nimesh-Msys))
- Add chefstyle testing in appveyor / travis [#55](https://github.com/chef/win32-certstore/pull/55) ([tas50](https://github.com/tas50))

## [v0.2.4](https://github.com/chef/win32-certstore/tree/v0.2.4) (2019-02-04)

#### Merged Pull Requests
- Properly close the cert store when we&#39;re done with it &amp; display errors [#52](https://github.com/chef/win32-certstore/pull/52) ([Nimesh-Msys](https://github.com/Nimesh-Msys))

## [v0.2.3](https://github.com/chef/win32-certstore/tree/v0.2.3) (2019-01-29)

#### Merged Pull Requests
- Importing PFX certificates with their private keys [#50](https://github.com/chef/win32-certstore/pull/50) ([Nimesh-Msys](https://github.com/Nimesh-Msys))

## [v0.2.2](https://github.com/chef/win32-certstore/tree/v0.2.2) (2019-01-16)

#### Merged Pull Requests
- Unpin the bundler dev dep [#51](https://github.com/chef/win32-certstore/pull/51) ([tas50](https://github.com/tas50))

## [v0.2.1](https://github.com/chef/win32-certstore/tree/v0.2.1) (2019-01-04)

#### Merged Pull Requests
- Fixes certificate get method to fetch certificate from given store. [#45](https://github.com/chef/win32-certstore/pull/45) ([Vasu1105](https://github.com/Vasu1105))
- Remove unnecessary config in the gemspec [#48](https://github.com/chef/win32-certstore/pull/48) ([tas50](https://github.com/tas50))
- Require ruby 2.3 or later [#49](https://github.com/chef/win32-certstore/pull/49) ([tas50](https://github.com/tas50))
- Fixing deletion of a certificate by its thumbprint. [#46](https://github.com/chef/win32-certstore/pull/46) ([Nimesh-Msys](https://github.com/Nimesh-Msys))

## [v0.1.11](https://github.com/chef/win32-certstore/tree/v0.1.11) (2018-10-31)

#### Merged Pull Requests
- Add missing license directive in the gemspec [#44](https://github.com/chef/win32-certstore/pull/44) ([tas50](https://github.com/tas50))

## [v0.1.10](https://github.com/chef/win32-certstore/tree/v0.1.10) (2018-10-30)

#### Merged Pull Requests
- Update expeditor config and gemfile groups [#42](https://github.com/chef/win32-certstore/pull/42) ([tas50](https://github.com/tas50))
- Update the gemspec to skip the readme, but ship the license [#43](https://github.com/chef/win32-certstore/pull/43) ([tas50](https://github.com/tas50))

## [v0.1.8](https://github.com/chef/win32-certstore/tree/v0.1.8) (2018-08-13)

#### Merged Pull Requests
- Delete certificate raise an exception if user pass invalid thumbprint [#41](https://github.com/chef/win32-certstore/pull/41) ([piyushawasthi](https://github.com/piyushawasthi))

## [v0.1.7](https://github.com/chef/win32-certstore/tree/v0.1.7) (2018-07-18)

#### Merged Pull Requests
- Add github templates/codeowners file &amp; update contributing docs [#34](https://github.com/chef/win32-certstore/pull/34) ([tas50](https://github.com/tas50))
- Fixed all chefstyling and update configuration [#38](https://github.com/chef/win32-certstore/pull/38) ([piyushawasthi](https://github.com/piyushawasthi))
- Fixed MSYS-857 &amp; MSYS-838  [#37](https://github.com/chef/win32-certstore/pull/37) ([piyushawasthi](https://github.com/piyushawasthi))
- MSYS-856 : Removed store validation [#36](https://github.com/chef/win32-certstore/pull/36) ([piyushawasthi](https://github.com/piyushawasthi))

## [v0.1.3](https://github.com/chef/win32-certstore/tree/v0.1.3) (2018-06-11)

#### Merged Pull Requests
- [MSYS-836] fixes for ruby2.0 and FFI destroy object messages  [#32](https://github.com/chef/win32-certstore/pull/32) ([piyushawasthi](https://github.com/piyushawasthi))
- Add badges to the readme [#25](https://github.com/chef/win32-certstore/pull/25) ([tas50](https://github.com/tas50))
- [MSYS-837] Update Travis for Ruby multiple version and add Chefstyle to Travis [#33](https://github.com/chef/win32-certstore/pull/33) ([piyushawasthi](https://github.com/piyushawasthi))



<!-- usage documentation: http://expeditor-docs.es.chef.io/configuration/changelog/ -->
<!-- latest_release 0.1.0 -->
## [v0.1.0](https://github.com/chef/win32-certstore/commits) (2018-04-19)

* Added support to validate a certificate in a certificate store on the basis of time validity [#20](https://github.com/chef/win32-certstore/pull/20) ([piyushawasthi](https://github.com/piyushawasthi))
* Added support to search for a certificate in an open certificate store [#18](https://github.com/chef/win32-certstore/pull/18) ([piyushawasthi](https://github.com/piyushawasthi))
* Added support to delete a certificate from a certificate store [#21](https://github.com/chef/win32-certstore/pull/21) ([piyushawasthi](https://github.com/piyushawasthi))
* Added support to list all certificates in a certificate store [#3](https://github.com/chef/win32-certstore/pull/3) ([piyushawasthi](https://github.com/piyushawasthi))
* Added support to get OpenSSL::X509 certificate object [#19](https://github.com/chef/win32-certstore/pull/19) ([piyushawasthi](https://github.com/piyushawasthi))
* Re-design the structure of Win32-certstore and adding certificate in certificate store [#16](https://github.com/chef/win32-certstore/pull/16) ([piyushawasthi](https://github.com/piyushawasthi))