_This file holds "in progress" release notes for the current release under development and is intended for consumption by the Chef Documentation team. Please see <https://docs.chef.io/release_notes.html> for the official Chef release notes._


# win32-certstore 0.1.0 release notes:
In this release we have added features for adding certificate in certificate store, get OpenSSL::X509 certificate object, lists all certificates in a certificate store, deletes a certificate from a certificate store, searches for a certificate in an open certificate store and validates a certificate in a certificate store on the basis of time validity.

## Features added in win32-certstore 0.1.0

* Added support to validate a certificate in a certificate store on the basis of time validity [#20](https://github.com/chef/win32-certstore/pull/20) ([piyushawasthi](https://github.com/piyushawasthi))

* Added support to search for a certificate in an open certificate store [#18](https://github.com/chef/win32-certstore/pull/18) ([piyushawasthi](https://github.com/piyushawasthi))

* Added support to delete a certificate from a certificate store [#21](https://github.com/chef/win32-certstore/pull/21) ([piyushawasthi](https://github.com/piyushawasthi))

* Added support to list all certificates in a certificate store [#3](https://github.com/chef/win32-certstore/pull/3) ([piyushawasthi](https://github.com/piyushawasthi))

* Added support to get OpenSSL::X509 certificate object [#19](https://github.com/chef/win32-certstore/pull/19) ([piyushawasthi](https://github.com/piyushawasthi))

* Added support to add new certificate in certificate store [#16](https://github.com/chef/win32-certstore/pull/16) ([piyushawasthi](https://github.com/piyushawasthi))