# win32-certstore
[![Build status](https://badge.buildkite.com/ba68b9ac04486e2ddf6587b35c1eac00260d4216829c289ce6.svg?branch=main)](https://buildkite.com/chef-oss/chef-win32-certstore-main-verify)
[![Gem Version](https://badge.fury.io/rb/win32-certstore.svg)](https://badge.fury.io/rb/win32-certstore)

Ruby library for accessing the certificate store on Microsoft Windows:

## Subcommands

This library provides the following features.

### Open certificate store

Any valid certificate store can be opened in two ways:

```
Win32::Certstore.open("Root") do |store|
    //your code should be here!
end
```

or

```
store = Win32::Certstore.open("Root")
```

### Add certificate

This method adds a new certificate to an open certificate store.

```
Input   - Certificate Object (OpenSSL::X509)
Return  - True/False
```

**Notes: The certificate must be passed as an `OpenSSL::X509` object.**

```ruby
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

Win32::Certstore.open('Root') do |store|
  store.add(certificate_object)
end
```

or

```ruby
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

store = Win32::Certstore.open('Root')
store.add(certificate_object)
store.close
```

### Get certificate

Gets a certificate from an open certificate store and returns it as an `OpenSSL::X509` object.

```
Input   - Certificate thumbprint
Return  - Certificate Object (OpenSSL::X509)
```

```ruby
Win32::Certstore.open("Root") do |store|
    store.get(certificate_thumbprint)
end
```

or

```ruby
store = Win32::Certstore.open("Root")
store.get(certificate_thumbprint)
store.close
```

### List certificates

Lists all certificates in a certificate store.

```
Input   - NA
Return  - Certificate List in JSON format.
```

```ruby
Win32::Certstore.open("Root") do |store|
    store.list
end
```

or

```ruby
store = Win32::Certstore.open("Root")
store.list
store.close
```

### Delete certificate

Deletes a certificate from a certificate store.

```
Input   - Certificate thumbprint
Return  - True/False
```

```ruby
Win32::Certstore.open("Root") do |store|
    store.delete(certificate_thumbprint)
end
```

or

```ruby
store = Win32::Certstore.open("Root")
store.delete(certificate_thumbprint)
store.close
```

### Search certificate

Searches for a certificate in an open certificate store.

```
Input   - Search Token as: Comman name, Friendly name, RDN and other attributes
Return  - Matching certificate list
```

```ruby
Win32::Certstore.open("Root") do |store|
    store.search(search_token)
end
```

or

```ruby
store = Win32::Certstore.open("Root")
store.search(search_token)
store.close
```

### Validate certificate

Validates a certificate in a certificate store on the basis of time validity.

```
Input   - Certificate thumbprint
Return  - True/False

```

```ruby
Win32::Certstore.open("Root") do |store|
    store.valid?(certificate_thumbprint)
end
```

or

```ruby
store = Win32::Certstore.open("Root")
store.valid?(certificate_thumbprint)
store.close
```

### Performing multiple operations

To perform more than one operations with single certificate store object

```ruby
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

Win32::Certstore.open('Root') do |store|
  store.add(certificate_object)
  store.list
end
```

or

```ruby
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

store = Win32::Certstore.open('Root')
store.add(certificate_object)
store.list
store.close
```

## Requirements / setup

### Ruby

Ruby 2.5+ is required.

## Contributing

For information on contributing to this project see https://github.com/chef/chef/blob/main/CONTRIBUTING.md

More information on the contribution process for Chef projects can be found in the [Chef Contributions document](http://docs.chef.io/community_contributions.html).

# LICENSE

Author:: Bryan McLellan (<btm@chef.io>)
Copyright:: 2017-2021 Chef Software, Inc.
License:: Apache License, Version 2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
