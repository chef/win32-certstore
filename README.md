# win32-certstore
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

This method add new certificate in a open certificate store. 

```
Input   - Certificate Object (OpenSSL::X509)
Return  - True/False
```

**Notes: The new certificate should be converted in OpenSSL::X509**

```
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

Win32::Certstore.open('Root') do |store|
  store.add(certificate_object)
end
```
    or
```
raw = File.read "C:\GlobalSignRootCA.pem" 
certificate_object = OpenSSL::X509::Certificate.new raw

store = Win32::Certstore.open('Root')
store.add(certificate_object)
store.close
```

### Get certificate

This method get certificate object from open certificate store.

```
Input   - Certificate thumbprint
Return  - Certificate Object (OpenSSL::X509)
```

```
Win32::Certstore.open("Root") do |store|
    store.get(certificate_thumbprint)
end
```
    or
```
store = Win32::Certstore.open("Root")
store.get(certificate_thumbprint)
store.close
```

### List certificates

This method lists all certificates from open certificate store.

```
Input   - NA
Return  - Certificate List in JSON format.
```

```
Win32::Certstore.open("Root") do |store|
    store.list
end
```
    or
```
store = Win32::Certstore.open("Root")
store.list
store.close
```

### Delete certificate

This method delete certificate from open certificate store.

```
Input   - Certificate thumbprint
Return  - True/False 
```

```
Win32::Certstore.open("Root") do |store|
    store.delete(certificate_thumbprint)
end
```
    or
```
store = Win32::Certstore.open("Root")
store.delete(certificate_thumbprint)
store.close
```

### Search certificate

This method search certificate from open certificate store.

```
Input   - Search Token as: Comman name, Friendly name, RDN and other attributes
Return  - Matching certificate list 
```

```
Win32::Certstore.open("Root") do |store|
    store.search(search_token)
end
```
    or
```
store = Win32::Certstore.open("Root")
store.search(search_token)
store.close
```

### Validate certificate

This method validate certificate from open certificate store.

```
Input   - Certificate thumbprint
Return  - True/False 

```

```
Win32::Certstore.open("Root") do |store|
    store.valid?(certificate_thumbprint)
end
```
    or
```
store = Win32::Certstore.open("Root")
store.valid?(certificate_thumbprint)
store.close
```

### Perform multiple operations

To perform more than one operations with single certificate store object

```
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

Win32::Certstore.open('Root') do |store|
  store.add(certificate_object)
  store.list
end
```
    or
```
raw = File.read "C:\GlobalSignRootCA.pem" 
certificate_object = OpenSSL::X509::Certificate.new raw

store = Win32::Certstore.open('Root')
store.add(certificate_object)
store.list
store.close
```

## Requirements / setup

### Ruby

Ruby 1.9.3+ is required.

## CONTRIBUTING:

Please file bugs against the WIN32-CERTSTORE project at https://github.com/chef/win32-certstore/issues.

More information on the contribution process for Chef projects can be found in the [Chef Contributions document](http://docs.chef.io/community_contributions.html).

# LICENSE:

Author:: Bryan McLellan (<btm@chef.io>)
Copyright:: 2017-2018 Chef Software, Inc.
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
