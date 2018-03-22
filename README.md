# win32-certstore
Ruby library for accessing the certificate store on Microsoft Windows:

## Subcommands

This library provides the following features.

### Open certificate store

Any valid certificate store can be opened in two ways:

**Notes: Valid certificate store names:  
  `CA -> Certification authority certificates.`  
  `MY -> A certificate store that holds certificates with associated private keys.`  
  `ROOT -> Root certificates.`  
  `SPC -> Software Publisher Certificate.`**

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

Add a valid certificate in a certificate store. 

**Notes: The new certificate should be converted in OpenSSL::X509 :**

```
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

Win32::Certstore.open('Root') do |store|
  store.add(certificate_object)
  store.close
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

### List certificates

Lists certificates of a valid certificate store and returns output in JSON format:

```
Win32::Certstore.open("Root") do |store|
    store.list
    store.close
end
```
    or
```
store = Win32::Certstore.open("Root")
store.list
store.close
```

### Delete certificate

Deletes a certificate from certificate store and returns output in string format.

**Notes: The certificate_name should be valid `CN or Common Name` of the certificate :**

```
certificate_name = 'Root Agency'
Win32::Certstore.open("Root") do |store|
    store.delete(certificate_name)
    store.close
end
```
    or
```
store = Win32::Certstore.open("Root")
store.delete(certificate_name)
store.close
```

### Retrieve certificate

Retrieve properties of a certificate from certificate store and returns output in hash format.

**Notes: The certificate_name should be valid `CN or Common Name` of the certificate**

```
certificate_name = 'GlobalSign Root CA'
Win32::Certstore.open("Root") do |store|
    store.retrieve(certificate_name)
    store.close
end
```
    or
```
store = Win32::Certstore.open("Root")
store.retrieve(certificate_name)
store.close
```

### Perform multiple operations

You can perform more that one oprations with single certificate store object

```
raw = File.read "C:\GlobalSignRootCA.pem"
certificate_object = OpenSSL::X509::Certificate.new raw

Win32::Certstore.open('Root') do |store|
  store.add(certificate_object)
  store.list
  store.close
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

### Chef version

This library requires >= Chef 11.0.0.

## CONTRIBUTING:

Please file bugs against the WIN32-CERTSTORE project at https://github.com/chef/win32-certstore/issues.

More information on the contribution process for Chef projects can be found in the [Chef Contributions document](http://docs.chef.io/community_contributions.html).

# LICENSE:

Author:: Bryan McLellan (<btm@chef.io>)
Copyright:: Copyright (c) 2017 Chef Software, Inc.
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
