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

### List certificates

Lists certificates of a valid certificate store and returns output in JSON format:

```
Win32::Certstore.open("Root") do |store|
    store.list
end
```
	or 
```
store = Win32::Certstore.open("Root")
store.list
```

### Add certificate

Add a valid certificate in a certificate store. 

**Notes: The new certificate should be in the following formats `.cer|.crt|.pfx|.der`:**

```
Win32::Certstore.open("Root") do |store|
    store.add(certificate_file_path)
end
```
	or 
```
store = Win32::Certstore.open("Root")
store.add(certificate_file_path)
```

### Delete certificate

Deletes a certificate from certificate store and returns output in string format.

**Notes: The certificate_name should be valid `CN or Common Name` of the certificate **

```
certificate_name = 'Root Agency'
Win32::Certstore.open("Root") do |store|
    store.delete(certificate_name)
end
```
    or
```
store = Win32::Certstore.open("Root")
store.delete(certificate_name)
```

### Retrieve certificate

Retrieve properties of a certificate from certificate store and returns output in hash format.

**Notes: The certificate_name should be valid `CN or Common Name` of the certificate**

```
certificate_name = 'GlobalSign Root CA'
Win32::Certstore.open("Root") do |store|
    store.retrieve(certificate_name)
end
```
    or
```
store = Win32::Certstore.open("Root")
store.retrieve(certificate_name)
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
