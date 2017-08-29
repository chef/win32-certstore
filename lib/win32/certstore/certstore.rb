#
# Author:: Nimisha Sharad (<nimisha.sharad@msystechnologies.com>)
# Copyright:: Copyright (c) 2017 Chef Software, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'win32/store/assertions'
require 'win32/store/crypto'
require 'pry'

module Win32
  class Certstore
    extend Win32::Store::Assertions
    extend Win32::Store::Crypto
    extend Chef::Mixin::ShellOut
    extend Chef::Mixin::WideString

    def self.open(store_name)
      certstore_handle = CertOpenSystemStoreW(nil, wstring(store_name))
      unless certstore_handle
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to open the Certificate Store `#{store_name}` with error: #{last_error}."
      end
      certstore_handle
    end

    def self.close(certstore_handle)
      include Win32::Store::Crypto
      closed = CertCloseStore(certstore_handle, CERT_CLOSE_STORE_FORCE_FLAG)
      unless closed
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to close the Certificate Store with error: #{last_error}."
      end
      closed
    end

    # CA -> Certification authority certificates.
    # MY -> A certificate store that holds certificates with associated private keys.
    # ROOT -> Root certificates.
    # SPC -> Software Publisher Certificate.

    def self.list_cert(certstore_name)
      # TO verify Valid ceritificate store name
      validate_store(certstore_name)
      # Open Valid certificate store
      store_handle = open(certstore_name)
      list = Win32::Certstore::Certificate.list(store_handle)
      # Close Open store
      close(store_handle)
      return list
    end

    def self.add_cert(*args)
      certstore_name = args.first
      # TO verify Valid ceritificate store name
      validate_store(certstore_name)
      # Open Valid certificate store
      store_handle = open(certstore_name)
      add = Win32::Certstore::Certificate.new(store_handle, args.last)
      close(store_handle)
      return add
    end

  end
end
