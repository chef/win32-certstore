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

require_relative "certstore/mixin/crypto"
require_relative "certstore/mixin/assertions"
require_relative "certstore/mixin/string"
require_relative "certstore/store_base"
require_relative "certstore/version"

module Win32
  class Certstore
    include Win32::Certstore::Mixin::Crypto
    extend Win32::Certstore::Mixin::Assertions
    include Win32::Certstore::Mixin::String
    include Win32::Certstore::StoreBase

    attr_reader :store_name

    def initialize(store_name)
      @certstore_handler = open(store_name)
    end

    # To open given certificate store
    def self.open(store_name)
      validate_store(store_name)
      if block_given?
        yield new(store_name)
      else
        new(store_name)
      end
    end

    # Adding New certificate to open certificate store
    def add(certificate_obj)
      cert_add(certstore_handler, certificate_obj)
    end

    # Get certificate from certificate store and return certificate object
    def get(certificate_thumbprint)
      cert_get(certstore_handler, certificate_thumbprint)
    end

    # Listing all certificate of open certificate store and return in certificates list
    def list
      cert_list(certstore_handler)
    end

    # Delete existing certificate from open certificate store
    def delete(certificate_thumbprint)
      cert_delete(certstore_handler, certificate_thumbprint)
    end

    # Search certificate from open certificate store and return certificates objects
    def search(certificate_name)
      cert_search(certstore_handler, certificate_name)
    end

    # To close and destroy pointer of open certificate store handler
    def close
      closed = CertCloseStore(@certstore_handler, CERT_CLOSE_STORE_FORCE_FLAG)
      unless closed
        last_error = FFI::LastError.error
        raise SystemCallError.new("Unable to close the Certificate Store.", last_error)
      end
      remove_finalizer
    end

    private

    attr_reader :certstore_handler

    # To open certstore and return open certificate store pointer
    def open(store_name)
      certstore_handler = CertOpenSystemStoreW(nil, wstring(store_name))
      unless certstore_handler
        last_error = FFI::LastError.error
        raise SystemCallError.new("Unable to open the Certificate Store `#{store_name}`.", last_error)
      end
      add_finalizer(certstore_handler)
      certstore_handler
    end

    # Get all open certificate store handler
    def add_finalizer(certstore_handler)
      ObjectSpace.define_finalizer(self, self.class.finalize(certstore_handler))
    end

    def self.finalize(certstore_handler)
      proc { puts "DESTROY OBJECT #{certstore_handler}" }
    end

    # To close all open certificate store at the end
    def remove_finalizer
      ObjectSpace.undefine_finalizer(self)
    end
  end
end
