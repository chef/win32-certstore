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
require_relative "certstore/mixin/helper"
require_relative "certstore/mixin/string"
require_relative "certstore/store_base"
require_relative "certstore/version"

module Win32
  class Certstore
    include Win32::Certstore::Mixin::Crypto
    extend Win32::Certstore::Mixin::Assertions
    include Win32::Certstore::Mixin::String
    include Win32::Certstore::StoreBase

    attr_accessor :store_name

    # Initializes a new instance of a certificate store.
    # takes 2 parameters - the store name (My, Root, etc) and the location (CurrentUser or LocalMachine), it defaults to LocalMachine for backwards compatibility
    def initialize(store_name, store_location: CERT_SYSTEM_STORE_LOCAL_MACHINE)
      @store_name = store_name
      @store_location = store_location
      @certstore_handler = open(store_name, store_location: store_location)
    end

    # To open given certificate store
    def self.open(store_name, store_location: CERT_SYSTEM_STORE_LOCAL_MACHINE)
      validate_store(store_name)
      if block_given?
        yield new(store_name, store_location: store_location)
      else
        new(store_name, store_location: store_location)
      end
    end

    # Adds a new certificate to an open certificate store
    # @param request [Object] of certificate in OpenSSL::X509::Certificate.new format
    # @return [true, false] only true or false
    def add(certificate_obj)
      cert_add(certstore_handler, certificate_obj)
    end

    # Adds a PFX certificate to certificate store
    #
    # @note Unlike other certificates, PFX can be password protected and may contain a private key.
    #       Therefore we need a different approach to import them.
    #
    # @param path [String] Path of the certificate that should be imported
    # @param password [String] Password of the certificate if it is protected
    # @param key_properties [Integer] dwFlags used to specify properties of the pfx key, see certstore/store_base.rb cert_add_pfx function
    #
    # @return [Boolean]
    #
    def add_pfx(path, password, key_properties = 0)
      cert_add_pfx(certstore_handler, path, password, key_properties)
    end

    # Return `OpenSSL::X509` certificate object
    # @param request [thumbprint<string>] of certificate
    # @return [Object] of certificates in OpenSSL::X509 format
    def get(certificate_thumbprint, store_name: @store_name, store_location: @store_location)
      cert_get(certificate_thumbprint, store_name: store_name, store_location: store_location)
    end

    # Returns all the certificates in a store
    # @param [nil]
    # @return [Array] array of certificates list
    def list
      cert_list(certstore_handler)
    end

    # Delete existing certificate from open certificate store
    # @param request [thumbprint<string>] of certificate
    # @return [true, false] only true or false
    def delete(certificate_thumbprint)
      cert_delete(certstore_handler, certificate_thumbprint)
    end

    # Returns all matching certificates in a store
    # @param request[search_token<string>] attributes of certificates as: CN, RDN, Friendly Name and other attributes
    # @return [Array] array of certificates list
    def search(search_token)
      cert_search(certstore_handler, search_token)
    end

    # Validates a certificate in a certificate store on the basis of time validity
    # @param request[thumbprint<string>] of certificate
    # @return [true, false] only true or false
    def valid?(certificate_thumbprint, store_location: "", store_name: "")
      cert_validate(certificate_thumbprint, store_location: store_location, store_name: store_name)
    end

    # To close and destroy pointer of open certificate store handler
    def close
      close_cert_store
      remove_finalizer
    end

    def self.finalize(certstore_handler)
      proc { certstore_handler.to_s }
    end

    private

    attr_reader :certstore_handler

    # To open certstore and return open certificate store pointer

    def open(store_name, store_location: CERT_SYSTEM_STORE_LOCAL_MACHINE)
      certstore_handler = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, nil, store_location, wstring(store_name))
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

    # To close all open certificate store at the end
    def remove_finalizer
      ObjectSpace.undefine_finalizer(self)
    end
  end
end
