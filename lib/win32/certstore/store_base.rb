#
# Author:: Piyush Awasthi (<piyush.awasthi@msystechnologies.com>)
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

require_relative "mixin/crypto"
require_relative "mixin/string"
require_relative "mixin/shell_out"
require_relative "mixin/unicode"
require "openssl"
require "json"

module Win32
  class Certstore
    module StoreBase
      include Win32::Certstore::Mixin::Crypto
      include Win32::Certstore::Mixin::Assertions
      include Win32::Certstore::Mixin::String
      include Win32::Certstore::Mixin::ShellOut
      include Win32::Certstore::Mixin::Unicode
      include Win32::Certstore::Mixin::Helper

      # Adding new certification in open certificate and return boolean
      # store_handler => Open certificate store handler
      # certificate_obj => certificate object must be in OpenSSL::X509
      def cert_add(store_handler, certificate_obj)
        validate_certificate_obj(certificate_obj)
        begin
          cert_args = cert_add_args(store_handler, certificate_obj)
          if CertAddEncodedCertificateToStore(*cert_args)
            true
          else
            lookup_error
          end
        rescue
          lookup_error("add")
        end
      end

      # Adds a PFX certificate to certificate store
      #
      # @see https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-pfximportcertstore PFXImportCertStore function
      # @see https://docs.microsoft.com/en-us/windows/desktop/api/wincrypt/nf-wincrypt-certaddcertificatecontexttostore CertAddCertificateContextToStore
      #
      # @param certstore_handler [FFI::Pointer] Handle of the store where certificate should be imported
      # @param path [String] Path of the certificate that should be imported
      # @param password [String] Password of the certificate
      # @param key_properties [Integer] dwFlags used to specify properties of the pfx key, see link above
      #
      # @return [Boolean]
      #
      # @raise [SystemCallError] when Crypt API would not be able to perform some action
      #
      def cert_add_pfx(certstore_handler, path, password = "", key_properties = 0)
        cert_added = false
        # Imports a PFX BLOB and returns the handle of a store
        pfx_cert_store = PFXImportCertStore(CRYPT_DATA_BLOB.new(File.binread(path)), wstring(password), key_properties)
        raise if pfx_cert_store.null?

        # Find all the certificate contexts in certificate store and add them ino the store
        while (cert_context = CertEnumCertificatesInStore(pfx_cert_store, cert_context)) && (not cert_context.null?)
          # Add certificate context to the certificate store
          args = add_certcontxt_args(certstore_handler, cert_context)
          cert_added = CertAddCertificateContextToStore(*args)
          raise unless cert_added
        end
        cert_added
      rescue
        lookup_error("Add a PFX")
      ensure
        if pfx_cert_store && !pfx_cert_store.null?
          close_cert_store(pfx_cert_store)
        end
      end

      # Get certificate from open certificate store and return certificate object
      # certificate_thumbprint => thumbprint is a hash. which could be sha1 or md5.
      def cert_get(certificate_thumbprint)
        validate_thumbprint(certificate_thumbprint)
        thumbprint = update_thumbprint(certificate_thumbprint)
        cert_pem = get_cert_pem(thumbprint)
        cert_pem = format_pem(cert_pem)
        unless cert_pem.empty?
          build_openssl_obj(cert_pem)
        end
      end

      # Listing certificate of open certstore and return list in json
      def cert_list(store_handler)
        cert_name = memory_ptr
        cert_list = []
        begin
          while (pcert_context = CertEnumCertificatesInStore(store_handler, pcert_context)) && (not pcert_context.null?)
            cert_args = cert_get_name_args(pcert_context, cert_name, CERT_NAME_FRIENDLY_DISPLAY_TYPE)
            if CertGetNameStringW(*cert_args)
              cert_list << cert_name.read_wstring
            end
          end
          CertFreeCertificateContext(pcert_context)
        rescue
          lookup_error("list")
        end
        cert_list.to_json
      end

      # Deleting certificate from open certificate store and return boolean
      # store_handler => Open certificate store handler
      # certificate_thumbprint => thumbprint is a hash. which could be sha1 or md5.
      def cert_delete(store_handler, certificate_thumbprint)
        validate_thumbprint(certificate_thumbprint)
        thumbprint = update_thumbprint(certificate_thumbprint)
        cert_delete_flag = false
        begin
          cert_args = cert_find_args(store_handler, thumbprint)
          pcert_context = CertFindCertificateInStore(*cert_args)
          unless pcert_context.null?
            cert_delete_flag = CertDeleteCertificateFromStore(CertDuplicateCertificateContext(pcert_context)) || lookup_error
          end
          CertFreeCertificateContext(pcert_context)
        rescue
          lookup_error("delete")
        end
        cert_delete_flag
      end

      # Verify certificate from open certificate store and return boolean or exceptions
      # store_handler => Open certificate store handler
      # certificate_thumbprint => thumbprint is a hash. which could be sha1 or md5.
      def cert_validate(certificate_thumbprint)
        validate_thumbprint(certificate_thumbprint)
        thumbprint = update_thumbprint(certificate_thumbprint)
        cert_pem = get_cert_pem(thumbprint)
        cert_pem = format_pem(cert_pem)
        verify_certificate(cert_pem)
      end

      # Search certificate from open certificate store and return list
      # store_handler => Open certificate store handler
      # search_token => CN, RDN or any certificate attribute
      def cert_search(store_handler, search_token)
        raise ArgumentError, "Invalid search token" if !search_token || search_token.strip.empty?

        certificate_list = []
        begin
          while (pcert_context = CertEnumCertificatesInStore(store_handler, pcert_context)) && !pcert_context.null?
            cert_property = get_cert_property(pcert_context)
            if cert_property.include?(search_token)
              certificate_list << [cert_property[CERT_NAME_FRIENDLY_DISPLAY_TYPE], cert_property[CERT_NAME_RDN_TYPE]]
            end
          end
          CertFreeCertificateContext(pcert_context)
        rescue
          lookup_error
        end
        certificate_list
      end

      # To close and destroy pointer of open certificate store handler
      def close_cert_store(certstore_handler = @certstore_handler)
        closed = CertCloseStore(certstore_handler, CERT_CLOSE_STORE_FORCE_FLAG)
        lookup_error("close") unless closed
      end

      private

      # Build arguments for CertAddEncodedCertificateToStore
      def cert_add_args(store_handler, certificate_obj)
        [store_handler, X509_ASN_ENCODING, der_cert(certificate_obj), certificate_obj.to_s.bytesize, 2, nil]
      end

      # Build arguments for CertFindCertificateInStore
      def cert_find_args(store_handler, thumbprint)
        [store_handler, ENCODING_TYPE, 0, CERT_FIND_SHA1_HASH, CRYPT_HASH_BLOB.new(thumbprint), nil]
      end

      # Build arguments for CertAddCertificateContextToStore
      def add_certcontxt_args(certstore_handler, cert_context)
        [certstore_handler, cert_context, CERT_STORE_ADD_REPLACE_EXISTING, nil]
      end

      # Match certificate CN exist in cert_rdn
      def is_cn_match?(cert_rdn, certificate_name)
        cert_rdn.read_wstring.match(/(^|\W)#{certificate_name}($|\W)/i)
      end

      # Get Certificate all properties
      def get_cert_property(pcert_context)
        property_value = memory_ptr
        property_list = []
        property_list[0] = ""
        (1..8).to_a.each do |property_type|
          CertGetNameStringW(pcert_context, property_type, CERT_NAME_ISSUER_FLAG, nil, property_value, 1024)
          property_list << property_value.read_wstring
        end
        property_list
      end

      # Build argument for CertGetNameStringW
      def cert_get_name_args(pcert_context, cert_name, search_type)
        [pcert_context, search_type, CERT_NAME_ISSUER_FLAG, nil, cert_name, 1024]
      end

      # Remove extra space and : from thumbprint
      def update_thumbprint(certificate_thumbprint)
        certificate_thumbprint.gsub(/[^A-Za-z0-9]/, "")
      end

      # Verify OpenSSL::X509::Certificate object
      def verify_certificate(cert_pem)
        return "Certificate not found" if cert_pem.empty?

        valid_duration?(build_openssl_obj(cert_pem))
      end

      # Convert OpenSSL::X509::Certificate object in .der formate
      def der_cert(cert_obj)
        FFI::MemoryPointer.from_string(cert_obj.to_der)
      end

      # Get certificate pem
      def get_cert_pem(thumbprint)
        get_data = powershell_out!(cert_ps_cmd(thumbprint, store_name))
        get_data.stdout
      end

      # Format pem
      def format_pem(cert_pem)
        cert_pem.delete("\r")
      end

      # Build pem to OpenSSL::X509::Certificate object
      def build_openssl_obj(cert_pem)
        OpenSSL::X509::Certificate.new(cert_pem)
      end

      # Create empty memory pointer
      def memory_ptr
        FFI::MemoryPointer.new(2, 256)
      end
    end
  end
end
