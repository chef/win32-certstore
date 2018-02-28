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
        rescue Exception => e
          lookup_error("add")
        end
      end

      # Get certificate from open certificate store and return certificate object
      # store_handler => Open certificate store handler
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
          while (pcert_context = CertEnumCertificatesInStore(store_handler, pcert_context)) && (not pcert_context.null?) do
            cert_args = cert_get_name_args(pcert_context, cert_name, CERT_NAME_FRIENDLY_DISPLAY_TYPE)
            if CertGetNameStringW(*cert_args)
              cert_list << cert_name.read_wstring
            end
          end
          CertFreeCertificateContext(pcert_context)
        rescue Exception => e
          lookup_error("list")
        end
        cert_list.to_json
      end

      # Deleting certificate from open certificate store and return boolean
      # store_handler => Open certificate store handler
      # certificate_thumbprint => thumbprint is a hash. which could be sha1 or md5.
      def cert_delete(store_handler, certificate_thumbprint)
        validate_thumbprint(certificate_thumbprint)
        cert_name = memory_ptr
        thumbprint = update_thumbprint(certificate_thumbprint)
        cert_pem = format_pem(get_cert_pem(thumbprint))
        cert_rdn = get_rdn(build_openssl_obj(cert_pem))
        cert_delete_flag = false
        begin
          cert_args = cert_find_args(store_handler, cert_rdn)
          if (pcert_context = CertFindCertificateInStore(*cert_args) and !pcert_context.null?)
            cert_delete_flag = CertDeleteCertificateFromStore(CertDuplicateCertificateContext(pcert_context)) || lookup_error
          end
          CertFreeCertificateContext(pcert_context)
        rescue Exception => e
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
        cert_rdn = memory_ptr
        certificate_list =[]
        counter = 0
        begin
          while (pcert_context = CertEnumCertificatesInStore(store_handler, pcert_context) and !pcert_context.null?)
            cert_property = get_cert_property(pcert_context)
            if cert_property.include?(search_token)
              certificate_list << [cert_property[CERT_NAME_FRIENDLY_DISPLAY_TYPE], cert_property[CERT_NAME_RDN_TYPE]]
            end
          end
          CertFreeCertificateContext(pcert_context)
        rescue Exception => e
          lookup_error
        end
        certificate_list
      end

      private

      # Build arguments for CertAddEncodedCertificateToStore
      def cert_add_args(store_handler, certificate_obj)
        [store_handler, X509_ASN_ENCODING, der_cert(certificate_obj), certificate_obj.to_s.bytesize, 2, nil]
      end

      # Build arguments for CertFindCertificateInStore
      def cert_find_args(store_handler, cert_rdn)
        [store_handler, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR, cert_rdn.to_wstring, nil]
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
        certificate_thumbprint.gsub(/[^A-Za-z0-9]/, '')
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
        get_data =  powershell_out!(cert_ps_cmd(thumbprint))
        get_data.stdout
      end

      # To get RDN from certificate object
      def get_rdn(cert_obj)
        cert_obj.issuer.to_s.concat("/").scan(/=(.*?)\//).join(", ")
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
