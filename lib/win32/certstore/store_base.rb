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

require_relative 'mixin/crypto'
require_relative 'mixin/string'
require_relative 'mixin/shell_out'
require_relative 'mixin/unicode'
require 'openssl'
require 'json'
require 'tempfile'

module Win32
  class Certstore
    module StoreBase
      include Win32::Certstore::Mixin::Crypto
      include Win32::Certstore::Mixin::Assertions
      include Win32::Certstore::Mixin::String
      include Win32::Certstore::Mixin::ShellOut
      include Win32::Certstore::Mixin::Unicode

      # Listing certificate of open certstore and return list in json
      def cert_list(store_handler)
        cert_name = FFI::MemoryPointer.new(2, 128)
        cert_list = []

        begin
          while (pCertContext = CertEnumCertificatesInStore(store_handler, pCertContext) and not pCertContext.null? ) do
            if (CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil, cert_name, 1024))
              cert_list << cert_name.read_wstring
            end
          end

          CertFreeCertificateContext(pCertContext)
        rescue Exception => e
          lookup_error("list")
        end
        cert_list.to_json
      end
      
      # Adding new certification in open certificate store return boolean
      def cert_add(store_handler, cert_file_path)
        validate_certificate(cert_file_path)
        file_content = d(cert_file_path)
        pointer_cert = FFI::MemoryPointer.from_string(file_content)
        cert_length = file_content.bytesize
        begin
          if (CertAddEncodedCertificateToStore(store_handler, X509_ASN_ENCODING, pointer_cert, cert_length, 2, nil))
            "Added certificate #{File.basename(cert_file_path)} successfully"
          else
            lookup_error
          end
        rescue Exception => e
          lookup_error("add")
        end
      end

      # Deleting certificate from open certificate store and return boolean 
      def cert_delete(store_handler, certificate_name)
        begin
          if ( !certificate_name.empty? and pCertContext = CertFindCertificateInStore(store_handler, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR, certificate_name.to_wstring, nil) and not pCertContext.null? )
            if CertDeleteCertificateFromStore(CertDuplicateCertificateContext(pCertContext))
              return "Deleted certificate #{certificate_name} successfully"
            else
              lookup_error
            end
          end
          return "Cannot find certificate with name as `#{certificate_name}`. Please re-verify certificate Issuer name or Friendly name"
        rescue Exception => e
          @error = "delete: "
          lookup_error
        end
      end

      def cert_retrieve(store_handler, certificate_name)
        property_value = FFI::MemoryPointer.new(2, 128)
        retrieve = { CERT_NAME_EMAIL_TYPE: nil, CERT_NAME_RDN_TYPE: nil, CERT_NAME_ATTR_TYPE: nil,
          CERT_NAME_SIMPLE_DISPLAY_TYPE: nil, CERT_NAME_FRIENDLY_DISPLAY_TYPE: nil, CERT_NAME_DNS_TYPE: nil,
          CERT_NAME_URL_TYPE: nil, CERT_NAME_UPN_TYPE: nil }
        begin
          if ( !certificate_name.empty? and pCertContext = CertFindCertificateInStore(store_handler, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR, certificate_name.to_wstring, nil) and not pCertContext.null? )
            retrieve.each do |property_type, value|
              CertGetNameStringW(pCertContext, eval(property_type.to_s), CERT_NAME_ISSUER_FLAG, nil, property_value, 1024)
              retrieve[property_type] = property_value.read_wstring
            end
            return retrieve
          end
          return "Cannot find certificate with name as `#{certificate_name}`. Please re-verify certificate Issuer name"
        rescue Exception => e
          @error = "retrieve: "
          lookup_error
        end
      end
      
      # Verifying certificate from open certificate store and return certificate time validity
      def cert_verification(store_handler, certificate_name)
        begin
          cert_name = FFI::MemoryPointer.new(2, 128)
          cert_list = []
          if ( pCertContext = CertFindCertificateInStore(store_handler, X509_ASN_ENCODING, 0, CERT_FIND_ISSUER_STR, certificate_name.to_wstring, nil) and not pCertContext.null? )
            pTargetCertInfo = CERT_INFO.new(pCertContext)
            encoded_cert = FFI::MemoryPointer.new(2, 128)
            
            out = FFI::MemoryPointer.new(2, 128)
            cert_context = CERT_CONTEXT.new
            cert_context[:dwCertEncodingType] = X509_ASN_ENCODING
            cert_context[:pbCertEncoded] = encoded_cert
            cert_context[:cbCertEncoded] = encoded_cert.size
            cert_context[:pCertInfo] = pTargetCertInfo
            cert_context[:hCertStore] = store_handler

            ctl_usages = CTL_USAGE.new
            ctl_usages[:cUsageIdentifier]=1
            ctl_usages[:rgpszUsageIdentifier]=pTargetCertInfo

            if CertVerifyCTLUsage(X509_ASN_ENCODING, 1, cert_context, ctl_usages, 1, nil, out)
              return "Certificate's time is valid."
            else
              return "Certificate is not valid yet."
            end
          end
          return "Cannot find certificate with name as `#{certificate_name}`. Please re-verify certificate Issuer name or Friendly name"
        rescue Exception => e
          @error = "Verify: "
          lookup_error
        end
      end 

      private

      # Lookup the generic error
      def lookup_error(failed_operation = nil)
        error_no = FFI::LastError.error
        case error_no
        when 1223
          raise SystemCallError.new("The operation was canceled by the user", error_no)
        when -2146885628
          raise SystemCallError.new("Cannot find ojject or property", error_no)
        when -2146885629
          raise SystemCallError.new("An error occurred while reading or writing to a file.", error_no)
        when -2146881269
          raise SystemCallError.new("ASN1 bad tag value met. -- Is the certificate in DER format?", error_no)
        when -2146881278
          raise SystemCallError.new("ASN1 unexpected end of data.", error_no)
        when -2147024891
          raise SystemCallError.new("System.UnauthorizedAccessException, Access denied..", error_no)
        else
          raise SystemCallError.new("Unable to #{failed_operation} certificate.", error_no)
        end
      end

      # This is a single public certificate in X509 DER format.
      # If your certificate has a header and footer line like "---- BEGIN CERTIFICATE ----" then it is in PEM format, not DER format.
      # A certificate can be converted with `openssl x509 -in example.crt -out example.der -outform DER`
      def read_certificate_content(cert_path)
        unless (File.extname(cert_path) == ".der")
          temp_file_path = Tempfile.new(['TempCert', '.der']).path
          shell_out_command("powershell.exe -Command openssl x509 -in #{cert_path} -outform DER -out #{temp_file_path}")
          cert_path = temp_file_path
        end
        File.read("#{cert_path}")
      end
    end
  end
end
