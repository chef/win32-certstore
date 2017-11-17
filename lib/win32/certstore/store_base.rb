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
require 'openssl'
require 'open3'

module Win32
  class Certstore
    module StoreBase
      include Win32::Certstore::Mixin::Crypto
      include Win32::Certstore::Mixin::Assertions
      include Chef::Mixin::WideString
      include Chef::Mixin::ShellOut

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
      
      def cert_add(store_handler, cert_file_path)
        validate_certificate(cert_file_path)
        file_content = read_certificate_content(cert_file_path)
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

      private

      def lookup_error(failed_operation = nil)
        last_error = FFI::LastError.error
        case last_error
        when 1223
          raise Chef::Exceptions::Win32APIError, "The operation was canceled by the user."
        when -2146885628
          raise Chef::Exceptions::Win32APIError, "Cannot find object or property."
        when -2146885629
          raise Chef::Exceptions::Win32APIError, "An error occurred while reading or writing to a file."
        when -2146881269
          raise Chef::Exceptions::Win32APIError, "ASN1 bad tag value met. -- Is the certificate in DER format?"
        when -2146881278
          raise Chef::Exceptions::Win32APIError, "ASN1 unexpected end of data."
        else
          raise Chef::Exceptions::Win32APIError, "Unable to #{failed_operation} certificate with error: #{last_error}."
        end
      end

      # This is a single public certificate in X509 DER format.
      # If your certificate has a header and footer line like "---- BEGIN CERTIFICATE ----" then it is in PEM format, not DER format.
      # A certificate can be converted with `openssl x509 -in example.crt -out example.der -outform DER`
      def read_certificate_content(cert_path)
        unless (File.extname(cert_path) == ".der")
          output = Open3.capture3("powershell.exe -Command $env:temp")
          raise RuntimeError,output[1] unless output[2].success?
          temp_file = output[0].strip.concat("\\TempCert.der")
          output = Open3.capture3("powershell.exe -Command openssl x509 -in #{cert_path} -outform DER -out #{temp_file}")
          raise RuntimeError,output[1] unless output[2].success?
          cert_path = temp_file
        end
        File.read("#{cert_path}")
      end

    end
  end
end
