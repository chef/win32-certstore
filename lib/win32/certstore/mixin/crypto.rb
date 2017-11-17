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
#

require 'ffi'
require 'chef'
require 'chef/win32/api'

module Win32
  class Certstore
  module Mixin
    module Crypto
      extend Chef::ReservedNames::Win32::API
      extend FFI::Library

      ffi_lib 'Crypt32'
      ffi_convention :stdcall

      ###############################################
      # Win32 API Constants
      ###############################################

      CERT_CLOSE_STORE_CHECK_FLAG                         = 0
      CERT_CLOSE_STORE_FORCE_FLAG                         = 1

      # cert encoding flags.
      CRYPT_ASN_ENCODING                                  = 0x00000001
      CRYPT_NDR_ENCODING                                  = 0x00000002
      X509_ASN_ENCODING                                   = 0x00000001
      X509_NDR_ENCODING                                   = 0x00000002
      PKCS_7_ASN_ENCODING                                 = 0x00010000
      PKCS_7_NDR_ENCODING                                 = 0x00020000
      PKCS_7_OR_X509_ASN_ENCODING                         = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

      # Certificate Display Format
      CERT_NAME_EMAIL_TYPE                                = 1
      CERT_NAME_RDN_TYPE                                  = 2
      CERT_NAME_ATTR_TYPE                                 = 3
      CERT_NAME_SIMPLE_DISPLAY_TYPE                       = 4
      CERT_NAME_FRIENDLY_DISPLAY_TYPE                     = 5
      CERT_NAME_DNS_TYPE                                  = 6
      CERT_NAME_URL_TYPE                                  = 7
      CERT_NAME_UPN_TYPE                                  = 8

      # List Certificates Flag
      CERT_NAME_ISSUER_FLAG                               = 0x1
      CERT_NAME_DISABLE_IE4_UTF8_FLAG                     = 0x00010000
      CERT_NAME_SEARCH_ALL_NAMES_FLAG                     = 0x2
      CERT_NAME_STR_ENABLE_PUNYCODE_FLAG                  = 0x00200000

      # Define ffi pointer
      HCERTSTORE                                          = FFI::TypeDefs[:pointer]
      HCRYPTPROV_LEGACY                                   = FFI::TypeDefs[:pointer]
      PCCERT_CONTEXT                                      = FFI::TypeDefs[:pointer]
      BYTE                                                = FFI::TypeDefs[:pointer]

      class CERT_CONTEXT < FFI::Struct
        layout :cbElement,   :DWORD,
        :pbElement,          :pointer
        def initialize(str = nil)
          super(nil)
          if str
            self[:pbElement] = FFI::MemoryPointer.from_string(str)
            self[:cbElement] = str.bytesize
          end
        end
      end

      ###############################################################################
      # Windows Function
      # To know description about below windows function
      # Search Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560
      ###############################################################################

      # To opens the most common system certificate store
      safe_attach_function :CertOpenSystemStoreW, [HCRYPTPROV_LEGACY, :LPCTSTR], HCERTSTORE
      # To close the already open certificate store
      safe_attach_function :CertCloseStore, [HCERTSTORE, :DWORD], :BOOL
      # To retrieves certificates in a certificate store
      safe_attach_function :CertEnumCertificatesInStore, [HCERTSTORE, PCCERT_CONTEXT], PCCERT_CONTEXT
      # To get certificate name
      safe_attach_function :CertGetNameStringW, [PCCERT_CONTEXT, :DWORD, :DWORD, :LPVOID, :LPTSTR, :DWORD], :DWORD
      # To find all of the property identifiers for the specified certificate.
      safe_attach_function :CertEnumCertificateContextProperties, [PCCERT_CONTEXT, :DWORD], :DWORD
      # Clean up
      safe_attach_function :CertFreeCertificateContext, [PCCERT_CONTEXT], :BOOL
      # Add certificate file in certificate store.
      safe_attach_function :CertAddSerializedElementToStore, [HCERTSTORE, :pointer, :DWORD, :DWORD, :DWORD, :DWORD, :LMSTR, :LPVOID], :BOOL
      # Add certification to certification store - Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376015(v=vs.85).aspx
      safe_attach_function :CertAddEncodedCertificateToStore, [HCERTSTORE, :DWORD, :PWSTR, :DWORD, :INT_PTR, PCCERT_CONTEXT], :BOOL

      safe_attach_function :CertSerializeCertificateStoreElement, [PCCERT_CONTEXT, :DWORD, :pointer, :DWORD], :BOOL
    end
  end
end
end
