#
# Author:: Nimisha Sharad (<nimisha.sharad@msystechnologies.com>)
# Copyright:: Copyright (c) 2017 Chef Software, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License")
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

require 'chef'
require 'mixlib/shellout'
require 'ffi'
require "chef/win32/api"
require 'openssl'

module Win32
  module Crypto
    module ReservedNames
      extend Chef::ReservedNames::Win32::API
      extend FFI::Library

      ffi_lib 'Crypt32'
      typedef :uintptr_t, :handle
      ###############################################
      # Win32 API Constants
      ###############################################

      CERT_CLOSE_STORE_CHECK_FLAG                         = 0
      CERT_CLOSE_STORE_FORCE_FLAG                         = 1
      # BYTE                        = []

      # PKCS_OR_X509_ASN_ENCODING   = (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

      # ASN.1 Encoding/Decoding Return Values
      CRYPT_E_ASN1_ERROR                                  = 0x80093100
      CRYPT_E_ASN1_INTERNAL                               = 0x80093101
      CRYPT_E_ASN1_EOD                                    = 0x80093102
      CRYPT_E_ASN1_CORRUPT                                = 0x80093103
      CRYPT_E_ASN1_LARGE                                  = 0x80093104
      CRYPT_E_ASN1_CONSTRAINT                             = 0x80093105
      CRYPT_E_ASN1_MEMORY                                 = 0x80093106
      CRYPT_E_ASN1_OVERFLOW                               = 0x80093107
      CRYPT_E_ASN1_BADPDU                                 = 0x80093108
      CRYPT_E_ASN1_BADARGS                                = 0x80093109
      CRYPT_E_ASN1_BADREAL                                = 0x8009310A
      CRYPT_E_ASN1_BADTAG                                 = 0x8009310B
      CRYPT_E_ASN1_CHOICE                                 = 0x8009310C
      CRYPT_E_ASN1_RULE                                   = 0x8009310D
      CRYPT_E_ASN1_UTF8                                   = 0x8009310E
      CRYPT_E_ASN1_PDU_TYPE                               = 0x80093133
      CRYPT_E_ASN1_NYI                                    = 0x80093134
      CRYPT_E_ASN1_EXTENDED                               = 0x80093201
      CRYPT_E_ASN1_NOEOD                                  = 0x80093202

      # cert encoding flags.
      CRYPT_ASN_ENCODING                                  = 0x00000001
      CRYPT_NDR_ENCODING                                  = 0x00000002
      X509_ASN_ENCODING                                   = 0x00000001
      X509_NDR_ENCODING                                   = 0x00000002
      PKCS_7_ASN_ENCODING                                 = 0x00010000
      PKCS_7_NDR_ENCODING                                 = 0x00020000
      PKCS_7_OR_X509_ASN_ENCODING                         = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)




      # Add certificate/CRL, encoded, context or element disposition values.
      CERT_STORE_ADD_NEW                                 = 1
      CERT_STORE_ADD_USE_EXISTING                        = 2
      CERT_STORE_ADD_REPLACE_EXISTING                    = 3
      CERT_STORE_ADD_ALWAYS                              = 4
      CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5
      CERT_STORE_ADD_NEWER                               = 6
      CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES            = 7

      # cert store provider
      CERT_STORE_PROV_MSG                                 = 1
      CERT_STORE_PROV_MEMORY                              = 2
      CERT_STORE_PROV_FILE                                = 3
      CERT_STORE_PROV_REG                                 = 4
      CERT_STORE_PROV_PKCS7                               = 5
      CERT_STORE_PROV_SERIALIZED                          = 6
      CERT_STORE_PROV_FILENAME_A                          = 7
      CERT_STORE_PROV_FILENAME_W                          = 8
      CERT_STORE_PROV_FILENAME                            = CERT_STORE_PROV_FILENAME_W
      CERT_STORE_PROV_SYSTEM_A                            = 9
      CERT_STORE_PROV_SYSTEM_W                            = 10
      CERT_STORE_PROV_SYSTEM                              = CERT_STORE_PROV_SYSTEM_W
      CERT_STORE_PROV_COLLECTION                          = 11
      CERT_STORE_PROV_SYSTEM_REGISTRY_A                   = 12
      CERT_STORE_PROV_SYSTEM_REGISTRY_W                   = 13
      CERT_STORE_PROV_SYSTEM_REGISTRY                     = CERT_STORE_PROV_SYSTEM_REGISTRY_W
      CERT_STORE_PROV_PHYSICAL_W                          = 14
      CERT_STORE_PROV_PHYSICAL                            = CERT_STORE_PROV_PHYSICAL_W
      CERT_STORE_PROV_SMART_CARD_W                        = 15
      CERT_STORE_PROV_SMART_CARD                          = CERT_STORE_PROV_SMART_CARD_W
      CERT_STORE_PROV_LDAP_W                              = 16
      CERT_STORE_PROV_LDAP                                = CERT_STORE_PROV_LDAP_W

      CERT_SYSTEM_STORE_CURRENT_USER                      = 1
      # Object Identifiers short hand.
      X509_EXTENSIONS            = 5
      X509_NAME_VALUE            = 6
      X509_NAME                  = 7
      X509_AUTHORITY_KEY_ID      = 9
      X509_KEY_USAGE_RESTRICTION = 11
      X509_BASIC_CONSTRAINTS     = 13
      X509_KEY_USAGE             = 14
      X509_BASIC_CONSTRAINTS2    = 15
      X509_CERT_POLICIES         = 16
      PKCS_UTC_TIME              = 17
      PKCS_ATTRIBUTE             = 22
      X509_UNICODE_NAME_VALUE    = 24
      X509_OCTET_STRING          = 25
      X509_BITS                  = 26
      X509_ANY_STRING            = X509_NAME_VALUE
      X509_UNICODE_ANY_STRING    = X509_UNICODE_NAME_VALUE
      X509_ENHANCED_KEY_USAGE    = 36
      PKCS_RC2_CBC_PARAMETERS    = 41
      X509_CERTIFICATE_TEMPLATE  = 64
      PKCS7_SIGNER_INFO          = 500
      CMS_SIGNER_INFO            = 501



      HCERTSTORE                                          = FFI::TypeDefs[:pointer]
      HCRYPTPROV_LEGACY                                   = FFI::TypeDefs[:pointer]
      PCCERT_CONTEXT                                      = FFI::TypeDefs[:pointer]
      BYTE                                                = FFI::TypeDefs[:pointer]

      class CERT_CONTEXT < FFI::Struct
        layout(
          :hCertStore,         :handle,
          :dwCertEncodingType, :DWORD,
          :pbCertEncoded,      :PWSTR,
          :cbCertEncoded,      :DWORD,
          :pCertInfo,          :pointer
        )
      end

      ffi_lib :crypt32
      safe_attach_function :CertOpenSystemStoreW, [HCRYPTPROV_LEGACY, :LPCTSTR], HCERTSTORE
      safe_attach_function :CryptEncodeObject, [:DWORD, :LMSTR, :pointer, :LPBYTE, :DWORD], :BOOL
      # Open certification store - Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560(v=vs.85).aspx
      safe_attach_function :CertOpenStore, [:INT_PTR, :INT_PTR, :PCRYPTPROTECT_PROMPTSTRUCT, :INT_PTR, :LPCTSTR], HCERTSTORE
      # Add certification to certification store - Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376015(v=vs.85).aspx
      safe_attach_function :CertAddEncodedCertificateToStore, [HCERTSTORE, :DWORD, :PWSTR, :DWORD, :INT_PTR, PCCERT_CONTEXT], :BOOL
      # Add certification to certification store - Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376015(v=vs.85).aspx
      safe_attach_function :CertAddCertificateContextToStore, [HCERTSTORE, :PLONG64, :DWORD, PCCERT_CONTEXT], :BOOL
      # Close certification store - Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376026(v=vs.85).aspx
      safe_attach_function :CertCloseStore, [HCERTSTORE, :DWORD], :BOOL
      ffi_lib :crypt32
      safe_attach_function :CertOpenSystemStoreA, [:pointer, :string], HCERTSTORE
      ffi_lib :crypt32
      safe_attach_function :CertEnumCertificatesInStore, [:handle, :pointer], :pointer
      ffi_lib :crypt32
      safe_attach_function :CertCloseStore, [:handle, :DWORD], :bool
    end
  end
end
