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

module Win32
  class Certstore
  module Mixin
    module Crypto
      extend FFI::Library

      ffi_lib 'Crypt32'
      ffi_convention :stdcall

      # Attempts to use FFI's attach_function method to link a native Win32
      # function into the calling module.  If this fails a dummy method is
      # defined which when called, raises a helpful exception to the end-user.
      module FFI::Library
        def safe_attach_function(win32_func, *args)
          attach_function(win32_func.to_sym, *args)
        rescue FFI::NotFoundError
          define_method(win32_func.to_sym) do |*margs|
            raise NotImplementedError, "This version of Windows does not implement the Win32 function [#{win32_func}]."
          end
        end
      end

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

      # Retrieve Certificates flag
      CERT_FIND_SUBJECT_STR                               = 0x00080007
      CERT_FIND_ISSUER_STR                                = 0x00080004

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
      DWORD                                               = FFI::TypeDefs[:uint32]
      BLOB                                                = FFI::TypeDefs[:ulong]
      LPSTR                                               = FFI::TypeDefs[:pointer]
      LPCTSTR                                             = FFI::TypeDefs[:pointer]
      BOOL                                                = FFI::TypeDefs[:bool]
      INT_PTR                                             = FFI::TypeDefs[:int]
      LONG                                                = FFI::TypeDefs[:long]
      LPVOID                                              = FFI::TypeDefs[:pointer]
      LPTSTR                                              = FFI::TypeDefs[:pointer]
      LMSTR                                               = FFI::TypeDefs[:pointer]
      PWSTR                                               = FFI::TypeDefs[:pointer]
      LPFILETIME                                          = FFI::TypeDefs[:pointer]
      PCERT_INFO                                          = FFI::TypeDefs[:pointer]
      PCTL_USAGE                                          = FFI::TypeDefs[:pointer]
      PCTL_VERIFY_USAGE_PARA                              = FFI::TypeDefs[:pointer]
      PCTL_VERIFY_USAGE_STATUS                            = FFI::TypeDefs[:pointer]

      class FILETIME < FFI::Struct
        layout :dwLowDateTime, DWORD,
               :dwHighDateTime, DWORD
      end

      # class CRYPT_INTEGER_BLOB < FFI::Struct
      #   layout :cbData, DWORD,   # Count, in bytes, of data
      #          :pbData, :pointer  # Pointer to data buffer
      # end
      class CRYPT_INTEGER_BLOB < FFI::Struct
        layout :cbData, DWORD,   # Count, in bytes, of data
               :pbData, :pointer  # Pointer to data buffer
      end

      class CRYPT_NAME_BLOB < FFI::Struct
        layout :cbData, DWORD,   # Count, in bytes, of data
               :pbData, :pointer  # Pointer to data buffer
        def initialize(str = nil)
          super(nil)
          if str
            self[:pbData] = FFI::MemoryPointer.new(2, 128)
          end
        end
      end

      class CERT_EXTENSION < FFI::Struct
        layout :pszObjId, LPTSTR,
               :fCritical, BOOL,
               :Value, CRYPT_INTEGER_BLOB
      end

      class CRYPT_BIT_BLOB < FFI::Struct
        layout :cbData, DWORD,
               :pbData, BYTE,
               :cUnusedBits, DWORD
      end

      class CRYPT_ALGORITHM_IDENTIFIER < FFI::Struct
        layout :pszObjId, LPSTR,
               :Parameters, CRYPT_INTEGER_BLOB
      end

      class CERT_PUBLIC_KEY_INFO < FFI::Struct
        layout :Algorithm, CRYPT_ALGORITHM_IDENTIFIER,
               :PublicKey, CRYPT_BIT_BLOB
      end

      class CERT_INFO < FFI::Struct
        layout :dwVersion, DWORD,
             :SerialNumber, CRYPT_INTEGER_BLOB,
             :SignatureAlgorithm, CRYPT_ALGORITHM_IDENTIFIER,
             :Issuer, CRYPT_NAME_BLOB,
             :NotBefore, FILETIME,
             :NotAfter, FILETIME,
             :Subject, CRYPT_NAME_BLOB,
             :SubjectPublicKeyInfo, CERT_PUBLIC_KEY_INFO,
             :IssuerUniqueId, CRYPT_BIT_BLOB,
             :SubjectUniqueId, CRYPT_BIT_BLOB,
             :cExtension, DWORD,
             :rgExtension, CERT_EXTENSION
      end

      class CERT_CONTEXT < FFI::Struct
        layout :dwCertEncodingType, DWORD,
               :pbCertEncoded, BYTE,
               :cbCertEncoded, DWORD,
               :pCertInfo, CERT_INFO,
               :hCertStore, HCERTSTORE
      end

      class CTL_USAGE < FFI::Struct
        layout :cUsageIdentifier, DWORD,
               :rgpszUsageIdentifier, LPSTR
      end

      ###############################################################################
      # Windows Function
      # To know description about below windows function
      # Search Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560
      ###############################################################################

      # To opens the most common system certificate store
      safe_attach_function :CertOpenSystemStoreW, [HCRYPTPROV_LEGACY, LPCTSTR], HCERTSTORE
      # To close the already open certificate store
      safe_attach_function :CertCloseStore, [HCERTSTORE, DWORD], BOOL
      # To retrieves certificates in a certificate store
      safe_attach_function :CertEnumCertificatesInStore, [HCERTSTORE, PCCERT_CONTEXT], PCCERT_CONTEXT
      # To get certificate name
      safe_attach_function :CertGetNameStringW, [PCCERT_CONTEXT, DWORD, DWORD, LPVOID, LPTSTR, DWORD], DWORD
      # To find all of the property identifiers for the specified certificate.
      safe_attach_function :CertEnumCertificateContextProperties, [PCCERT_CONTEXT, DWORD], DWORD
      # Clean up
      safe_attach_function :CertFreeCertificateContext, [PCCERT_CONTEXT], BOOL
      # Add certificate file in certificate store.
      safe_attach_function :CertAddSerializedElementToStore, [HCERTSTORE, :pointer, DWORD, DWORD, DWORD, DWORD, LMSTR, LPVOID], BOOL
      # Add certification to certification store - Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376015(v=vs.85).aspx
      safe_attach_function :CertAddEncodedCertificateToStore, [HCERTSTORE, DWORD, PWSTR, DWORD, INT_PTR, PCCERT_CONTEXT], BOOL
      safe_attach_function :CertSerializeCertificateStoreElement, [PCCERT_CONTEXT, DWORD, :pointer, DWORD], BOOL
      # Duplicates a certificate context by incrementing its reference count
      safe_attach_function :CertDuplicateCertificateContext, [PCCERT_CONTEXT], PCCERT_CONTEXT
      # Delete certification from certification store
      safe_attach_function :CertDeleteCertificateFromStore, [PCCERT_CONTEXT], BOOL
      # To retrieve specific certificates from certificate store
      safe_attach_function :CertFindCertificateInStore, [HCERTSTORE, DWORD, DWORD, DWORD, LPVOID, PCCERT_CONTEXT], PCCERT_CONTEXT
      # The CertVerifyTimeValidity function verifies the time validity of a certificate
      safe_attach_function :CertVerifyTimeValidity, [LPFILETIME, PCERT_INFO], LONG
      # The CertVerifyCTLUsage function verifies that a subject is trusted for a specified usage by finding a signed and time-valid
      safe_attach_function :CertVerifyCTLUsage, [DWORD, DWORD, LPVOID, PCTL_USAGE, DWORD, PCTL_VERIFY_USAGE_PARA, PCTL_VERIFY_USAGE_STATUS], BOOL
    end
  end
end
end
