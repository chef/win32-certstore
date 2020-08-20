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
require "openssl" unless defined?(OpenSSL)

module Win32
  class Certstore
    module Mixin
      module Assertions
        # Validate certificate store name
        def validate_store(store_name)
          if store_name.to_s.strip.empty?
            raise ArgumentError, "Empty Certificate Store."
          end
        end

        # Validate certificate type
        def validate_certificate(cert_file_path)
          unless !cert_file_path.nil? && File.extname(cert_file_path) =~ /.cer|.crt|.pfx|.der/
            raise ArgumentError, "Invalid Certificate format."
          end
        end

        # Validate certificate Object
        def validate_certificate_obj(cert_obj)
          unless cert_obj.class == OpenSSL::X509::Certificate
            raise ArgumentError, "Invalid Certificate object."
          end
        end

        # Validate thumbprint
        def validate_thumbprint(cert_thumbprint)
          if cert_thumbprint.nil? || cert_thumbprint.strip.empty?
            raise ArgumentError, "Invalid certificate thumbprint."
          end
        end

        # Validate certificate name not nil/empty
        def validate!(token)
          raise ArgumentError, "Invalid search token" if !token || token.strip.empty?
        end

        # Common System call errors
        def lookup_error(failed_operation = nil)
          error_no = FFI::LastError.error
          case error_no
          when 1223
            raise SystemCallError.new("The operation was canceled by the user", error_no)
          when -2146885628
            raise SystemCallError.new("Cannot find object or property", error_no)
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

        private

        # These Are Valid certificate store name
        # CA -> Certification authority certificates.
        # MY -> A certificate store that holds certificates with associated private keys.
        # ROOT -> Root certificates.
        # SPC -> Software Publisher Certificate.
        def valid_store_name
          %w{MY CA ROOT AUTHROOT DISALLOWED SPC TRUST TRUSTEDPEOPLE TRUSTEDPUBLISHER CLIENTAUTHISSUER TRUSTEDDEVICES SMARTCARDROOT WEBHOSTING REMOTE\ DESKTOP}
        end
      end
    end
  end
end
