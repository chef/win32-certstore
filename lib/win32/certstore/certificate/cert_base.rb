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

require 'win32/store/crypto'

module Win32
  class Certstore
    class Certificate
      module CertBase
        include Win32::Store::Crypto
        include Chef::Mixin::ShellOut
        include Chef::Mixin::WideString

        def list_cert(store_handle)
          cert_name = FFI::MemoryPointer.new(2, 128)
          cert_list = []
          begin
            while (pCertContext = CertEnumCertificatesInStore(store_handle, pCertContext) and not pCertContext.null? ) do
              if (CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil, cert_name, 1024))
                cert_list << cert_name.read_wstring
              end
            end
            CertFreeCertificateContext(pCertContext)
          rescue Exception => e
            last_error = FFI::LastError.error
            raise Chef::Exceptions::Win32APIError, "Unable to load certificate with error: #{last_error}."
          end
          cert_list.to_json
        end

      end
    end
  end
end
