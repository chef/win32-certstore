#
# Author:: Piyush Awasthi (<piyush.awasthi@msystechnologies.com>)
# Copyright:: Copyright (c) 2018 Chef Software, Inc.
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

require "date"

module Win32
  class Certstore
    module Mixin
      module Helper
        # PSCommand to search certificate from thumbprint and either turn it into a pem or return a path to a pfx object
        def key_ps_cmd(thumbprint, store_location: "LocalMachine", store_name: "My")
          <<-CMD
            $Location = [Security.Cryptography.X509Certificates.StoreLocation]::#{store_location}
            $StoreName = [Security.Cryptography.X509Certificates.StoreName]::#{store_name}
            $Store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $Location
            $OpenFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly
            $Store.Open($OpenFlags)
            $mycert = $Store.Certificates | Where-Object {$_.Thumbprint -eq "#{thumbprint}"}
            $mykey = $mycert.PrivateKey
            $decrypted_key = $mykey.ExportRSAPrivateKey()
            if ($null -ne $decrypted_key){
              $content = @(
              '-----BEGIN RSA PRIVATE KEY-----'
                  [System.Convert]::ToBase64String($decrypted_key, 'InsertLineBreaks')
              '-----END RSA PRIVATE KEY-----'
              )
            }
            $content
          CMD
        end

        def cert_ps_cmd(thumbprint, store_location: "LocalMachine", store_name: "My")
          <<-EOH
            $cert = Get-ChildItem Cert:\\#{store_location}\\#{store_name} -Recurse | Where { $_.Thumbprint -eq "#{thumbprint}" }

            $content = $null
            if($null -ne $cert)
            {
              $content = @(
                '-----BEGIN CERTIFICATE-----'
                [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
                '-----END CERTIFICATE-----'
              )
            }
            $content
          EOH
        end

        # validate certificate not_before and not_after date in UTC
        def valid_duration?(cert_obj)
          cert_obj.not_before < Time.now.utc && cert_obj.not_after > Time.now.utc
        end
      end
    end
  end
end
