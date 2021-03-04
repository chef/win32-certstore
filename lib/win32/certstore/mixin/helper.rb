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
        def cert_ps_cmd(thumbprint, store_location: "LocalMachine", export_password: "1234", output_path:"")
          <<-EOH
            $cert = Get-ChildItem Cert:\'#{store_location}' -Recurse | Where { $_.Thumbprint -eq '#{thumbprint}' }

            # The function and the code below test to see if a) the cert has a private key and b) it has a
            # Enhanced Usage of Client Auth. Those 2 attributes would mean this is a pfx-able object
            function test_cert_values{
              $usagelist = ($cert).EnhancedKeyUsageList
              foreach($use in $usagelist){
                if($use.FriendlyName -like "Client Authentication" ){
                    return $true
                }
                else {
                    return $false
                }
              }
            }

            $result = test_cert_values

            $output_path = "#{output_path}"
            if([string]::IsNullOrEmpty($output_path)){
              $temproot = [System.IO.Path]::GetTempPath()
            }
            else{
              $temproot = $output_path
            }

            if((($cert).HasPrivateKey) -and ($result -eq $true)){
              $file_name = '#{thumbprint}'
              $file_path = $(Join-Path -Path $temproot -ChildPath "$file_name.pfx")
              $mypwd = ConvertTo-SecureString -String '#{export_password}' -Force -AsPlainText
              $cert | Export-PfxCertificate -FilePath $file_path -Password $mypwd | Out-Null
              $file_path
            }
            else {
              $content = $null
              if($cert -ne $null)
              {
              $content = @(
                '-----BEGIN CERTIFICATE-----'
                [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
                '-----END CERTIFICATE-----'
              )
              }
              $content
            }
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
