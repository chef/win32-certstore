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

module Win32
  class Certstore
    module Mixin
      module Helper

        # PSCommand to search certificate from thumbprint and convert in pem
        def cert_ps_cmd(thumbprint)
          "$CertThumbprint = '#{thumbprint}'
          $content = $null
          $cert = Get-ChildItem Cert:\ -Recurse | Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -First 1
          if($cert -ne $null)
          {
          $content = @(
            '-----BEGIN CERTIFICATE-----'
            [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
            '-----END CERTIFICATE-----'
          )
          }
          $content"
        end
      end
    end
  end
end

