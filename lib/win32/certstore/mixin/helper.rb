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
        def cert_ps_cmd(thumbprint, store_location: "LocalMachine", store_name: "My")
          # the PowerShell block below uses a "Here-String" - it is explicitly formatted against the left margin.
          <<-EOH
            $cert = Get-ChildItem Cert:\\#{store_location}\\#{store_name} -Recurse -Force | Where-Object { $_.Thumbprint -eq "#{thumbprint}" }

            if ([string]::IsNullOrEmpty($cert)){
              return "Certificate Not Found"
            }

            $certdata = [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks')
            $content = $null
            if($null -ne $cert)
            {
              $content =
@"
-----BEGIN CERTIFICATE-----
$($certdata)
-----END CERTIFICATE-----
"@
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
