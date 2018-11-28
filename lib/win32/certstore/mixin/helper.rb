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

        # PSCommand to search certificate from thumbprint and convert in pem
        def cert_ps_cmd(thumbprint, store_name)
          <<-EOH
            $content = $null
            $cert = Get-ChildItem Cert:\\LocalMachine\\'#{store_name}' -Recurse | Where { $_.Thumbprint -eq '#{thumbprint}' }
            if($cert -ne $null)
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
