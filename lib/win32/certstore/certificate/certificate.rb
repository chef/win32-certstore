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

require 'win32/certstore/certificate/cert_base'
require 'pry'

module Win32
  class Certstore
    class Certificate
      include Certificate::CertBase
      extend Certificate::CertBase

      attr_accessor :store_handler, :content
      # To Display Certificate List
      # Take input certificate store name
      # Return List in JSON format
      def initialize(store_handler, cert_path)
        @store_handler = store_handler
        @cert_path = cert_path
        create
      end

      def create
        add_certificate(@store_handler, @cert_path)
      end

      # To Display Certificate List
      # Take input certificate store name
      # Return List in JSON format
      def self.list(store_handler)
        # Get Certificate list of open certificate store
        return list_cert(store_handler)
      end
      
    end
  end
end
