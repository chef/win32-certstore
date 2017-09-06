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

module Win32::Mixin::Assertions

  # Validate certificate store name
  def validate_store(store_name)
    unless valid_store_name.include?(store_name&.upcase)
      raise ArgumentError, "Invalid Certificate Store."
    end
  end

  # Validate certificate type
  def validate_certificate(cert_file_path)
    unless (!cert_file_path.nil? && File.extname(cert_file_path) =~ /.cer|.crt|.pfx|.der/ )
      raise ArgumentError, "Invalid Certificate format."
    end
  end

  private

  # These Are Valid certificate store name
  # CA -> Certification authority certificates.
  # MY -> A certificate store that holds certificates with associated private keys.
  # ROOT -> Root certificates.
  # SPC -> Software Publisher Certificate.
  def valid_store_name
    ["MY", "CA", "ROOT", "SPC"]
  end
end
