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

module Win32
  class Certstore
    # CA -> Certification authority certificates.
    # MY -> A certificate store that holds certificates with associated private keys.
    # ROOT -> Root certificates.
    # SPC -> Software Publisher Certificate.

    def self.add_cert(*args)
      Win32::Certstore::Certificate::Add.new(args)
    end

    def self.list_cert(certstore_name)
      Win32::Certstore::Certificate::List.new(certstore_name).show
    end

  end
end
