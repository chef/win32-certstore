#
# Author:: John Keiser (<jkeiser@chef.io>)
# Author:: Seth Chisamore (<schisamo@chef.io>)
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

require_relative "string"

module Win32::Certstore::Mixin::Unicode
end

module FFI
  class Pointer
    include Win32::Certstore::Mixin::String
    def read_wstring(num_wchars = nil)
      if num_wchars.nil?
        # Find the length of the string
        length = 0
        last_char = nil
        while last_char != "\000\000"
          length += 1
          last_char = get_bytes(0, length * 2)[-2..-1]
        end

        num_wchars = length
      end
      wide_to_utf8(get_bytes(0, num_wchars * 2))
    end
  end
end
