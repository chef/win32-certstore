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

require 'chef'
require 'mixlib/shellout'
require 'ffi'
require "chef/win32/api"

module Win32
  module API
    module ReservedNames
      extend Chef::ReservedNames::Win32::API
      extend FFI::Library

      ffi_lib 'Crypt32'

      HCERTSTORE = FFI::TypeDefs[:pointer]
      HCRYPTPROV_LEGACY = FFI::TypeDefs[:pointer]

      # Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376560(v=vs.85).aspx
      safe_attach_function :CertOpenSystemStoreW, [HCRYPTPROV_LEGACY, :LPCTSTR], HCERTSTORE

      # Ref: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376026(v=vs.85).aspx
      CERT_CLOSE_STORE_CHECK_FLAG = 0
      CERT_CLOSE_STORE_FORCE_FLAG = 1
      safe_attach_function :CertCloseStore, [HCERTSTORE, :DWORD], :BOOL
    end
  end
end
