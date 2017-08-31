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

require 'store/crypto'
require 'store/assertions'
require_relative 'store_base'

module Win32
  class Certstore
    include Win32::Store::Crypto
    extend Win32::Store::Assertions
    include Chef::Mixin::WideString
    extend Win32::Certstore::StoreBase

    attr_accessor :store_name

    def self.open(store_name)
      validate_store(store_name)
      @certstore_handle = self.new.send(:open, store_name)
      if block_given?
        yield self
      else
        self
      end
    end

    def self.list
      list = cert_list(@certstore_handle)
      self.new.send(:close)
      return list
    end

    private

    def open(store_name)
      certstore_handle = CertOpenSystemStoreW(nil, wstring(store_name))
      unless certstore_handle
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to open the Certificate Store `#{store_name}` with error: #{last_error}."
      end
      certstore_handle
    end

    def close
      closed = CertCloseStore(@certstore_handle, CERT_CLOSE_STORE_FORCE_FLAG)
      unless closed
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to close the Certificate Store with error: #{last_error}."
      end
    end
  end
end
