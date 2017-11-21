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

require_relative 'certstore/mixin/crypto'
require_relative 'certstore/mixin/assertions'
require_relative 'certstore/store_base'
require_relative 'certstore/version'

module Win32
  class Certstore
    include Win32::Certstore::Mixin::Crypto
    extend Win32::Certstore::Mixin::Assertions
    include Chef::Mixin::WideString
    include Win32::Certstore::StoreBase

    attr_reader :store_name

    def initialize(store_name)
      @certstore_handler = open(store_name)
    end

    def self.open(store_name)
      validate_store(store_name)
      if block_given?
        yield self.new(store_name)
      else
        self.new(store_name)
      end
    end

    def list
      list = cert_list(@certstore_handler)
      close
      return list
    end

    def add(cert_file_path)
      add = cert_add(@certstore_handler, cert_file_path)
      close
      return add
    end

    def delete(certificate_name)
      delete_cert = cert_delete(@certstore_handler, certificate_name)
      close
      return delete_cert
    end

    private
    
    attr_reader :certstore_handler

    def open(store_name)
      certstore_handler = CertOpenSystemStoreW(nil, wstring(store_name))
      unless certstore_handler
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to open the Certificate Store `#{store_name}` with error: #{last_error}."
      end
      add_finalizer(certstore_handler)
      certstore_handler
    end

    def add_finalizer(certstore_handler)
      ObjectSpace.define_finalizer(self, self.class.finalize(certstore_handler))
    end

    def self.finalize(certstore_handler)
      proc { puts "DESTROY OBJECT #{certstore_handler}" }
    end

    def close
      closed = CertCloseStore(@certstore_handler, CERT_CLOSE_STORE_FORCE_FLAG)
      unless closed
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to close the Certificate Store with error: #{last_error}."
      end
      remove_finalizer
    end

    def remove_finalizer
      ObjectSpace.undefine_finalizer(self)
    end
  end
end
