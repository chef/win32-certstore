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

require 'win32/crypto/reserved_names'
require 'win32/crypto/default_policies'

module Win32
  class Certstore
    include Win32::Crypto::ReservedNames
    include Win32::Crypto::DefaultPolicies
    include Chef::Mixin::ShellOut
    include Chef::Mixin::WideString

    # CA -> Certification authority certificates.
    # MY -> A certificate store that holds certificates with associated private keys.
    # ROOT -> Root certificates.
    # SPC -> Software Publisher Certificate.

    def open store_name
      certstore_handle = CertOpenSystemStoreW(nil, wstring(store_name))
      unless certstore_handle
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to open the Certificate Store `#{store_name}` with error: #{last_error}."
      end
      certstore_handle
    end

    def add_cert *args
      Win32::Crypto::DefaultPolicies::validate_args(args)
      cert_cmd = get_PScommand(args)
      begin
        cert_file = shell_out(cert_cmd)
        cert_file.error!
      rescue => detail
        warn("Failed to add root certificate: #{cert_file.error!}")
      end
    end

    def load store_name
      certs = []
      ptr = FFI::Pointer::NULL
      store = CertOpenSystemStoreA(nil, wstring(store_name))
      begin
        while (ptr = CertEnumCertificatesInStore(store, ptr)) and not ptr.null?
         context = CERT_CONTEXT.new(ptr)
         cert_buf = context[:pbCertEncoded].read_bytes(context[:cbCertEncoded])
         begin
           certs << OpenSSL::X509::Certificate.new(cert_buf)
         rescue => detail
           Puppet.warning("Failed to import root certificate: #{detail.inspect}")
         end
       end
     ensure
       CertCloseStore(store, 0)
     end
     certs
    end

    def close certstore_handle
      closed = CertCloseStore(certstore_handle, CERT_CLOSE_STORE_FORCE_FLAG)
      unless closed
        last_error = FFI::LastError.error
        raise Chef::Exceptions::Win32APIError, "Unable to close the Certificate Store with error: #{last_error}."
      end
      closed
    end

    private

    def update_params(user_parms)
      if user_parms.size > 1
        path_index = user_parms.each_index.select{|i| user_parms[i] =~ /.cer|.crt|.pfx|.der/}.first
        user_parms[0], user_parms[user_parms.size-1] = user_parms.find{|loc| loc != user_parms[path_index]}.delete(' '), user_parms[path_index]
      else
        user_parms[0], user_parms[1] = "ROOT", user_parms[0]
      end
    end

    def get_PScommand(user_parms)
      user_parms = update_params(user_parms)
      if user_parms.last =~ /.pfx/
        cmd = "powershell.exe -Command certutil -addstore -f -importpfx '#{user_parms.first}' '#{user_parms.last}'"
      else
        cmd = "powershell.exe -Command certutil -addstore -f -v '#{user_parms.first}' '#{user_parms.last}'"
      end
      cmd
    end
  end
end
