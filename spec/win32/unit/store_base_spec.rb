#
# Author:: Nimesh Patni (<nimesh.patni@msystechnologies.com>)
# Copyright:: 2017-2018 Chef Software, Inc
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
#

require "spec_helper"

describe Win32::Certstore, :windows_only do
  subject(:store_base) { Class.new { extend Win32::Certstore::StoreBase } }
  let(:null_ptr) { FFI::MemoryPointer::NULL }
  let(:mem_pointer) { FFI::MemoryPointer.new(:char, 16) }

  describe "#cert_add_pfx" do
    let(:certstore_handler) { mem_pointer }
    let(:pfx_path) { '.\spec\win32\assets\pfx_cert.pfx' }
    let(:pfx_wt_root_path) { '.\spec\win32\assets\pfx_with_testroot.pfx' }
    let(:pem_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
    let(:password) { "chef@123" }
    context "invalid certstore_handler" do
      it "raises an error" do
        certstore_handler = "Invalid"
        expect { subject.cert_add_pfx(certstore_handler, pfx_path, password) }
          .to raise_error(SystemCallError)
      end
    end
    context "invalid pfx_path" do
      it "raises an error" do
        pfx_path = "Invalid"
        expect { subject.cert_add_pfx(certstore_handler, pfx_path, password) }
          .to raise_error(Errno::NOERROR, "No error - Unable to Add a PFX certificate.")
      end
    end
    context "invalid password" do
      it "raises an error" do
        password = "Invalid"
        expect { subject.cert_add_pfx(certstore_handler, pfx_path, password) }
          .to raise_error(SystemCallError, "The specified network password is not correct. - Unable to Add a PFX certificate.")
      end
    end
    context "other than PFX certificates" do
      it "raises an error" do
        expect { subject.cert_add_pfx(certstore_handler, pem_path, password) }
          .to raise_error(SystemCallError)
      end
    end
    context "valid arguments" do
      it "returns true" do
        allow_any_instance_of(Win32::Certstore::Mixin::Crypto)
          .to receive(:CertAddCertificateContextToStore).and_return(true)

        expect(subject.cert_add_pfx(certstore_handler, pfx_path, password))
          .to be_truthy
      end
    end
    context "valid arguments with test root" do
      it "returns true" do
        allow_any_instance_of(Win32::Certstore::Mixin::Crypto)
          .to receive(:CertAddCertificateContextToStore).and_return(true)

        expect(subject.cert_add_pfx(certstore_handler, pfx_wt_root_path, password))
          .to be_truthy
      end
    end
  end
end
