#
# Author:: Vasundhara Jagdale (<vasundhara.jagdale@msystechnologies.com>)
# Copyright:: 2017-2018 Chef Software, Inc.
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
require "openssl"

RSpec.describe Win32::Certstore, :windows_only do
  before { open_cert_store("My") }
  after(:each) do
    delete_cert
    close_store
  end

  describe "#get" do
    before { add_cert }
    let(:cert_pem) { File.read('.\spec\win32\assets\GlobalSignRootCA.pem') }

    # passing valid thumbprint
    it "returns the certificate_object if found" do
      thumbprint = "b1bc968bd4f49d622aa89a81f2150152a41d829c"
      expect(@store).to receive(:cert_get).with(thumbprint).and_return(cert_pem)
      @store.get(thumbprint)
    end

    # passing invalid thumbprint
    it "returns nil if certificate not found" do
      thumbprint = "b1bc968bd4f49d622aa89a81f2150152a41d829cab"
      expect(@store).to receive(:cert_get).with(thumbprint).and_return(nil)
      @store.get(thumbprint)
    end
  end

  private

  def open_cert_store(store)
    @store = Win32::Certstore.open(store)
  end

  def add_cert
    raw = File.read ".\\spec\\win32\\assets\\GlobalSignRootCA.pem"
    certificate_object = OpenSSL::X509::Certificate.new raw
    @store.add(certificate_object)
  end

  def close_store
    @store.close
  end

  def delete_cert
    @store.delete("b1bc968bd4f49d622aa89a81f2150152a41d829c")
  end
end
