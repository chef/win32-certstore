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
require "openssl" unless defined?(OpenSSL)

# CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
# CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
# X509_ASN_ENCODING = 0x00000001

# Testing loading certs into LocalMachine - this is testing legacy usage
RSpec.describe Win32::Certstore, :windows_only do
  let(:store_location) { CERT_SYSTEM_STORE_CURRENT_USER }
  let(:certstore) { Win32::Certstore }
  let(:certbase) { Win32::Certstore::StoreBase }
  let(:store_name) { "MY" }
  before do
    @store = certstore.open(store_name, store_location: store_location)
  end
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
    it "returns raises an Arugment error" do
      thumbprint14 = "b1bc968bd4f49d622aa89a81f2150"
      expect { @store.get(thumbprint14) }.to raise_error(ArgumentError)
    end
  end

  describe "#get!" do
    before { add_cert }
    let(:cert_pem) { File.read('.\spec\win32\assets\GlobalSignRootCA.pem') }
    # passing valid thumbprint
    it "returns the certificate_object if found" do
      thumbprint = "b1bc968bd4f49d622aa89a81f2150152a41d829c"
      expect(@store).to receive(:cert_get).with(thumbprint).and_return("foo")
      @store.get!(thumbprint)
    end

    # passing invalid thumbprint
    it "returns ArgumentError if certificate not found" do
      thumbprint = "b1bc968bd4f49d622aa89a81f2150152a41d829cab"
      # expect { @store.get!(thumbprint) }.to raise_error(ArgumentError)
      expect(@store).to receive(:cert_get).with(thumbprint).and_return(cert_pem)
      @store.get!(thumbprint)
    end
  end

  private

  def open_cert_store(store, store_location)
    @store = Win32::Certstore.open(store, store_location: store_location)
  end

  def add_cert
    raw = File.read ".\\spec\\win32\\assets\\GlobalSignRootCA.pem"
    certificate_object = OpenSSL::X509::Certificate.new raw
    @store.add(certificate_object)
  end

  def add_pfx
    raw = ".\\spec\\win32\\assets\\steveb.pfx"
    @store.add_pfx(raw, "1234")
  end

  def close_store
    @store.close
  end

  def delete_cert
    @store.delete("b1bc968bd4f49d622aa89a81f2150152a41d829c")
  end
end

# Now testing new code and what happens if you want to import something into CurrentUser - 1/29/2021
# Defining the store constant here as the spec doesn't read from the values in the crypto.rb file.

RSpec.describe Win32::Certstore, :windows_only do
  let(:store_location) { CERT_SYSTEM_STORE_CURRENT_USER }
  let(:certstore) { Win32::Certstore }
  let(:store_name) { "MY" }
  before do
    @store = certstore.open(store_name, store_location: store_location)
  end
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

  def open_cert_store(store, store_location)
    @store = Win32::Certstore.open(store, store_location: store_location)
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
