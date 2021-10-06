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
#

# Notes : 10/5/2021 - the tests below mock calls to methods in store_base.rb that are powershell_exec calls. This was done because at this point, these calls will resturn an ffi_lib error when running the tests. This is because powershell_exec is part of chef client and not
# a stand-alone gem so when rspec calls into the method there is no way to invoke it. The store_base code works in production because it will always be called under the context of the chef-client. Once the powershell_exec code is moved to the chef-utils gem, a gem dependency
# can be added here and the mocks can be removed in favor of the actual calls.

require "spec_helper"
require "openssl" unless defined?(OpenSSL)

CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_SYSTEM_STORE_CURRENT_USER = 0x00010000
X509_ASN_ENCODING = 0x00000001

describe Win32::Certstore, :windows_only do
  let(:store_location) { CERT_SYSTEM_STORE_CURRENT_USER }
  let(:certstore) { Win32::Certstore }
  let(:certbase) { Win32::Certstore::StoreBase }
  let(:certstore_handler) { Win32::Certstore.new(store_name, store_location: store_location) }

  describe "#cert_list" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing invalid certificate store name" do
      let(:store_name) { "Chef" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.not_to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing nil certificate store name" do
      let(:store_name) { nil }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing valid certificate" do
      let(:store_name) { "root" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_list).and_return([root_certificate_name])
      end
      it "returns certificate list" do
        store = certstore.open(store_name, store_location: store_location)
        certificate_list = store.list
        expect(certificate_list.size).to eql(1)
        expect(certificate_list.first).to eql root_certificate_name
      end
    end
  end

  describe "#cert_add" do
    context "When passing certificate path instead of certificate object to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      it "it raises ArgumentError - Invalid Certificate object" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.add(cert_file_path) }.to raise_error(ArgumentError)
      end
    end

    context "When passing invalid certificate object to the CurrentUser Store" do
      let(:store_name) { "my" }
      let(:cert_file_path) { '.\spec\win32\assets\notes.txt' }
      it "it raises ArgumentError - Invalid Certificate object" do
        allow(certstore).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        store = certstore.open(store_name, store_location: store_location)
        expect { store.add(cert_file_path) }.to raise_error(ArgumentError)
      end
    end

    context "When passing a valid certificate object to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_add).and_return(true)
      end
      it "returns Certificate added successfully" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.add(certificate_object)).to eql true
      end
    end
  end

  describe "#cert_get" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829f" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_get).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "returns Argument Error" do
        store = certstore.open(store_name, store_location: store_location)
        # cert_obj = store.get(thumbprint)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing valid thumbprint to the CurrentUser store" do
      let(:store_name) { "MY" }
      let(:thumbprint22) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      before do
        allow_any_instance_of(certbase).to receive(:cert_get).and_return(certificate_object)
      end
      it "it returns an OpenSSL::X509::Certificate Object from the CurrentUser store" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.get(thumbprint22)).to be_an_instance_of(OpenSSL::X509::Certificate)
      end
    end

    context "When passing an invalid thumbprint with spaces to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_get).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing valid thumbprint with : to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_get).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end
  end

  describe "#cert_delete" do
    context "When passing empty certificate store name to the CurrentUser Store" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint to the CurrentUser Store" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil to the CurrentUser Store" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint to the CurrentUser Store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:CertFindCertificateInStore).and_return(false)
        allow_any_instance_of(certstore).to receive(:lookup_error).and_return(false)
      end
      it "returns false" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.delete(thumbprint)).to eql(false)
      end
    end

    context "When passing valid thumbprint to the CurrentUser Store" do
      let(:store_name) { "root" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:CertFindCertificateInStore).and_return(FFI::MemoryPointer.new(1))
        allow_any_instance_of(certstore).to receive(:CertDuplicateCertificateContext).and_return(true)
        allow_any_instance_of(certstore).to receive(:CertDeleteCertificateFromStore).and_return(true)
        allow_any_instance_of(certstore).to receive(:CertFreeCertificateContext).and_return(true)
      end
      it "returns true when thumbprint has no spaces" do
        thumbprint = "b1bc968bd4f49d622aa89a81f2150152a41d829c"
        store = certstore.open(store_name, store_location: store_location)
        expect(store.delete(thumbprint)).to eql(true)
      end
    end

    context "When passing a valid thumbprint with spaces or colons to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      let(:thumbprint2) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_delete).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "returns ArgumentError when thumbprint has spaces" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "returns ArgumentError when thumbprint has colons" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint2) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end
  end

  describe "#cert_validate" do
    context "When passing empty certificate store name to the CurrentUser store" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.valid?(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.valid?(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing valid thumbprint to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_validate).and_return(true)
      end
      it "returns Certificate found" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.valid?(thumbprint)).to eql(true)
      end
    end

    context "When passing a valid certificate thumbprint for a certificate that does not exist to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829f" }
      let(:cert_pem) { File.read('.\spec\win32\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_validate).and_raise(ArgumentError, "Certificate not found")
      end
      it "returns Certificate not found" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.valid?(thumbprint) }.to raise_error(ArgumentError, "Certificate not found")
      end
    end
  end

  describe "#cert_search" do
    context "When passing empty token" do
      let(:store_name) { "root" }
      let(:token) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.search(token) }.to raise_error(ArgumentError, "Invalid search token")
      end
    end
    context "When search token is nil" do
      let(:store_name) { "root" }
      let(:token) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.search(token) }.to raise_error(ArgumentError, "Invalid search token")
      end
    end

    context "When passing invalid search token" do
      let(:store_name) { "root" }
      let(:token) { "invalid search" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:get_cert_property).and_return("")
      end
      it "returns empty Array list" do
        store = certstore.open(store_name, store_location: store_location)
        cert_list = store.search(token)
        expect(cert_list).to be_an_instance_of(Array)
        expect(cert_list).to be_empty
      end
    end
    context "When passing valid search token CN" do
      let(:store_name) { "root" }
      let(:token) { "GlobalSign Root CA" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:get_cert_property).and_return(["", "", "BE, GlobalSign nv-sa, Root CA, GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "", ""])
      end
      it "returns valid " do
        store = certstore.open(store_name, store_location: store_location)
        cert_list = store.search(token)
        expect(cert_list).to be_an_instance_of(Array)
        cert_list.flatten!
        expect(cert_list.first).to eql("GlobalSign Root CA")
        expect(cert_list.last).to eql("BE, GlobalSign nv-sa, Root CA, GlobalSign Root CA")
      end
    end
  end

  describe "#get_thumbprint" do
    context "When looking up a certificate by Friendlyname, CN, or Subject Name" do
      let(:store_name) { "root" }
      let(:search_token) { "GlobalSign" }
      let(:broken_search_token) { "Foo" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before do
        allow_any_instance_of(certbase).to receive(:cert_lookup_by_token).and_return(thumbprint)
      end
      it "it returns a valid thumbprint if a certificate matches." do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.get_thumbprint(search_token)).to eql("b1bc968bd4f49d622aa89a81f2150152a41d829c")
      end
    end
    context "When looking up a certificate by Friendlyname, CN, or Subject Name for a non-existent certificate" do
      let(:store_name) { "root" }
      let(:search_token) { "GlobalSign" }
      let(:broken_search_token) { "Foo" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before do
        allow_any_instance_of(certbase).to receive(:cert_lookup_by_token).and_raise(ArgumentError, "Certificate not found while looking for certificate : #{search_token} in store : #{store_name} at this location : #{store_location}")
      end
      it "Throws an Argument error when the matching certificate does not exist" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get_thumbprint(broken_search_token) }.to raise_error(ArgumentError, "Certificate not found while looking for certificate : #{search_token} in store : #{store_name} at this location : #{store_location}")
      end
    end
  end

  describe "Perform more than one operations with single certstore object" do
    context "Perform add and list with single certstore object" do
      let(:store_name) { "root" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      it "returns Certificate added successfully listing certificates for the same" do
        # allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(true)
        # allow(certstore).to receive(:open).with(store_name, store_location: store_location).and_return(certstore_handler)
        store = certstore.open(store_name, store_location: store_location)
        expect(store.add(certificate_object)).to eql true
        certificate_list = store.list
        root_cert_list = store.search(root_certificate_name)
        expect(certificate_list.size).to be >= 1
        catcher = root_cert_list.to_s.split('"')[1]
        expect(catcher).to eql(root_certificate_name)
      end
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

describe Win32::Certstore, :windows_only do
  let(:store_location) { CERT_SYSTEM_STORE_LOCAL_MACHINE }
  let(:certstore) { Win32::Certstore }
  let(:certbase) { Win32::Certstore::StoreBase }
  let(:certstore_handler) { Win32::Certstore.new(store_name, store_location: store_location) }

  describe "#cert_list" do
    context "When passing empty certificate store name to the LocalMachine store" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing invalid certificate store name to the LocalMachine store" do
      let(:store_name) { "Chef" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.not_to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing nil certificate store name to the LocalMachine store" do
      let(:store_name) { nil }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing valid certificate to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:cert_list).and_return([root_certificate_name])
      end
      it "returns certificate list" do
        store = certstore.open(store_name, store_location: store_location)
        certificate_list = store.list
        expect(certificate_list.size).to eql(1)
        expect(certificate_list.first).to eql root_certificate_name
      end
    end
  end

  describe "#cert_add" do
    context "When passing certificate path instead of certificate object to the CurrentUser store" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      it "it raises ArgumentError - Invalid Certificate object" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.add(cert_file_path) }.to raise_error(ArgumentError)
      end
    end

    context "When passing invalid certificate object to the CurrentUser Store" do
      let(:store_name) { "my" }
      let(:cert_file_path) { '.\spec\win32\assets\notes.txt' }
      it "it raises ArgumentError - Invalid Certificate object" do
        allow(certstore).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        store = certstore.open(store_name, store_location: store_location)
        expect { store.add(cert_file_path) }.to raise_error(ArgumentError)
      end
    end

    context "When passing a valid certificate object to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_add).and_return(true)
      end
      it "returns Certificate added successfully" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.add(certificate_object)).to eql true
      end
    end
  end

  describe "#cert_get" do
    context "When passing empty certificate store name to the LocalMachine store" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint to the LocalMachine store" do
      let(:store_name) { "MY" }
      let(:thumbprint) { "Foo" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_get).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing valid thumbprint top the LocalMachine store" do
      let(:store_name) { "MY" }
      let(:thumbprint22) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      before do
        allow_any_instance_of(certbase).to receive(:cert_get).and_return(certificate_object)
      end
      it "it returns an OpenSSL::X509::Certificate Object from the CurrentUser store" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.get(thumbprint22)).to be_an_instance_of(OpenSSL::X509::Certificate)
      end
    end

    context "When passing an invalid thumbprint with spaces to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_get).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "it raises ArgumentErrore" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing valid thumbprint with : to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_get).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "it raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end
  end

  describe "#cert_delete" do
    context "When passing empty certificate store name to the LocalMachine Store" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name, store_location: store_location) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint to the LocalMachine Store" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil to the LocalMachine Store" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint to the LocalMachine Store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:CertFindCertificateInStore).and_return(false)
        allow_any_instance_of(certstore).to receive(:lookup_error).and_return(false)
      end
      it "returns false" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.delete(thumbprint)).to eql(false)
      end
    end

    context "When passing valid thumbprint to the LocalMachine Store" do
      let(:store_name) { "root" }
      # let(:cert_pem) { File.read('.\spec\win32\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:CertFindCertificateInStore).and_return(FFI::MemoryPointer.new(1))
        allow_any_instance_of(certstore).to receive(:CertDuplicateCertificateContext).and_return(true)
        allow_any_instance_of(certstore).to receive(:CertDeleteCertificateFromStore).and_return(true)
        allow_any_instance_of(certstore).to receive(:CertFreeCertificateContext).and_return(true)
      end
      it "returns true when thumbprint has no spaces" do
        thumbprint = "b1bc968bd4f49d622aa89a81f2150152a41d829c"
        store = certstore.open(store_name, store_location: store_location)
        expect(store.delete(thumbprint)).to eql(true)
      end
    end

    context "When passing a valid thumbprint with spaces or colons to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      let(:thumbprint2) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_delete).and_raise(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "returns ArgumentError when thumbprint has spaces" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
      it "returns ArgumentError when thumbprint has colons" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.delete(thumbprint2) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing a valid certificate thumbprint for a certificate that does not exist to the LocalMachine store" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829f" }
      let(:cert_pem) { File.read('.\spec\win32\assets\GlobalSignRootCA.pem') }
      it "returns Certificate not found" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.delete(thumbprint)).to eql(false)
      end
    end
  end

  describe "#cert_search" do
    context "When passing empty token" do
      let(:store_name) { "root" }
      let(:token) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.search(token) }.to raise_error(ArgumentError, "Invalid search token")
      end
    end
    context "When search token is nil" do
      let(:store_name) { "root" }
      let(:token) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.search(token) }.to raise_error(ArgumentError, "Invalid search token")
      end
    end
    context "When passing invalid search token" do
      let(:store_name) { "root" }
      let(:token) { "invalid search" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:get_cert_property).and_return("")
      end
      it "returns empty Array list" do
        store = certstore.open(store_name, store_location: store_location)
        cert_list = store.search(token)
        expect(cert_list).to be_an_instance_of(Array)
        expect(cert_list).to be_empty
      end
    end
    context "When passing valid search token CN" do
      let(:store_name) { "root" }
      let(:token) { "GlobalSign Root CA" }
      before(:each) do
        allow_any_instance_of(certstore).to receive(:get_cert_property).and_return(["", "", "BE, GlobalSign nv-sa, Root CA, GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "", ""])
      end
      it "returns valid " do
        store = certstore.open(store_name, store_location: store_location)
        cert_list = store.search(token)
        expect(cert_list).to be_an_instance_of(Array)
        cert_list.flatten!
        expect(cert_list.first).to eql("GlobalSign Root CA")
        expect(cert_list.last).to eql("BE, GlobalSign nv-sa, Root CA, GlobalSign Root CA")
      end
    end
  end

  describe "#get_thumbprint" do
    context "When looking up a certificate by Friendlyname, CN, or Subject Name" do
      let(:store_name) { "root" }
      let(:search_token) { "GlobalSign" }
      let(:broken_search_token) { "Foo" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before do
        allow_any_instance_of(certbase).to receive(:cert_lookup_by_token).and_return(thumbprint)
      end
      it "it returns a valid thumbprint if a certificate matches." do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.get_thumbprint(search_token)).to eql("b1bc968bd4f49d622aa89a81f2150152a41d829c")
      end
    end
    context "When looking up a certificate by Friendlyname, CN, or Subject Name for a non-existent certificate" do
      let(:store_name) { "root" }
      let(:search_token) { "GlobalSign" }
      let(:broken_search_token) { "Foo" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before do
        allow_any_instance_of(certbase).to receive(:cert_lookup_by_token).and_raise(ArgumentError, "Certificate not found while looking for certificate : #{search_token} in store : #{store_name} at this location : #{store_location}")
      end
      it "Throws an Argument error when the matching certificate does not exist" do
        store = certstore.open(store_name, store_location: store_location)
        expect { store.get_thumbprint(broken_search_token) }.to raise_error(ArgumentError, "Certificate not found while looking for certificate : #{search_token} in store : #{store_name} at this location : #{store_location}")
      end
    end
  end

  describe "Perform more than one operations with single certstore object" do
    context "Perform add and list with single certstore object" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      it "returns Certificate added successfully listing certificates for the same" do
        store = certstore.open(store_name, store_location: store_location)
        expect(store.add(certificate_object)).to eql true
        certificate_list = store.list
        root_cert_list = store.search(root_certificate_name)
        expect(certificate_list.size).to be >= 1
        catcher = root_cert_list.to_s.split('"')[1]
        expect(catcher).to eql(root_certificate_name)
      end
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
