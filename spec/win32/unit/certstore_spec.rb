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

require "spec_helper"
require "openssl"

describe Win32::Certstore, :windows_only do

  let(:certstore) { Win32::Certstore }
  let(:certstore_handler) { Win32::Certstore.new(store_name) }
  let(:certbase) { Win32::Certstore::StoreBase }

  describe "#cert_list" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing invalid certificate store name" do
      let(:store_name) { "Chef" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name) }.not_to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing nil certificate store name" do
      let(:store_name) { nil }
      it "raises ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing valid certificate" do
      let(:store_name) { "root" }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_list).and_return([root_certificate_name])
      end
      it "returns certificate list" do
        store = certstore.open(store_name)
        certificate_list = store.list
        expect(certificate_list.size).to eql(1)
        expect(certificate_list.first).to eql root_certificate_name
      end
    end
  end

  describe "#cert_add" do
    context "When passing invalid certificate object" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\unit\assets\GlobalSignRootCA.pem' }
      it "raises ArgumentError - Invalid Certificate object" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(ArgumentError)
      end
    end

    context "When passing certificate path instead of certificate object" do
      let(:store_name) { "my" }
      let(:cert_file_path) { '.\spec\win32\unit\assets\GlobalSignRootCA.pem' }

      it "raises ArgumentError - Invalid Certificate object" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(ArgumentError)
      end
    end

    context "When passing valid certificate object" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\unit\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      it "returns Certificate added successfully" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(true)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect(store.add(certificate_object)).to eql true
      end
    end
  end

  describe "#cert_get" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.get(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return("")
      end
      it "returns nil" do
        store = certstore.open(store_name)
        cert_obj = store.get(thumbprint)
        expect(cert_obj).to eql(nil)
      end
    end

    context "When passing valid thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829909c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
      end
      it "returns OpenSSL::X509::Certificate Object" do
        store = certstore.open(store_name)
        cert_obj = store.get(thumbprint)
        expect(cert_obj).to be_an_instance_of(OpenSSL::X509::Certificate)
        expect(cert_obj.not_before.to_s).to eql("1998-09-01 12:00:00 UTC")
        expect(cert_obj.not_after.to_s).to eql("2028-01-28 12:00:00 UTC")
      end
    end

    context "When passing valid thumbprint with spaces" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
      end
      it "returns OpenSSL::X509::Certificate Object" do
        store = certstore.open(store_name)
        cert_obj = store.get(thumbprint)
        expect(cert_obj).to be_an_instance_of(OpenSSL::X509::Certificate)
        expect(cert_obj.not_before.to_s).to eql("1998-09-01 12:00:00 UTC")
        expect(cert_obj.not_after.to_s).to eql("2028-01-28 12:00:00 UTC")
      end
    end

    context "When passing valid thumbprint with :" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
      end
      it "returns OpenSSL::X509::Certificate Object" do
        store = certstore.open(store_name)
        cert_obj = store.get(thumbprint)
        expect(cert_obj).to be_an_instance_of(OpenSSL::X509::Certificate)
        expect(cert_obj.not_before.to_s).to eql("1998-09-01 12:00:00 UTC")
        expect(cert_obj.not_after.to_s).to eql("2028-01-28 12:00:00 UTC")
      end
    end
  end

  describe "#cert_delete" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.delete(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:CertFindCertificateInStore).and_return(false)
        allow_any_instance_of(certbase).to receive(:lookup_error).and_return(false)
      end
      it "returns false" do
        store = certstore.open(store_name)
        expect(store.delete(thumbprint)).to eql(false)
      end
    end

    context "When passing valid thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829909c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
        allow_any_instance_of(certbase).to receive(:CertDeleteCertificateFromStore).and_return(true)
      end
      it "returns true" do
        store = certstore.open(store_name)
        expect(store.delete(thumbprint)).to eql(true)
      end
    end

    context "When passing valid thumbprint with spaces" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
        allow_any_instance_of(certbase).to receive(:CertDeleteCertificateFromStore).and_return(true)
      end
      it "returns true" do
        store = certstore.open(store_name)
        expect(store.delete(thumbprint)).to eql(true)
      end
    end

    context "When passing valid thumbprint with :" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
        allow_any_instance_of(certbase).to receive(:CertDeleteCertificateFromStore).and_return(true)
      end
      it "returns true" do
        store = certstore.open(store_name)
        expect(store.delete(thumbprint)).to eql(true)
      end
    end
  end

  describe "#cert_validate" do
    context "When passing empty certificate store name" do
      let(:store_name) { "" }
      it "raises ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError, "Empty Certificate Store.")
      end
    end

    context "When passing empty thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.valid?(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing thumbprint is nil" do
      let(:store_name) { "root" }
      let(:thumbprint) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.valid?(thumbprint) }.to raise_error(ArgumentError, "Invalid certificate thumbprint.")
      end
    end

    context "When passing invalid thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return("")
      end
      it "returns Certificate not found" do
        store = certstore.open(store_name)
        expect(store.valid?(thumbprint)).to eql("Certificate not found")
      end
    end

    context "When passing valid certificate's thumbprint" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829909c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
      end
      it "returns true" do
        store = certstore.open(store_name)
        expect(store.valid?(thumbprint)).to eql(true)
      end
    end

    context "When passing valid certificate's thumbprint with spaces" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1 bc 96 8b d4 f4 9d 62 2a a8 9a 81 f2 15 01 52 a4 1d 82 9c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
      end
      it "returns true" do
        store = certstore.open(store_name)
        expect(store.valid?(thumbprint)).to eql(true)
      end
    end

    context "When passing valid certificate's thumbprint with :" do
      let(:store_name) { "root" }
      let(:thumbprint) { "b1:bc:96:8b:d4:f4:9d:62:2a:a8:9a:81:f2:15:01:52:a4:1d:82:9c" }
      let(:cert_pem) { File.read('.\spec\win32\unit\assets\GlobalSignRootCA.pem') }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_pem).and_return(cert_pem)
      end
      it "returns true" do
        store = certstore.open(store_name)
        expect(store.valid?(thumbprint)).to eql(true)
      end
    end
  end

  describe "#cert_search" do
    context "When passing empty token" do
      let(:store_name) { "root" }
      let(:token) { " " }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.search(token) }.to raise_error(ArgumentError, "Invalid search token")
      end
    end
    context "When search token is nil" do
      let(:store_name) { "root" }
      let(:token) { nil }
      it "raises ArgumentError" do
        store = certstore.open(store_name)
        expect { store.search(token) }.to raise_error(ArgumentError, "Invalid search token")
      end
    end
    context "When passing invalid search token" do
      let(:store_name) { "root" }
      let(:token) { "invalid search" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:get_cert_property).and_return("")
      end
      it "returns empty Array list" do
        store = certstore.open(store_name)
        cert_list = store.search(token)
        expect(cert_list).to be_an_instance_of(Array)
        expect(cert_list).to be_empty
      end
    end
    context "When passing valid search token CN" do
      let(:store_name) { "root" }
      let(:token) { "GlobalSign Root CA" }
      before(:each) do
        allow(certbase).to receive(:get_cert_property).and_return(["", "", "BE, GlobalSign nv-sa, Root CA, GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "GlobalSign Root CA", "", ""])
      end
      it "returns valid " do
        store = certstore.open(store_name)
        cert_list = store.search(token)
        expect(cert_list).to be_an_instance_of(Array)
        cert_list.flatten!
        expect(cert_list.first).to eql("GlobalSign Root CA - R1")
        expect(cert_list.last).to eql("BE, GlobalSign nv-sa, Root CA, GlobalSign Root CA")
      end
    end
  end

  describe "Perform more than one operations with single certstore object" do
    context "Perform add and list with single certstore object" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\unit\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:root_certificate_name) { "Microsoft Root Certificate Authority" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_list).and_return([root_certificate_name])
      end
      it "returns Certificate added successfully listing certificates for the same" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(true)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect(store.add(certificate_object)).to eql true
        certificate_list = store.list
        expect(certificate_list.size).to eql(1)
        expect(certificate_list.first).to eql root_certificate_name
      end
    end
  end

  describe "#Failed with FFI::LastError" do
    context "While adding or deleting or retrieving certificate" do
      let(:store_name) { "root" }
      let(:cert_file_path) { '.\spec\win32\unit\assets\GlobalSignRootCA.pem' }
      let(:certificate_object) { OpenSSL::X509::Certificate.new(File.read cert_file_path) }
      let(:certificate_name) { "GlobalSign" }
      let(:thumbprint) { "b1bc968bd4f49d622aa89a81f2150152a41d829c" }

      it "returns 'The operation was canceled by the user'" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(1223)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect { store.add(certificate_object) }.to raise_error(SystemCallError)
      end

      it "returns 'Cannot find object or property'" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146885628)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect { store.add(certificate_object) }.to raise_error(SystemCallError)
      end

      it "returns 'An error occurred while reading or writing to a file'" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146885629)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect { store.add(certificate_object) }.to raise_error(SystemCallError)
      end

      it "returns 'ASN1 bad tag value met. -- Is the certificate in DER format?'" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146881269)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        store = certstore.open(store_name)
        expect { store.add(certificate_object) }.to raise_error(SystemCallError)
      end

      it "returns 'ASN1 unexpected end of data'" do
        allow(certstore_handler).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(certstore).to receive(:open).with(store_name).and_return(certstore_handler)
        allow(FFI::LastError).to receive(:error).and_return(-2146881278)
        store = certstore.open(store_name)
        expect { store.add(certificate_object) }.to raise_error(SystemCallError)
      end

      it "return 'System.UnauthorizedAccessException, Access denied..'" do
        allow(certbase).to receive(:CertFindCertificateInStore).and_return(true)
        allow(certbase).to receive(:CertDeleteCertificateFromStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2147024891)
        store = certstore.open(store_name)
        expect { store.delete(thumbprint) }.not_to raise_error(SystemCallError)
      end
    end
  end
end
